import os
import json
import secrets
import tempfile
import threading
import time
import logging
from collections import deque
from typing import Optional

import anyio
from fastapi import Body, FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .core import Engine, needs_alert
from .realtime import RealtimeScanner, ALERT_THRESHOLD
from .quarantine import QuarantineManager
from . import paths
from . import __version__

logger = logging.getLogger('DEXMOND_MIE')

# Paths resolve correctly whether running from source or a packaged executable.
RULES_DIR = paths.rules_dir()
QUARANTINE_DIR = paths.quarantine_dir()
STATE_FILE = paths.state_file()
REPUTATION_DB = paths.reputation_db()
TOKEN_FILE = paths.token_file()

# Only loopback host names are accepted, blocking DNS-rebinding attacks.
ALLOWED_HOSTNAMES = {'localhost', '127.0.0.1', '::1'}
# Public paths never return AUTH_TOKEN. Browser sessions authenticate via a
# one-time /launch ticket (cli/tray) or POST /api/auth/session, receiving an
# HttpOnly SameSite=Strict cookie paired with a custom X-DEXMOND-CSRF header.
PUBLIC_PATHS = {'/', '/favicon.ico', '/launch', '/api/auth/session'}
AUTH_HEADER = 'x-dexmond-token'
CSRF_HEADER = 'x-dexmond-csrf'
SESSION_COOKIE = 'mie_session'
MAX_UPLOAD_BYTES = 256 * 1024 * 1024


def _extract_hostname(host_header: str) -> str:
    '''Extracts and normalises the hostname from an HTTP Host header,
    supporting bracketed IPv6 literals ([::1], [::1]:8888) and rejecting empty
    or malformed Host values (Finding S-3).'''
    raw = (host_header or '').strip().lower()
    if not raw:
        return ''
    if raw.startswith('['):
        end = raw.find(']')
        if end <= 1:
            return ''
        rest = raw[end + 1:]
        if rest and (not rest.startswith(':') or not rest[1:].isdigit()):
            return ''
        return raw[1:end]
    if ':' in raw:
        if raw.count(':') != 1:
            return ''
        host_part, port_part = raw.split(':', 1)
        if not host_part or not port_part.isdigit():
            return ''
        return host_part
    return raw


def _load_or_create_token() -> str:
    '''Loads the local auth token, creating a new owner-only file on first run.
    Blocks cross-origin web pages and other OS user accounts on the machine
    (processes running under the same OS user share access to the user's files).'''
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    try:
        if os.path.lexists(TOKEN_FILE) and not paths.is_symlink_or_junction(TOKEN_FILE):
            fd = os.open(TOKEN_FILE, os.O_RDONLY | nofollow)
            with os.fdopen(fd, 'r', encoding='utf-8') as f:
                tok = f.read().strip()
            if tok:
                paths.ensure_owner_only_file(TOKEN_FILE)
                return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(32)
    os.makedirs(os.path.dirname(TOKEN_FILE) or '.', exist_ok=True)
    if paths.is_symlink_or_junction(TOKEN_FILE):
        raise OSError('Refusing to write token through symbolic link')
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | nofollow, 0o600)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(tok)
    paths.ensure_owner_only_file(TOKEN_FILE)
    logger.info('Generated new local access token')
    return tok


AUTH_TOKEN = _load_or_create_token()
SESSION_SECRET = secrets.token_urlsafe(32)
CSRF_TOKEN = secrets.token_urlsafe(32)
_tickets_lock = threading.Lock()
_bootstrap_tickets = {}  # ticket -> expiry monotonic timestamp


def mint_bootstrap_ticket(ttl_seconds: float = 30.0) -> str:
    now = time.monotonic()
    ticket = secrets.token_urlsafe(24)
    with _tickets_lock:
        expired = [k for k, exp in _bootstrap_tickets.items() if exp <= now]
        for k in expired:
            _bootstrap_tickets.pop(k, None)
        while len(_bootstrap_tickets) >= 16:
            oldest = next(iter(_bootstrap_tickets))
            _bootstrap_tickets.pop(oldest, None)
        _bootstrap_tickets[ticket] = now + ttl_seconds
    return ticket


def _consume_bootstrap_ticket(ticket: str) -> bool:
    if not ticket:
        return False
    now = time.monotonic()
    with _tickets_lock:
        exp = _bootstrap_tickets.pop(ticket, None)
    return exp is not None and exp > now


def _has_valid_session(request: Request) -> bool:
    cookie = request.cookies.get(SESSION_COOKIE, '')
    return bool(cookie) and secrets.compare_digest(cookie, SESSION_SECRET)


def _redact_http_results(results: dict) -> dict:
    '''Redacts raw base64 IOC values in HTTP scan responses so /api/scan cannot
    be used to exfiltrate PEM keys, tokens, or secrets (Finding S-1).'''
    if not isinstance(results, dict):
        return results
    out = dict(results)
    details = out.get('details')
    if isinstance(details, dict) and isinstance(details.get('iocs'), dict):
        details_copy = dict(details)
        iocs_copy = dict(details['iocs'])
        if 'base64' in iocs_copy and isinstance(iocs_copy['base64'], list):
            iocs_copy['base64'] = [
                f'{val[:8]}...[redacted {len(val)} chars]' if len(val) > 12 else '[redacted]'
                for val in iocs_copy['base64']
            ]
        details_copy['iocs'] = iocs_copy
        out['details'] = details_copy
    return out


app = FastAPI(title='DEXMOND MIE', version=__version__)
engine = Engine(RULES_DIR, REPUTATION_DB)
quarantine = QuarantineManager(QUARANTINE_DIR)
_started = time.time()
_stats = {'scans': 0, 'threats': 0}
_activity = deque(maxlen=50)
_state_lock = threading.Lock()


@app.middleware('http')
async def _guard(request: Request, call_next):
    hostname = _extract_hostname(request.headers.get('host', ''))
    if not hostname or hostname not in ALLOWED_HOSTNAMES:
        return JSONResponse({'detail': 'Invalid host'}, status_code=400)
    if request.url.path not in PUBLIC_PATHS:
        token = request.headers.get(AUTH_HEADER, '')
        header_ok = bool(token) and secrets.compare_digest(token, AUTH_TOKEN)
        csrf = request.headers.get(CSRF_HEADER, '')
        session_ok = (_has_valid_session(request)
                      and bool(csrf)
                      and secrets.compare_digest(csrf, CSRF_TOKEN))
        if not (header_ok or session_ok):
            return JSONResponse({'detail': 'Unauthorized'}, status_code=401)
    return await call_next(request)


def _load_state():
    try:
        with open(STATE_FILE, encoding='utf-8') as f:
            state = json.load(f)
        _stats.update(state.get('stats', {}))
        _activity.extend(state.get('activity', []))
    except (OSError, json.JSONDecodeError):
        pass


def _save_state():
    with _state_lock:
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, 'w', encoding='utf-8') as f:
                json.dump({'stats': _stats, 'activity': list(_activity)}, f)
        except OSError as e:
            logger.error(f'Failed to save state: {e}')


_load_state()


def _on_realtime_result(results):
    _stats['scans'] += 1
    score = results.get('score', 0)
    if score >= ALERT_THRESHOLD:
        _stats['threats'] += 1
    if needs_alert(results, ALERT_THRESHOLD):
        _activity.appendleft({
            'time': time.strftime('%H:%M:%S'),
            'filename': results.get('filename', '?'),
            'path': results.get('path', ''),
            'verdict': results.get('verdict', 'UNKNOWN'),
            'score': score,
            'quarantined': bool(results.get('auto_quarantined'))})
    _save_state()


def _auto_quarantine(path, results):
    '''Called by realtime protection to isolate a confirmed threat.'''
    quarantine.add(path, results)


protection = RealtimeScanner(RULES_DIR, result_callback=_on_realtime_result,
                             engine=engine, quarantine_callback=_auto_quarantine)


@app.on_event('startup')
def _start_protection():
    protection.start()


@app.on_event('shutdown')
def _stop_protection():
    if protection.is_active:
        protection.stop()


@app.post('/api/auth/ticket')
def create_launch_ticket():
    '''Mints a single-use 30-second bootstrap ticket for cli/tray browser launch.'''
    return {'ticket': mint_bootstrap_ticket()}


@app.get('/launch')
def launch_session(ticket: str = ''):
    resp = RedirectResponse(url='/', status_code=303)
    if _consume_bootstrap_ticket(ticket):
        resp.set_cookie(key=SESSION_COOKIE, value=SESSION_SECRET,
                        httponly=True, samesite='strict', path='/')
    return resp


@app.post('/api/auth/session')
def exchange_token_for_session(payload: dict):
    candidate = str((payload or {}).get('token', '')).strip()
    if not candidate or not secrets.compare_digest(candidate, AUTH_TOKEN):
        raise HTTPException(status_code=401, detail='Invalid access token')
    resp = JSONResponse({'ok': True, 'csrf': CSRF_TOKEN})
    resp.set_cookie(key=SESSION_COOKIE, value=SESSION_SECRET,
                    httponly=True, samesite='strict', path='/')
    return resp


@app.get('/', response_class=HTMLResponse)
def dashboard(request: Request):
    csrf = CSRF_TOKEN if _has_valid_session(request) else ''
    return DASHBOARD_HTML.replace('__CSRF_TOKEN__', csrf)


@app.get('/status')
def status():
    return {
        'status': 'active',
        'version': __version__,
        'uptime': int(time.time() - _started),
        'rules_dir': RULES_DIR,
        'yara_loaded': engine.yara_engine.rules is not None,
        'rules_count': engine.yara_engine.rules_count,
        'yara_status': engine.yara_engine.status,
        'yara_errors': engine.yara_engine.errors,
        'scans': _stats['scans'],
        'threats': _stats['threats'],
        'reputation': engine.reputation.counts,
        'protection': {
            'active': protection.is_active,
            'watched': protection.watched,
            'auto_quarantine': protection.auto_quarantine},
        'activity': list(_activity)[:10]}


@app.post('/api/protection/start')
def protection_start():
    watched = protection.start()
    if not watched:
        raise HTTPException(status_code=500, detail='No folders available to watch')
    return {'active': True, 'watched': watched}


@app.post('/api/protection/stop')
def protection_stop():
    protection.stop()
    return {'active': False, 'watched': []}


@app.post('/api/protection/auto-quarantine')
def protection_auto_quarantine(payload: dict):
    protection.auto_quarantine = bool(payload.get('enabled'))
    logger.info(f'Auto-quarantine {"enabled" if protection.auto_quarantine else "disabled"}')
    return {'auto_quarantine': protection.auto_quarantine}


@app.post('/api/shutdown')
def app_shutdown():
    if protection.is_active:
        protection.stop()
    _save_state()
    from . import cli
    if getattr(cli, '_uvicorn_server', None) is not None:
        cli._uvicorn_server.should_exit = True
    return {'stopping': True}


@app.get('/api/quarantine')
def quarantine_list():
    return quarantine.list()


@app.post('/api/quarantine')
def quarantine_add(payload: dict):
    path = payload.get('path', '')
    if not path or not paths.is_regular_non_link(path):
        raise HTTPException(status_code=404, detail=f'Regular file not found: {path}')
    results = engine.scan_file(path)
    if results.get('score', 0) < ALERT_THRESHOLD:
        raise HTTPException(
            status_code=400,
            detail=f"Refusing to quarantine: file is not a detected threat "
                   f"(score {results.get('score', 0)}/{ALERT_THRESHOLD}).")
    try:
        meta = quarantine.add(path, results)
        if meta and meta.get('sha256'):
            engine.auto_evolution.on_isolate(engine.reputation, meta['sha256'], meta.get('filename', ''))
    except OSError as e:
        raise HTTPException(status_code=500, detail=f'Could not quarantine file: {e}')
    abspath = os.path.abspath(path)
    for item in _activity:
        if item.get('path') == abspath:
            item['quarantined'] = True
    _save_state()
    return meta


@app.post('/api/quarantine/{qid}/restore')
def quarantine_restore(qid: str, payload: Optional[dict] = Body(default=None)):
    trust_hash = bool((payload or {}).get('trust', False))
    try:
        meta = quarantine._meta(qid)
        dest = quarantine.restore(qid)
        trusted_added = False
        if trust_hash and meta and meta.get('sha256'):
            trusted_added = bool(engine.reputation.add_trusted(
                meta['sha256'],
                f"user-restored ({meta.get('filename', '')})" if meta.get('filename') else 'user-restored'))
    except KeyError:
        raise HTTPException(status_code=404, detail='Quarantine item not found')
    except OSError as e:
        raise HTTPException(status_code=500, detail=f'Could not restore quarantined file: {e}')
    return {'restored_to': dest, 'trusted': trusted_added}


@app.delete('/api/quarantine/{qid}')
def quarantine_delete(qid: str):
    try:
        quarantine.delete(qid)
    except KeyError:
        raise HTTPException(status_code=404, detail='Quarantine item not found')
    except OSError as e:
        raise HTTPException(status_code=500, detail=f'Could not delete quarantine item: {e}')
    return {'deleted': qid}


@app.get('/api/reputation/trusted')
def trusted_list():
    return [{'sha256': k, 'label': v} for k, v in sorted(engine.reputation.trusted.items())]


@app.delete('/api/reputation/trusted/{sha256}')
def trusted_delete(sha256: str):
    if not engine.reputation.remove_trusted(sha256):
        raise HTTPException(status_code=404, detail='Trusted hash not found')
    return {'removed': sha256.lower()}


def _record(results):
    _stats['scans'] += 1
    if results.get('score', 0) >= ALERT_THRESHOLD:
        _stats['threats'] += 1
    _save_state()
    return results


@app.post('/api/scan')
def scan_path(payload: dict):
    path = payload.get('path', '')
    if not path or not paths.is_regular_non_link(path):
        raise HTTPException(status_code=404, detail=f'Regular file not found: {path}')
    raw = _record(engine.scan_file(path))
    return JSONResponse(_redact_http_results(raw), status_code=200)


@app.post('/api/scan/upload')
async def scan_upload(file: UploadFile = File(...)):
    display_name = os.path.basename(file.filename or 'uploaded.bin')[:200]
    tmp_path = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=paths.scratch_dir(),
                                         prefix='mie_up_', suffix='.upload.tmp') as tmp:
            tmp_path = tmp.name
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413,
                                        detail=f'Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit')
                tmp.write(chunk)
        results = await anyio.to_thread.run_sync(engine.scan_file, tmp_path)
        results['filename'] = display_name
        results['path'] = f'(uploaded) {display_name}'
        return JSONResponse(_redact_http_results(_record(results)), status_code=200)
    finally:
        if tmp_path and os.path.lexists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DEXMOND MIE</title>
<style>
  :root {
    --ink: #1c2733;
    --ink-soft: #5c6b7a;
    --line: #e4e9ee;
    --panel: #f7f9fb;
    --accent: #0e7c86;
    --accent-dark: #0a5d65;
    --clean: #1e7d46;
    --clean-bg: #e9f6ee;
    --warn: #a86a10;
    --danger: #b3372b;
    --danger-bg: #fbeeec;
    --radius: 14px;
    --shadow: 0 1px 3px rgba(28, 39, 51, .07), 0 4px 14px rgba(28, 39, 51, .04);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: #f2f5f8;
    color: var(--ink);
    font: 15px/1.55 -apple-system, "Segoe UI", "Inter", Roboto, "Helvetica Neue", sans-serif;
  }
  .mono { font-family: ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace; }

  header {
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
    padding: 16px 32px; background: #fff; border-bottom: 1px solid var(--line);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand svg { flex: none; }
  .wordmark { font-size: 17px; font-weight: 700; letter-spacing: .1em; }
  .wordmark small { display: block; font-weight: 400; letter-spacing: .02em; color: var(--ink-soft); font-size: 12px; }
  .edition { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--ink-soft); }
  .badge { background: var(--panel); border: 1px solid var(--line); border-radius: 999px; padding: 4px 14px; font-weight: 600; color: var(--accent-dark); }

  main { max-width: 1180px; margin: 0 auto; padding: 28px 32px 48px; }

  .strip { display: grid; grid-template-columns: 1.6fr 1fr 1fr; gap: 18px; margin-bottom: 26px; }
  @media (max-width: 960px) { .strip { grid-template-columns: 1fr; } }
  .tile { background: #fff; border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: 20px 22px; }
  .tile .eyebrow { margin-bottom: 10px; }
  .protection { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
  .shield { width: 52px; height: 52px; border-radius: 50%; display: grid; place-items: center; background: var(--clean-bg); flex: none; }
  .shield.off { background: var(--danger-bg); }
  .protection .state { flex: 1; min-width: 180px; }
  .protection .state b { font-size: 17px; display: block; }
  .protection .state span { font-size: 13px; color: var(--ink-soft); }
  .stat-tile b { font-size: 26px; font-weight: 700; display: block; }
  .stat-tile span { font-size: 13px; color: var(--ink-soft); }

  .switch { display: flex; align-items: center; gap: 10px; margin-top: 16px; cursor: pointer; user-select: none; }
  .switch input { position: absolute; opacity: 0; width: 0; height: 0; }
  .switch .track { position: relative; width: 40px; height: 22px; border-radius: 999px; background: #cdd6df; transition: background .15s; flex: none; }
  .switch .track::after { content: ""; position: absolute; top: 2px; left: 2px; width: 18px; height: 18px; border-radius: 50%; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,.2); transition: transform .15s; }
  .switch input:checked + .track { background: var(--accent); }
  .switch input:checked + .track::after { transform: translateX(18px); }
  .switch input:focus-visible + .track { outline: 2px solid var(--accent); outline-offset: 2px; }
  .switch-label { font-size: 13px; color: var(--ink-soft); }

  .eyebrow { font-size: 11px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; color: var(--ink-soft); margin: 0 0 12px; }

  button {
    padding: 11px 24px; border: none; border-radius: 999px; background: var(--accent); color: #fff;
    font: inherit; font-weight: 600; cursor: pointer; transition: background .15s, transform .05s;
  }
  button:hover { background: var(--accent-dark); }
  button:active { transform: scale(.98); }
  button.secondary { background: #fff; color: var(--ink); border: 1.5px solid var(--line); }
  button.secondary:hover { border-color: #c3ced8; background: var(--panel); }
  button.danger-outline { background: #fff; color: var(--danger); border: 1.5px solid #e8c8c4; }
  button.danger-outline:hover { background: var(--danger-bg); border-color: var(--danger); }
  input[type="text"]:focus, input[type="password"]:focus, button:focus-visible, .dropzone:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

  .cols { display: grid; grid-template-columns: 340px 1fr; gap: 24px; }
  @media (max-width: 960px) { .cols { grid-template-columns: 1fr; } }
  .card { background: #fff; border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: 20px 22px; }
  .card + .card { margin-top: 20px; }

  input[type="text"], input[type="password"] {
    width: 100%; padding: 11px 14px; border: 1.5px solid var(--line); border-radius: 10px;
    font: inherit; color: var(--ink); background: #fff; margin-bottom: 12px;
  }
  .dropzone {
    border: 1.5px dashed #c3ced8; border-radius: 10px; background: var(--panel);
    padding: 28px 14px; text-align: center; color: var(--ink-soft); cursor: pointer; font-size: 14px;
    transition: border-color .15s, background .15s;
  }
  .dropzone.drag, .dropzone:hover { border-color: var(--accent); color: var(--accent-dark); background: #f0fafb; }

  .activity-list { list-style: none; margin: 0; padding: 0; font-size: 13px; }
  .activity-list li { display: flex; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--line); }
  .activity-list li:last-child { border-bottom: none; }
  .activity-list .t { color: var(--ink-soft); flex: none; }
  .activity-list .f { flex: 1; word-break: break-all; }
  .chip { border-radius: 999px; padding: 2px 10px; font-size: 11px; font-weight: 700; flex: none; }
  .chip.warn { background: #fdf3e3; color: var(--warn); }
  .chip.danger { background: var(--danger-bg); color: var(--danger); }
  .chip.clean { background: var(--clean-bg); color: var(--clean); }
  .empty-note { color: var(--ink-soft); font-size: 13px; }
  button.mini { padding: 5px 14px; font-size: 12px; flex: none; }
  .q-actions { display: flex; gap: 6px; flex: none; }

  #report .placeholder {
    background: #fff; border: 1.5px dashed var(--line); border-radius: var(--radius);
    padding: 70px 20px; text-align: center; color: var(--ink-soft);
  }
  .verdict-banner {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
    background: #fff; border: 1px solid var(--line); border-left: 6px solid var(--vcolor, var(--clean));
    border-radius: var(--radius); box-shadow: var(--shadow); padding: 18px 22px; margin-bottom: 18px;
  }
  .verdict-banner .verdict { font-size: 20px; font-weight: 700; color: var(--vcolor); }
  .verdict-banner .file { color: var(--ink-soft); font-size: 12.5px; word-break: break-all; }
  .scoreline { text-align: right; }
  .scoreline b { font-size: 26px; }
  .scoreline span { color: var(--ink-soft); font-size: 13px; }

  .meter { position: relative; height: 8px; border-radius: 4px; background: #fff; border: 1px solid var(--line); margin: 4px 2px 20px; }
  .meter .fill { position: absolute; inset: 0 auto 0 0; border-radius: 4px; background: var(--vcolor); }
  .meter .tick { position: absolute; top: -4px; bottom: -4px; width: 1px; background: #c3ced8; }
  .meter-labels { display: flex; justify-content: space-between; font-size: 11px; color: var(--ink-soft); margin: -14px 2px 20px; }

  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { text-align: left; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--ink-soft); font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--line); }
  td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .cat { font-size: 12px; color: var(--ink-soft); white-space: nowrap; }
  .weight { text-align: right; font-weight: 600; white-space: nowrap; }
  .ledger-total td { border-top: 2px solid var(--ink); font-weight: 700; }
  .section { background: #fff; border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: 18px 22px; margin-bottom: 18px; }
  .kv { display: grid; grid-template-columns: 96px 1fr; gap: 4px 16px; font-size: 14px; }
  .kv dt { color: var(--ink-soft); } .kv dd { margin: 0; word-break: break-all; }
  .ioc-tag { display: inline-block; background: var(--panel); border: 1px solid var(--line); border-radius: 999px; padding: 2px 10px; margin: 2px 4px 2px 0; font-size: 12.5px; }
  .auth-box { max-width: 520px; margin: 0 auto 24px; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <svg width="34" height="34" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 L20 5.5 V11 C20 16.5 16.6 20.6 12 22 C7.4 20.6 4 16.5 4 11 V5.5 Z"
            fill="#0e7c86"/>
      <path d="M8.4 11.6 L11 14.2 L15.8 9.4" stroke="#fff" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>
    <div class="wordmark">DEXMOND MIE<small>Second-opinion file scanner</small></div>
  </div>
  <div class="edition"><span class="badge">Free Edition</span> v<span id="ver">&ndash;</span></div>
</header>
<main>
  <p style="text-align: center; color: var(--ink-soft); margin-bottom: 24px; font-size: 14px;">
    MIE is a second-opinion file scanner: it checks files with its own pattern rules and heuristics.
    It has not been tested against real malware, so keep your regular security software turned on.
    Folder monitoring checks new files created in your watched user folders while MIE is running.
  </p>
  <div id="authCard" class="card auth-box" hidden>
    <p class="eyebrow">Unlock Local Session</p>
    <p class="empty-note" style="margin-top:0">Open MIE from the desktop window / tray icon, or paste your per-user token from <span class="mono">.auth_token</span>:</p>
    <form onsubmit="unlockSession(event)">
      <input type="password" id="authInput" placeholder="Local access token" autocomplete="off">
      <button type="submit" style="width:100%">Unlock dashboard</button>
    </form>
    <p id="authErr" class="empty-note" style="color:var(--danger);margin-bottom:0" hidden></p>
  </div>
  <div class="strip">
    <div class="tile">
      <p class="eyebrow">Folder monitoring</p>
      <div class="protection">
        <div class="shield" id="shield">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path id="shieldPath" d="M12 2 L20 5.5 V11 C20 16.5 16.6 20.6 12 22 C7.4 20.6 4 16.5 4 11 V5.5 Z" fill="#1e7d46"/>
            <path d="M8.4 11.6 L11 14.2 L15.8 9.4" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
          </svg>
        </div>
        <div class="state">
          <b id="protState">Checking&hellip;</b>
          <span id="protDetail"></span>
        </div>
        <button id="protBtn" class="danger-outline" onclick="toggleProtection()" hidden>Turn off</button>
      </div>
      <label class="switch">
        <input type="checkbox" id="autoQ" onchange="toggleAutoQuarantine()">
        <span class="track" aria-hidden="true"></span>
        <span class="switch-label">Auto-quarantine malicious files</span>
      </label>
    </div>
    <div class="tile stat-tile">
      <p class="eyebrow">Detection rules</p>
      <b id="rules">&ndash;</b><span>YARA rule files loaded (built in, not updated online)</span>
      <span id="repLine" style="display:block;margin-top:6px">&ndash;</span>
    </div>
    <div class="tile stat-tile">
      <p class="eyebrow">Total recorded</p>
      <b><span id="scans">0</span> / <span id="threats" style="color:var(--danger)">0</span></b>
      <span>files scanned / files flagged</span>
    </div>
  </div>

  <div class="cols">
    <aside>
      <div class="card">
        <p class="eyebrow">Scan a file</p>
        <form onsubmit="scanPath(event)" style="margin-bottom: 16px;">
          <input type="text" id="path" placeholder="C:\\path\\to\\file" aria-label="File path">
          <button type="submit" style="width: 100%;">Scan file</button>
        </form>
        <div style="text-align: center; color: var(--ink-soft); font-size: 13px; margin-bottom: 16px;">&mdash; OR &mdash;</div>
        <div class="dropzone" id="dz" tabindex="0" role="button" aria-label="Upload a file to scan">
          Drop a file here or click to choose
        </div>
        <input type="file" id="file" hidden>
      </div>
      <div class="card">
        <p class="eyebrow">Recent detections</p>
        <ul class="activity-list" id="activity"></ul>
        <p class="empty-note" id="activityEmpty">Nothing flagged yet.</p>
      </div>
      <div class="card">
        <p class="eyebrow">Quarantine</p>
        <label class="switch" style="margin:0 0 10px">
          <input type="checkbox" id="trustOnRestore">
          <span class="track" aria-hidden="true"></span>
          <span class="switch-label">Trust hash when restoring</span>
        </label>
        <ul class="activity-list" id="qlist"></ul>
        <p class="empty-note" id="qEmpty">No files in quarantine.</p>
      </div>
      <div class="card">
        <p class="eyebrow">Trusted hashes</p>
        <ul class="activity-list" id="tlist"></ul>
        <p class="empty-note" id="tEmpty">No user-trusted hashes.</p>
      </div>
    </aside>
    <section id="report" aria-live="polite">
      <div class="placeholder">Scan a file to see its full report here.</div>
    </section>
  </div>
</main>
<script>
const $ = (id) => document.getElementById(id);
let CSRF = "__CSRF_TOKEN__";
// Browser requests carry an HttpOnly SameSite=Strict session cookie plus this
// session-bound CSRF header (never the raw .auth_token in unauthenticated GET /).
function afetch(url, opts) {
  opts = opts || {};
  opts.credentials = 'same-origin';
  opts.headers = Object.assign({}, opts.headers, {'X-DEXMOND-CSRF': CSRF});
  return fetch(url, opts);
}
let protActive = null;

async function unlockSession(e) {
  e.preventDefault();
  $('authErr').hidden = true;
  const r = await fetch('/api/auth/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token: $('authInput').value})
  });
  if (!r.ok) {
    $('authErr').textContent = 'Invalid token. Check .auth_token in your DexmondMIE data folder.';
    $('authErr').hidden = false;
    return;
  }
  const d = await r.json();
  CSRF = d.csrf || '';
  $('authInput').value = '';
  $('authCard').hidden = true;
  refresh();
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function folderLabel(p) {
  const parts = String(p).replace(/[\\\\/]+$/, '').split(/[\\\\/]/);
  return parts[parts.length - 1] || p;
}

function renderProtection(p) {
  protActive = p.active;
  const btn = $('protBtn');
  btn.hidden = false;
  if (p.active) {
    const names = (p.watched || []).map(folderLabel).join(', ');
    $('protState').textContent = 'Active';
    $('protDetail').textContent = 'Monitoring ' + p.watched.length + ' folder' +
      (p.watched.length === 1 ? '' : 's') + (names ? ' (' + names + ')' : '');
    $('shield').classList.remove('off');
    $('shieldPath').setAttribute('fill', '#1e7d46');
    btn.textContent = 'Turn off';
    btn.className = 'danger-outline';
  } else {
    $('protState').textContent = 'Off';
    $('protDetail').textContent = 'New files are not being checked. Turn monitoring back on.';
    $('shield').classList.add('off');
    $('shieldPath').setAttribute('fill', '#b3372b');
    btn.textContent = 'Turn on';
    btn.className = '';
  }
  const auto = $('autoQ');
  if (document.activeElement !== auto) auto.checked = !!p.auto_quarantine;
}

function renderActivity(items) {
  const ul = $('activity');
  $('activityEmpty').style.display = items.length ? 'none' : '';
  ul.innerHTML = items.map((a) => {
    const cls = a.verdict.includes('MALICIOUS') ? 'danger' : 'warn';
    const action = a.quarantined
      ? '<span class="chip clean">quarantined</span>'
      : '<button class="mini secondary" data-q="add" data-path="' + esc(a.path) + '">Quarantine</button>';
    return '<li><span class="t mono">' + esc(a.time) + '</span>' +
           '<span class="f">' + esc(a.filename) + '</span>' +
           '<span class="chip ' + cls + '">' + a.score + '</span>' + action + '</li>';
  }).join('');
}

function renderQuarantine(items) {
  const ul = $('qlist');
  $('qEmpty').style.display = items.length ? 'none' : '';
  ul.innerHTML = items.map((q) =>
    '<li><span class="f">' + esc(q.filename) +
    '<br><span class="t">' + esc(q.quarantined_at) + ' &middot; score ' + q.score + '</span></span>' +
    '<span class="q-actions">' +
    '<button class="mini secondary" data-q="restore" data-id="' + esc(q.id) + '">Restore</button>' +
    '<button class="mini danger-outline" data-q="delete" data-id="' + esc(q.id) + '">Delete</button>' +
    '</span></li>').join('');
}

function renderTrusted(items) {
  const ul = $('tlist');
  $('tEmpty').style.display = items.length ? 'none' : '';
  ul.innerHTML = items.map((t) =>
    '<li><span class="f">' + esc(t.label) + '<br><span class="t mono">' + esc(t.sha256.slice(0, 16)) + '&hellip;</span></span>' +
    '<button class="mini danger-outline" data-q="untrust" data-sha="' + esc(t.sha256) + '">Remove</button></li>'
  ).join('');
}

async function refresh() {
  if (!CSRF) {
    $('authCard').hidden = false;
    return;
  }
  try {
    const sr = await afetch('/status');
    if (sr.status === 401) {
      CSRF = '';
      $('authCard').hidden = false;
      return;
    }
    const [s, q, tr] = await Promise.all([
      sr.json(),
      (await afetch('/api/quarantine')).json(),
      (await afetch('/api/reputation/trusted')).json()]);
    $('authCard').hidden = true;
    $('ver').textContent = s.version;
    const ys = s.yara_status || (s.yara_loaded ? 'ON' : 'YARA-OFF');
    $('rules').textContent = ys === 'ON' ? s.rules_count
      : (ys === 'DEGRADED' ? s.rules_count + ' (DEGRADED)' : 'YARA-OFF');
    $('rules').style.color = ys === 'ON' ? '' : 'var(--danger)';
    $('rules').title = (s.yara_errors || []).map((e) => e.file + ': ' + e.error).join(' | ');
    const rep = s.reputation || {malicious: 0, trusted: 0};
    $('repLine').textContent = rep.malicious + ' known-bad / ' + rep.trusted + ' trusted hashes';
    $('scans').textContent = s.scans;
    $('threats').textContent = s.threats;
    renderProtection(s.protection);
    renderActivity(s.activity || []);
    renderQuarantine(q || []);
    renderTrusted(tr || []);
  } catch (e) { /* engine unreachable; keep last known state */ }
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-q]');
  if (!btn) return;
  btn.disabled = true;
  try {
    const kind = btn.dataset.q;
    if (kind === 'add') {
      await afetch('/api/quarantine', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path: btn.dataset.path})});
      if (btn.id === 'reportQBtn') { btn.textContent = 'Quarantined'; }
    } else if (kind === 'restore') {
      await afetch('/api/quarantine/' + btn.dataset.id + '/restore', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({trust: $('trustOnRestore').checked})});
    } else if (kind === 'delete') {
      if (!confirm('Permanently delete this file from quarantine?')) { btn.disabled = false; return; }
      await afetch('/api/quarantine/' + btn.dataset.id, {method: 'DELETE'});
    } else if (kind === 'untrust') {
      await afetch('/api/reputation/trusted/' + btn.dataset.sha, {method: 'DELETE'});
    }
    await refresh();
  } finally {
    btn.disabled = false;
  }
});

async function toggleProtection() {
  const btn = $('protBtn');
  btn.disabled = true;
  try {
    await afetch(protActive ? '/api/protection/stop' : '/api/protection/start', {method: 'POST'});
    await refresh();
  } finally {
    btn.disabled = false;
  }
}

async function toggleAutoQuarantine() {
  await afetch('/api/protection/auto-quarantine', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled: $('autoQ').checked})});
  await refresh();
}

function verdictColor(v) {
  if (v.includes('MALICIOUS')) return 'var(--danger)';
  if (v.includes('SUSPICIOUS')) return 'var(--warn)';
  return 'var(--clean)';
}

function render(d) {
  if (d.error || d.detail) {
    $('report').innerHTML = '<div class="placeholder">' + esc(d.error || d.detail) + '</div>';
    return;
  }
  const v = d.verdict || 'UNKNOWN';
  const color = verdictColor(v);
  const kb = d.size != null ? (d.size / 1024).toFixed(1) + ' KB' : '';
  let html = '<div class="verdict-banner" style="--vcolor:' + color + '">' +
    '<div><div class="verdict">' + esc(v) + '</div>' +
    '<div class="file mono">' + esc(d.path || '') + (kb ? ' &middot; ' + kb : '') +
    (d.scan_time != null ? ' &middot; ' + d.scan_time + 's' : '') + '</div></div>' +
    '<div class="scoreline"><b>' + d.score + '</b><span> / 100</span><br><span>risk score</span></div>' +
    (d.score >= 30 && d.path && !d.path.startsWith('(uploaded)')
      ? '<button class="danger-outline" id="reportQBtn" data-q="add" data-path="' + esc(d.path) + '">Quarantine file</button>'
      : '') +
    '</div>';

  html += '<div class="meter" style="--vcolor:' + color + '" role="img" aria-label="Risk score ' + d.score + ' of 100">' +
    '<div class="fill" style="width:' + d.score + '%"></div>' +
    '<div class="tick" style="left:30%"></div><div class="tick" style="left:70%"></div></div>' +
    '<div class="meter-labels"><span>0 &middot; clean</span><span>30 &middot; suspicious</span><span>70 &middot; malicious</span></div>';

  const f = d.findings || [];
  html += '<div class="section"><p class="eyebrow">Evidence ledger</p>';
  if (f.length === 0) {
    html += '<p class="empty-note">No suspicious signals found in this file.</p>';
  } else {
    html += '<table><tr><th>Signal</th><th>Description</th><th style="text-align:right">Weight</th></tr>';
    for (const x of f) {
      html += '<tr><td class="cat">' + esc(x.category) + '</td><td>' + esc(x.description) +
              '</td><td class="weight">+' + x.weight + '</td></tr>';
    }
    html += '<tr class="ledger-total"><td></td><td>Risk score (capped at 100)</td><td class="weight">' + d.score + '</td></tr></table>';
  }
  html += '</div>';

  const h = d.hashes || {};
  if (Object.keys(h).length) {
    html += '<div class="section"><p class="eyebrow">Hashes</p><dl class="kv">';
    for (const [k, val] of Object.entries(h)) {
      html += '<dt>' + esc(k.toUpperCase()) + '</dt><dd class="mono">' + esc(val) + '</dd>';
    }
    html += '</dl></div>';
  }

  const pe = (d.details || {}).pe_info;
  if (pe) {
    html += '<div class="section"><p class="eyebrow">PE details</p><dl class="kv">' +
      '<dt>Compiled</dt><dd>' + esc(pe.timestamp || '') + '</dd>' +
      '<dt>Sections</dt><dd>' + (pe.sections || []).length + '</dd>' +
      '<dt>Imports</dt><dd>' + Object.keys(pe.imports || {}).length + ' DLLs</dd>' +
      '<dt>Entry point</dt><dd class="mono">' + esc(pe.entry_point || '') + '</dd></dl></div>';
  }

  const iocs = (d.details || {}).iocs;
  if (iocs && Object.keys(iocs).length) {
    html += '<div class="section"><p class="eyebrow">Extracted IOCs</p>';
    for (const [k, vals] of Object.entries(iocs)) {
      html += '<div style="margin-bottom:6px"><span class="cat">' + esc(k) + '</span><br>' +
        vals.slice(0, 8).map((x) => '<span class="ioc-tag mono">' + esc(x) + '</span>').join('') +
        (vals.length > 8 ? ' &hellip;' : '') + '</div>';
    }
    html += '</div>';
  }

  const arc = (d.details || {}).archive;
  if (arc) {
    html += '<div class="section"><p class="eyebrow">Archive contents</p>' +
      '<dl class="kv"><dt>Members</dt><dd>' + arc.members_scanned + ' scanned</dd>' +
      '<dt>Flagged members</dt><dd>' + arc.threats.length + '</dd></dl>';
    if (arc.threats.length) {
      html += '<table><tr><th>Member</th><th>Verdict</th><th style="text-align:right">Score</th></tr>';
      for (const t of arc.threats) {
        html += '<tr><td class="mono">' + esc(t.name) + '</td><td>' + esc(t.verdict) +
                '</td><td class="weight">' + t.score + '</td></tr>';
      }
      html += '</table>';
    }
    html += '</div>';
  }

  const rep = (d.details || {}).reputation;
  if (rep) {
    html += '<div class="section"><p class="eyebrow">Reputation</p>' +
      '<p class="empty-note">Matched local ' + esc(rep.reputation) +
      ' hash list: ' + esc(rep.label) + '</p></div>';
  }

  $('report').innerHTML = html;
  refresh();
}

async function scanPath(e) {
  e.preventDefault();
  const r = await afetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path: $('path').value})});
  render(await r.json());
}

async function scanUpload(fileObj) {
  const fd = new FormData();
  fd.append('file', fileObj);
  const r = await afetch('/api/scan/upload', {method: 'POST', body: fd});
  render(await r.json());
}

const dz = $('dz'), fileInput = $('file');
dz.addEventListener('click', () => fileInput.click());
dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
fileInput.addEventListener('change', () => { if (fileInput.files[0]) scanUpload(fileInput.files[0]); });
dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
dz.addEventListener('drop', (e) => {
  e.preventDefault(); dz.classList.remove('drag');
  if (e.dataTransfer.files[0]) scanUpload(e.dataTransfer.files[0]);
});

refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>'''
