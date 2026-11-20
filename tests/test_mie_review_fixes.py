'''Regression tests for the 2026-11-20 MIE security, archive, quarantine,
YARA/PE heuristic, and local-API review fixes.'''
import asyncio
import base64
import hashlib
import io
import json
import os
import struct
import types
import urllib.error
import urllib.request
import zipfile

import pytest

from dexmond_mie import core, licence, paths, quarantine, reputation, tray
from dexmond_mie.auto_evolution import RuleSynthesizer, approve_rule
from dexmond_mie.pe_analyzer import PEAnalyzer
from dexmond_mie.utils import StringExtractor


# --------------------------------------------------------- ASGI test helper
def _asgi_call(app, method: str, path: str, headers=None, body: bytes = b'', query: str = ''):
    hdrs = [(k.lower().encode('latin1'), v.encode('latin1'))
            for k, v in (headers or {}).items()]
    sent = []

    async def _run():
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return {'type': 'http.disconnect'}

        async def send(msg):
            sent.append(msg)

        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': method.upper(),
            'scheme': 'http',
            'path': path,
            'raw_path': path.encode('ascii'),
            'query_string': query.encode('ascii'),
            'headers': hdrs,
            'client': ('127.0.0.1', 54321),
            'server': ('127.0.0.1', 8888),
        }
        await app(scope, receive, send)

    asyncio.run(_run())
    start = next(m for m in sent if m['type'] == 'http.response.start')
    resp_headers = {}
    set_cookies = []
    for k, v in start.get('headers', []):
        kl = k.decode('latin1').lower()
        vd = v.decode('latin1')
        if kl == 'set-cookie':
            set_cookies.append(vd)
        resp_headers[kl] = vd
    raw_body = b''.join(m.get('body', b'') for m in sent if m['type'] == 'http.response.body')
    return start['status'], resp_headers, set_cookies, raw_body


# --------------------------------------------------------- S-1 & S-3: webapp
def test_s3_extract_hostname_ipv6_and_empty(monkeypatch, tmp_path):
    monkeypatch.setenv('DEXMOND_DATA_DIR', str(tmp_path / 'data'))
    from dexmond_mie import webapp
    assert webapp._extract_hostname('localhost:8888') == 'localhost'
    assert webapp._extract_hostname('127.0.0.1:18888') == '127.0.0.1'
    assert webapp._extract_hostname('[::1]') == '::1'
    assert webapp._extract_hostname('[::1]:8888') == '::1'
    assert webapp._extract_hostname('') == ''
    assert webapp._extract_hostname(':8888') == ''
    assert webapp._extract_hostname('[]') == ''
    assert webapp._extract_hostname('evil.example.com:8888') == 'evil.example.com'


def test_s1_dashboard_never_leaks_auth_token_and_enforces_csrf(monkeypatch, tmp_path):
    monkeypatch.setenv('DEXMOND_DATA_DIR', str(tmp_path / 'data'))
    from dexmond_mie import webapp

    # 1. Missing or non-loopback Host is rejected with 400
    st, _, _, _ = _asgi_call(webapp.app, 'GET', '/', headers={})
    assert st == 400
    st, _, _, _ = _asgi_call(webapp.app, 'GET', '/', headers={'Host': 'evil.com'})
    assert st == 400
    # Bare IPv6 loopback Host: [::1] is accepted
    st, _, _, raw = _asgi_call(webapp.app, 'GET', '/', headers={'Host': '[::1]'})
    assert st == 200
    html = raw.decode('utf-8')
    assert webapp.AUTH_TOKEN not in html
    assert webapp.CSRF_TOKEN not in html

    # 2. Unauthenticated /status returns 401; X-DEXMOND-Token returns 200
    st, _, _, _ = _asgi_call(webapp.app, 'GET', '/status', headers={'Host': 'localhost:8888'})
    assert st == 401
    st, _, _, _ = _asgi_call(
        webapp.app, 'GET', '/status',
        headers={'Host': 'localhost:8888', 'X-DEXMOND-Token': webapp.AUTH_TOKEN})
    assert st == 200

    # 3. Single-use ticket -> /launch sets HttpOnly SameSite=Strict cookie; cookie alone (without CSRF) is 401
    st, _, _, ticket_raw = _asgi_call(
        webapp.app, 'POST', '/api/auth/ticket',
        headers={'Host': 'localhost:8888', 'X-DEXMOND-Token': webapp.AUTH_TOKEN})
    assert st == 200
    ticket = json.loads(ticket_raw)['ticket']

    st, hdrs, cookies, _ = _asgi_call(
        webapp.app, 'GET', '/launch', query=f'ticket={ticket}', headers={'Host': 'localhost:8888'})
    assert st == 303
    assert any('mie_session=' in c and 'HttpOnly' in c and 'SameSite=strict' in c for c in cookies)
    cookie_pair = cookies[0].split(';', 1)[0]

    # Replay of single-use ticket does not mint a second cookie
    st, _, cookies2, _ = _asgi_call(
        webapp.app, 'GET', '/launch', query=f'ticket={ticket}', headers={'Host': 'localhost:8888'})
    assert cookies2 == []

    # Cookie WITHOUT X-DEXMOND-CSRF fails (blocks cross-port localhost CSRF)
    st, _, _, _ = _asgi_call(
        webapp.app, 'GET', '/status',
        headers={'Host': 'localhost:8888', 'Cookie': cookie_pair})
    assert st == 401

    # Cookie WITH X-DEXMOND-CSRF succeeds, and authenticated GET / still never embeds AUTH_TOKEN
    st, _, _, auth_html_raw = _asgi_call(
        webapp.app, 'GET', '/',
        headers={'Host': 'localhost:8888', 'Cookie': cookie_pair})
    assert webapp.AUTH_TOKEN not in auth_html_raw.decode('utf-8')
    assert webapp.CSRF_TOKEN in auth_html_raw.decode('utf-8')

    st, _, _, _ = _asgi_call(
        webapp.app, 'GET', '/status',
        headers={'Host': 'localhost:8888', 'Cookie': cookie_pair, 'X-DEXMOND-CSRF': webapp.CSRF_TOKEN})
    assert st == 200

    # 4. /api/scan redacts long base64 secret strings in HTTP output
    secret_file = tmp_path / 'fake_env.txt'
    fake_secret = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5QUJDREVGR0g='
    secret_file.write_text(f'API_SECRET={fake_secret}\n', encoding='utf-8')
    st, _, _, scan_raw = _asgi_call(
        webapp.app, 'POST', '/api/scan',
        headers={'Host': 'localhost:8888', 'X-DEXMOND-Token': webapp.AUTH_TOKEN,
                 'Content-Type': 'application/json'},
        body=json.dumps({'path': str(secret_file)}).encode('utf-8'))
    assert st == 200
    assert fake_secret.encode('utf-8') not in scan_raw
    assert b'redacted' in scan_raw


# --------------------------------------------------------- S-5 & S-6: archives
@pytest.mark.parametrize('bad_name', [
    '//203.0.113.55/share/a.txt',
    r'\\203.0.113.55\share\a.txt',
    'Z:/outside.txt',
    'C:ads_stream.txt',
    '../escape.txt',
    'a/../../escape.txt',
    '/etc/passwd',
    'CON',
    'nul.txt',
    'dir/LPT1.exe',
])
def test_s5_unsafe_archive_member_names_rejected_before_fs(bad_name):
    assert core._is_safe_archive_member_name(bad_name) is False


def test_s5_cross_drive_or_unc_entry_does_not_abort_later_zip_members(tmp_path, make_engine):
    zpath = tmp_path / 'mixed.zip'
    with zipfile.ZipFile(zpath, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('Z:/bad_drive_entry.txt', b'ignored')
        zf.writestr('//192.0.2.9/unc/leak.txt', b'ignored')
        zf.writestr('good/script.ps1', b'powershell.exe -EncodedCommand SQBFAFgA')
    eng = make_engine()
    res = eng.scan_file(str(zpath))
    arc = res['details']['archive']
    assert arc['members_scanned'] == 1
    assert arc['coverage']['complete'] is False
    assert res['score'] >= 20


def test_s6_spoofed_zip_header_file_size_caught_as_mismatch(monkeypatch, tmp_path, make_engine):
    monkeypatch.setattr(core, 'MAX_ARCHIVE_MEMBER_BYTES', 1024)
    zpath = tmp_path / 'spoofed.zip'
    payload = b'A' * 4096
    with zipfile.ZipFile(zpath, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('zeros.bin', payload)
    raw = bytearray(zpath.read_bytes())
    # Patch uncompressed size (4096 = 0x1000) in both local header (offset 22)
    # and central directory header to 16 bytes so pre-check sees 16 <= 1024,
    # while streaming decompression catches actual > 1024 before stream EOF!
    lh_uncomp = struct.unpack_from('<I', raw, 22)[0]
    assert lh_uncomp == 4096
    struct.pack_into('<I', raw, 22, 16)
    cd_pos = raw.find(b'PK\x01\x02')
    assert cd_pos > 0
    assert struct.unpack_from('<I', raw, cd_pos + 24)[0] == 4096
    struct.pack_into('<I', raw, cd_pos + 24, 16)
    zpath.write_bytes(bytes(raw))

    eng = make_engine()
    res = eng.scan_file(str(zpath))
    arc = res['details']['archive']
    assert arc['members_scanned'] == 0
    assert arc['coverage']['complete'] is False
    assert any('member extraction failed' in r or 'mismatch' in r for r in arc['coverage']['reasons'])


# --------------------------------------------------------- S-8, S-9, S-10: links & quarantine
def test_s8_s9_s10_quarantine_and_scan_refuse_symlinks_and_toctou(tmp_path, make_engine):
    qdir = tmp_path / 'quarantine'
    qm = quarantine.QuarantineManager(str(qdir))

    real = tmp_path / 'real.bin'
    real.write_bytes(b'real-payload-bytes')
    real_sha = hashlib.sha256(b'real-payload-bytes').hexdigest()

    # S-9 TOCTOU: wrong expected sha256 aborts without deleting real file or leaving .qtn
    with pytest.raises(OSError):
        qm.add(str(real), {'hashes': {'sha256': '0' * 64}, 'score': 80, 'verdict': 'MALICIOUS'})
    assert real.exists()
    assert [f for f in os.listdir(qdir) if f.endswith('.qtn')] == []

    # Valid quarantine + non-overwriting restore (.restored, .restored.1)
    meta = qm.add(str(real), {'hashes': {'sha256': real_sha}, 'score': 80, 'verdict': 'MALICIOUS'})
    assert not real.exists()
    # Put two files at original and .restored so restore picks .restored.1
    real.write_bytes(b'occupant-0')
    (tmp_path / 'real.restored.bin').write_bytes(b'occupant-1')
    restored_path = qm.restore(meta['id'])
    assert restored_path.endswith('real.restored.1.bin')
    assert open(restored_path, 'rb').read() == b'real-payload-bytes'

    # Symlink checks (skipped if OS disallows unprivileged symlinks)
    link = tmp_path / 'link_to_real.bin'
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip('Symlinks require privilege on this runner')

    eng = make_engine()
    scan_res = eng.scan_file(str(link))
    assert 'error' in scan_res
    with pytest.raises(OSError):
        qm.add(str(link), {'score': 80, 'verdict': 'MALICIOUS'})
    assert real.exists()

    # Dangling symlink at original_path is NOT followed on restore
    victim = tmp_path / 'victim_target.bin'
    to_q = tmp_path / 'item.bin'
    to_q.write_bytes(b'quarantined-sample')
    meta2 = qm.add(str(to_q), {'score': 80, 'verdict': 'MALICIOUS'})
    os.symlink(victim, to_q)  # dangling symlink!
    out2 = qm.restore(meta2['id'])
    assert not victim.exists()
    assert out2 != str(to_q)


# --------------------------------------------------------- S-11, S-12, R-1..R-6, T-2
def test_s11_auto_evolution_escapes_filename_and_rejects_duplicate_rule(tmp_path):
    rules_dir = tmp_path / 'rules'
    rules_dir.mkdir()
    inj_name = 'evil" \n}\nrule injected { condition: true }\n//'
    res = {
        'score': 85,
        'filename': inj_name,
        'hashes': {'sha256': 'abcdef0123456789' * 4},
        'details': {'iocs': {'suspicious_api': ['ReflectiveLoaderStageTwoMarker']}},
    }
    rname = RuleSynthesizer.generate_yara_rule('sample.bin', res, str(rules_dir))
    assert rname is not None and 'abcdef012345' in rname
    proposed_text = (rules_dir / 'proposed' / 'auto_generated.yar').read_text(encoding='utf-8')
    assert '\nrule injected' not in proposed_text
    assert [ln.split()[1] for ln in proposed_text.splitlines() if ln.startswith('rule ')] == [rname]
    try:
        import yara
        compiled = yara.compile(source=proposed_text)
        assert compiled.match(data=b'benign content') == []
    except ImportError:
        pass
    assert 'severity = "medium"' in proposed_text
    assert 'all of ($s*)' in proposed_text

    seen = []

    def fake_compiler(src):
        names = [ln.split()[1] for ln in src.splitlines() if ln.startswith('rule ')]
        if len(names) != len(set(names)):
            raise RuntimeError('duplicate rule identifier')
        seen.append(names)

    approve_rule(str(rules_dir), rname, compiler=fake_compiler)
    # Re-propose same sha256 + filename and confirm duplicate approval is rejected
    RuleSynthesizer.generate_yara_rule('sample.bin', res, str(rules_dir))
    with pytest.raises(ValueError):
        approve_rule(str(rules_dir), rname, compiler=fake_compiler)


def test_s12_licence_post_refuses_http_redirect(monkeypatch):
    class FakeFP(io.BytesIO):
        def close(self):
            super().close()

    def fake_http_open(self, req):
        raise urllib.error.HTTPError(
            req.full_url, 302, 'Found', {'Location': 'http://downgrade.example/activate'}, FakeFP(b'{}'))

    monkeypatch.setattr(urllib.request.HTTPHandler, 'http_open', fake_http_open)
    monkeypatch.setattr(urllib.request.HTTPSHandler, 'https_open', fake_http_open)
    status, _ = licence._post_json('https://activate.dexmond.com/activate', {'code': 'X'}, 2.0)
    assert status == 302


def test_r1_b64_executable_matches_real_pe_header():
    pe_bytes = bytearray(96)
    pe_bytes[0:2] = b'MZ'
    pe_bytes[2:4] = b'\x90\x00'
    pe_bytes[4:6] = b'\x03\x00'
    pe_bytes[8:10] = b'\x04\x00'
    b64 = base64.b64encode(bytes(pe_bytes)).decode('ascii')
    assert b64.startswith('TVqQAAMAAAAEAAAA')
    _, iocs = StringExtractor.extract_ascii_unicode(f'$x = "{b64}"'.encode('ascii'), 5)
    assert 'b64_executable' in iocs


def test_r2_benign_advisory_not_critical_and_wide_mimikatz_pe_matches(tmp_path, make_engine):
    eng = make_engine()
    if eng.yara_engine.status != 'ON':
        pytest.skip('yara-python not active')

    faq = tmp_path / 'ransomware_faq.html'
    faq.write_text(
        '<p>CISA guidance: never pay in Bitcoin; restore your files from offline backups.</p>',
        encoding='utf-8')
    faq_res = eng.scan_file(str(faq))
    assert faq_res['score'] < 30
    assert 'Ransomware_Note_Indicators' not in faq_res['yara']

    # Wide-only Mimikatz strings inside an MZ binary ARE detected
    wide_pe = bytearray(b'MZ' + b'\x00' * 128)
    wide_pe += 'sekurlsa::logonpasswords'.encode('utf-16le') + b'\x00' * 64
    mimi_path = tmp_path / 'wide_sample.bin'
    mimi_path.write_bytes(bytes(wide_pe))
    mimi_res = eng.scan_file(str(mimi_path))
    assert 'Mimikatz_Credential_Tool' in mimi_res['yara']


def test_r3_r4_delay_imports_unicode_chains_and_dll_zero_ep():
    imp1 = types.SimpleNamespace(name=b'InternetOpenW', name_offset=0x200)
    imp2 = types.SimpleNamespace(name=b'InternetOpenUrlW', name_offset=0x220)
    imp3 = types.SimpleNamespace(name=b'CreateProcessW', name_offset=0x240)
    delay_entry = types.SimpleNamespace(dll=b'WININET.dll', imports=[imp1, imp2])
    std_entry = types.SimpleNamespace(dll=b'KERNEL32.dll', imports=[imp3])
    fake_pe = types.SimpleNamespace(
        FILE_HEADER=types.SimpleNamespace(Machine=0x8664, TimeDateStamp=1700000000, Characteristics=0x2002),
        OPTIONAL_HEADER=types.SimpleNamespace(AddressOfEntryPoint=0, ImageBase=0x180000000, DataDirectory=[]),
        sections=[],
        DIRECTORY_ENTRY_IMPORT=[std_entry],
        DIRECTORY_ENTRY_DELAY_IMPORT=[delay_entry],
    )
    a = PEAnalyzer.from_pe(fake_pe)
    assert 'InternetOpenW' in a.get_suspicious_imports()
    assert any('Remote Download & Exec Chain' in c for c in a.get_api_chains())
    assert 'Entry point is zero' not in a._check_anomalies()


def test_r6_eicar_hash_cannot_be_whitelisted_and_t2_tray_status(tmp_path):
    db = reputation.ReputationDB(str(tmp_path / 'rep.json'))
    eicar_sha = next(iter(reputation.PROTECTED_MALICIOUS))
    db.add_malicious(eicar_sha, 'EICAR-Test-File')
    assert db.add_trusted(eicar_sha, 'accidental-restore') is False
    assert db.lookup(eicar_sha)['reputation'] == 'malicious'

    assert tray._derive_tray_status({'yara_status': 'ON', 'protection': {'active': False}})[1] == 'Status: Monitoring Off'
    assert tray._derive_tray_status({'yara_status': 'YARA-OFF', 'protection': {'active': True}})[1] == 'Status: YARA Off'
    assert tray._derive_tray_status({'yara_status': 'ON', 'protection': {'active': True}})[1] == 'Status: Active'
