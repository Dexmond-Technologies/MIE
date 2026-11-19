import argparse
import io
import sys
import json
import logging
import os
import time
import threading

from colorama import init, Fore, Style

from .core import Engine
from . import paths

_fallback_stream = None
_uvicorn_server = None


def _open_fallback_stream():
    global _fallback_stream
    if _fallback_stream is not None and not _fallback_stream.closed:
        return _fallback_stream
    try:
        log_path = os.path.join(paths.data_dir(), 'dexmond_mie.log')
        try:
            if os.path.isfile(log_path) and os.path.getsize(log_path) > 5 * 1024 * 1024:
                os.replace(log_path, log_path + '.1')
        except OSError:
            pass
        _fallback_stream = open(log_path, 'a', encoding='utf-8', errors='replace', buffering=1)
    except OSError:
        _fallback_stream = io.StringIO()
    return _fallback_stream


def _ensure_stdio():
    '''In a PyInstaller windowed build (console=False), sys.stdout and
    sys.stderr are None, which breaks print(), StreamHandler and uvicorn's
    DefaultFormatter. Redirect missing streams to a log file (or StringIO).'''
    if sys.stdout is None or sys.stderr is None:
        stream = _open_fallback_stream()
        if sys.stdout is None:
            sys.stdout = stream
        if sys.stderr is None:
            sys.stderr = stream


_ensure_stdio()
init()

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = int(os.environ.get('DEXMOND_PORT', '8888'))


def setup_logging(verbose=False):
    _ensure_stdio()
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()])


def print_results(results, output_format='console'):
    if output_format == 'json':
        print(json.dumps(results, indent=2, default=str))
        return
    print(f'''\n{Fore.CYAN}=== DEXMOND MIE Scan Results ==={Style.RESET_ALL}''')
    print(f'''File: {results.get('path')}''')
    print(f'''Verdict: {color_verdict(results.get('verdict'))} (Score: {results.get('score')}/100)''')
    yara_status = results.get('details', {}).get('yara_status')
    if yara_status and yara_status != 'ON':
        print(f'''{Fore.RED}YARA status: {yara_status} (rule-based detection is not complete){Style.RESET_ALL}''')
    print('Hashes:')
    for k, v in results.get('hashes', {}).items():
        print(f'''  {k.upper()}: {v}''')
    print(f'''\n{Fore.YELLOW}[+] Findings:{Style.RESET_ALL}''')
    for finding in results.get('findings', []):
        print(f'''  - [{finding['category']}] {finding['description']} (Weight: {finding['weight']})''')
    if 'pe_info' in results.get('details', {}):
        print(f'''\n{Fore.GREEN}[*] PE Info:{Style.RESET_ALL}''')
        pe = results['details']['pe_info']
        print(f'''  Compile Time: {pe.get('timestamp')}''')
        print(f'''  Sections: {len(pe.get('sections', []))}''')
        print(f'''  Imports: {len(pe.get('imports', []))} DLLs''')
    if 'iocs' in results.get('details', {}):
        print(f'''\n{Fore.MAGENTA}[!] Extracted IOCs:{Style.RESET_ALL}''')
        for k, v in results['details']['iocs'].items():
            print(f'''  {k}: {v[:5]} {'...' if len(v) > 5 else ''}''')


def color_verdict(verdict):
    verdict = verdict or 'UNKNOWN'
    if 'MALICIOUS' in verdict:
        return f'''{Fore.RED}{verdict}{Style.RESET_ALL}'''
    if 'SUSPICIOUS' in verdict:
        return f'''{Fore.YELLOW}{verdict}{Style.RESET_ALL}'''
    return f'''{Fore.GREEN}{verdict}{Style.RESET_ALL}'''


def _uvicorn_kwargs(host, port):
    return {'host': host, 'port': port, 'log_level': 'warning', 'log_config': None}


def _start_server(host, port):
    '''Starts the dashboard/API server in a background thread and waits until
    it is accepting connections. The webapp auto-starts realtime protection.'''
    global _uvicorn_server
    _ensure_stdio()
    import uvicorn
    from .webapp import app
    config = uvicorn.Config(app, **_uvicorn_kwargs(host, port))
    server_obj = uvicorn.Server(config)
    _uvicorn_server = server_obj
    server = threading.Thread(target=server_obj.run, daemon=True)
    server.start()
    host_fmt = f'[{host}]' if ':' in host and not host.startswith('[') else host
    url = f'http://{host_fmt}:{port}'
    for _ in range(50):
        if not server.is_alive():
            break
        try:
            import urllib.request
            req = urllib.request.Request(f'{url}/status')
            try:
                with open(paths.token_file(), encoding='utf-8') as f:
                    req.add_header('X-DEXMOND-Token', f.read().strip())
            except OSError:
                pass
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    return url


def run_gui(host=DEFAULT_HOST, port=DEFAULT_PORT):
    '''Full desktop experience: dashboard server + system-tray icon + window.'''
    logger = logging.getLogger('DEXMOND_MIE')
    os.environ.setdefault('DEXMOND_API_URL', f'http://{host}:{port}')
    try:
        import uvicorn  # noqa: F401
        from .webapp import app  # noqa: F401
    except ImportError as e:
        logger.error(f'GUI dependencies not available ({e}). '
                     'Install requirements.txt, or use the "scan" / "background" commands.')
        sys.exit(1)
    url = _start_server(host, port)
    logger.info(f'Dashboard running at {url}')

    # Desktop window (pywebview) on the main thread; tray icon in a helper
    # thread. Both are optional so the app still runs if either is missing.
    window = None
    try:
        import webview
        window = webview.create_window('DEXMOND MIE', url, width=1200, height=820)
    except ImportError:
        logger.info('pywebview not installed; the dashboard is available in your browser')

    try:
        from .tray import run_tray
        threading.Thread(target=run_tray, args=(window,), daemon=True).start()
    except ImportError as e:
        logger.info(f'System tray unavailable ({e})')

    if window is not None:
        import webview
        webview.start()
    else:
        try:
            import webbrowser
            webbrowser.open(url)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def run_background(host=DEFAULT_HOST, port=DEFAULT_PORT):
    '''Headless/tray mode: dashboard server + realtime protection, no window.'''
    logger = logging.getLogger('DEXMOND_MIE')
    os.environ.setdefault('DEXMOND_API_URL', f'http://{host}:{port}')
    url = _start_server(host, port)
    logger.info(f'Folder monitoring running in background; dashboard at {url}')
    try:
        from .tray import run_tray
        run_tray(None)
    except Exception as e:
        logger.warning(f'Tray unavailable ({e}); running headless (Ctrl+C to stop)')
        try:
            while _uvicorn_server is None or not _uvicorn_server.should_exit:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def run_serve(host=DEFAULT_HOST, port=DEFAULT_PORT):
    '''Headless server mode: dashboard/API server + folder monitoring only.'''
    logger = logging.getLogger('DEXMOND_MIE')
    os.environ.setdefault('DEXMOND_API_URL', f'http://{host}:{port}')
    url = _start_server(host, port)
    logger.info(f'Server running at {url}')
    try:
        while _uvicorn_server is None or not _uvicorn_server.should_exit:
            time.sleep(0.5)
    except KeyboardInterrupt:
        if _uvicorn_server is not None:
            _uvicorn_server.should_exit = True


def run():
    _ensure_stdio()
    parser = argparse.ArgumentParser(description='DEXMOND MIE - Lightweight Malware Inspection Engine')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.add_parser('gui', help='Launch the Graphical User Interface')
    subparsers.add_parser('background', help='Run in the background: tray icon and folder monitoring')
    subparsers.add_parser('serve', help='Run the local server and folder monitoring headlessly')
    scan_parser = subparsers.add_parser('scan', help='Scan a file or directory')
    scan_parser.add_argument('target', help='File or directory to scan')
    scan_parser.add_argument('--rules-dir', default=paths.rules_dir(), help='Path to YARA rules directory')
    scan_parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    scan_parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    scan_parser.add_argument('--no-reputation', action='store_true',
                             help='Measuring mode: ignore the known-hash reputation list')
    scan_parser.add_argument('--auto-evolution', action='store_true',
                             help='Propose YARA rules for unmatched threats (rules/proposed/, '
                                  'not loaded until approved)')
    rules_parser = subparsers.add_parser('rules', help='Review auto-generated (proposed) YARA rules')
    rules_parser.add_argument('action', choices=['list-proposed', 'approve'])
    rules_parser.add_argument('name', nargs='?', help='Rule name to approve')
    rules_parser.add_argument('--rules-dir', default=paths.rules_dir(), help='Path to YARA rules directory')
    args = parser.parse_args()
    if not args.command:
        args.command = 'gui'
        args.verbose = False
    setup_logging(getattr(args, 'verbose', False))
    if args.command == 'gui':
        run_gui()
        return
    if args.command == 'background':
        run_background()
        return
    if args.command == 'serve':
        run_serve()
        return
    if args.command == 'rules':
        from .auto_evolution import list_proposed, approve_rule
        if args.action == 'list-proposed':
            names = list_proposed(args.rules_dir)
            print('\n'.join(names) if names else 'No proposed rules.')
            return
        if not args.name:
            print('Error: give the rule name to approve.')
            sys.exit(2)
        try:
            dest = approve_rule(args.rules_dir, args.name)
        except ValueError as e:
            print(f'Not approved: {e}')
            sys.exit(1)
        print(f'Approved {args.name} -> {dest} (restart the app to load it)')
        return
    if args.command == 'scan':
        engine = Engine(args.rules_dir, paths.reputation_db(),
                        use_reputation=not args.no_reputation,
                        auto_evolution=True if args.auto_evolution else None)
        yara_info = engine.yara_engine.status_info()
        if yara_info['status'] != 'ON':
            print(f'''{Fore.RED}WARNING: YARA status {yara_info['status']}: '''
                  f'''{yara_info['rule_files']} rule file(s) loaded, '''
                  f'''{len(yara_info['errors'])} failed{Style.RESET_ALL}''', file=sys.stderr)
            for err in yara_info['errors']:
                print(f'''  {err['file']}: {err['error']}''', file=sys.stderr)
        target_path = os.path.abspath(args.target)
        if os.path.isfile(target_path):
            results = engine.scan_file(target_path)
            print_results(results, args.output)
            return
        if os.path.isdir(target_path):
            print(f'''Scanning directory: {target_path}''')
            for root, _, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    results = engine.scan_file(file_path)
                    print_results(results, args.output)
            return
        print(f'''Error: Target {target_path} not found.''')
        sys.exit(1)


if __name__ == '__main__':
    run()
