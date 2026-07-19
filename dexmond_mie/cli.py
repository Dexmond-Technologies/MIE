import argparse
import sys
import json
import logging
import os

from colorama import init, Fore, Style

from .core import Engine

init()


def setup_logging(verbose=False):
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


def run_gui(host='127.0.0.1', port=8000):
    logger = logging.getLogger('DEXMOND_MIE')
    try:
        import uvicorn
        from .webapp import app
    except ImportError as e:
        logger.error(f'GUI dependencies not available ({e}). '
                     'Install fastapi and uvicorn, or use the "scan" / "background" commands.')
        sys.exit(1)
    import threading
    server = threading.Thread(
        target=uvicorn.run, args=(app,),
        kwargs={'host': host, 'port': port, 'log_level': 'warning'},
        daemon=True)
    server.start()
    url = f'http://{host}:{port}'
    logger.info(f'Dashboard running at {url}')
    try:
        import webview
        window = webview.create_window('DEXMOND MIE', url)
        webview.start()
    except ImportError:
        logger.info('pywebview not installed; serving in browser mode (Ctrl+C to stop)')
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def run_background():
    logger = logging.getLogger('DEXMOND_MIE')
    from .realtime import RealtimeScanner
    notification_callback = None
    try:
        from .tray import run_tray, show_notification
        notification_callback = show_notification
        has_tray = True
    except ImportError as e:
        logger.warning(f'Tray unavailable ({e}); running headless realtime scan')
        has_tray = False
    scanner = RealtimeScanner('./rules', notification_callback=notification_callback)
    scanner.start()
    try:
        if has_tray:
            run_tray()
        else:
            import time
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        scanner.stop()


def run():
    parser = argparse.ArgumentParser(description='DEXMOND MIE - Lightweight Malware Inspection Engine')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.add_parser('gui', help='Launch the Graphical User Interface')
    subparsers.add_parser('background', help='Launch in background with tray icon and realtime scan')
    scan_parser = subparsers.add_parser('scan', help='Scan a file or directory')
    scan_parser.add_argument('target', help='File or directory to scan')
    scan_parser.add_argument('--rules-dir', default='./rules', help='Path to YARA rules directory')
    scan_parser.add_argument('--output', choices=['console', 'json'], default='console', help='Output format')
    scan_parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
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
    if args.command == 'scan':
        engine = Engine(args.rules_dir)
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
