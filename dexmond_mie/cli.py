# Source Generated with Decompyle++
# File: cli.pyc (Python 3.10)

import argparse
import sys
import json
import logging
import os
import threading
import time
import webview
import uvicorn
from colorama import init, Fore, Style
from core import Engine
init()

def setup_logging(verbose = None):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level, '%(asctime)s - %(name)s - %(levelname)s - %(message)s', [
        logging.StreamHandler()], **('level', 'format', 'handlers'))


def print_results(results = None, output_format = None):
    if output_format == 'json':
        print(json.dumps(results, 2, str, **('indent', 'default')))
        return None
    None(f'''\n{Fore.CYAN}=== DEXMOND MIE Scan Results ==={Style.RESET_ALL}''')
    print(f'''File: {results.get('path')}''')
    print(f'''Verdict: {color_verdict(results.get('verdict'))} (Score: {results.get('score')}/100)''')
    print('Hashes:')
    for k, v in results.get('hashes', { }).items():
        print(f'''  {k.upper()}: {v}''')
    print(f'''\n{Fore.YELLOW}[+] Findings:{Style.RESET_ALL}''')
    for finding in results.get('findings', []):
        print(f'''  - [{finding['category']}] {finding['description']} (Weight: {finding['weight']})''')
    if 'pe_info' in results.get('details', { }):
        print(f'''\n{Fore.GREEN}[*] PE Info:{Style.RESET_ALL}''')
        pe = results['details']['pe_info']
        print(f'''  Compile Time: {pe.get('timestamp')}''')
        print(f'''  Sections: {len(pe.get('sections', []))}''')
        print(f'''  Imports: {len(pe.get('imports', []))} DLLs''')
    if 'iocs' in results.get('details', { }):
        print(f'''\n{Fore.MAGENTA}[!] Extracted IOCs:{Style.RESET_ALL}''')
        for k, v in results['details']['iocs'].items():
            print(f'''  {k}: {v[:5]} {'...' if len(v) > 5 else ''}''')
    return None


def color_verdict(verdict):
    if 'MALICIOUS' in verdict:
        return f'''{Fore.RED}{verdict}{Style.RESET_ALL}'''
    if None in verdict:
        return f'''{Fore.YELLOW}{verdict}{Style.RESET_ALL}'''
    return f'''{None.GREEN}{verdict}{Style.RESET_ALL}'''


def run_gui():
    pass
# WARNING: Decompyle incomplete


def run_background():
    pass
# WARNING: Decompyle incomplete


def run():
    parser = argparse.ArgumentParser('DEXMOND MIE - Lightweight Malware Inspection Engine', **('description',))
    subparsers = parser.add_subparsers('command', 'Commands', **('dest', 'help'))
    gui_parser = subparsers.add_parser('gui', 'Launch the Graphical User Interface', **('help',))
    bg_parser = subparsers.add_parser('background', 'Launch in background with tray icon and realtime scan', **('help',))
    scan_parser = subparsers.add_parser('scan', 'Scan a file or directory', **('help',))
    scan_parser.add_argument('target', 'File or directory to scan', **('help',))
    scan_parser.add_argument('--rules-dir', './rules', 'Path to YARA rules directory', **('default', 'help'))
    scan_parser.add_argument('--output', [
        'console',
        'json'], 'console', 'Output format', **('choices', 'default', 'help'))
    scan_parser.add_argument('--verbose', 'store_true', 'Enable verbose logging', **('action', 'help'))
    args = parser.parse_args()
    if not args.command:
        args.command = 'gui'
        args.verbose = False
    setup_logging(getattr(args, 'verbose', False))
    if args.command == 'gui':
        run_gui()
        return None
    if None.command == 'background':
        run_background()
        return None
    if None.command == 'scan':
        engine = Engine(args.rules_dir)
        target_path = os.path.abspath(args.target)
        if os.path.isfile(target_path):
            results = engine.scan_file(target_path)
            print_results(results, args.output)
            return None
        if None.path.isdir(target_path):
            print(f'''Scanning directory: {target_path}''')
            for root, _, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    results = engine.scan_file(file_path)
                    print_results(results, args.output)
            return None
        None(f'''Error: Target {target_path} not found.''')
        sys.exit(1)
        return None

if __name__ == '__main__':
    run()
    return None
