import os
import time
import ctypes
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .core import Engine, needs_alert, auto_quarantine_allowed
from . import paths

logger = logging.getLogger('DEXMOND_REALTIME')

ALERT_THRESHOLD = 30

# In-progress download / temp files; scanned once they are renamed to
# their final name (which arrives as a moved event).
IGNORED_EXTENSIONS = {'.crdownload', '.part', '.partial', '.download', '.tmp', '.qtn'}
DEBOUNCE_SECONDS = 2.0

# Windows Known Folder GUIDs (Downloads, Desktop, Documents), resolving
# OneDrive Known Folder Move paths automatically (Finding W-4).
_KNOWN_FOLDER_GUIDS = (
    (0x374DE290, 0x123F, 0x4565, (0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B)),  # Downloads
    (0xB4BFCC3A, 0xDB2C, 0x424C, (0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41)),  # Desktop
    (0xFDD39AD0, 0x238F, 0x46AF, (0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7)),  # Documents
)


def _windows_known_folders():
    if os.name != 'nt':
        return []
    try:
        class _GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', ctypes.c_uint32),
                ('Data2', ctypes.c_uint16),
                ('Data3', ctypes.c_uint16),
                ('Data4', ctypes.c_uint8 * 8),
            ]

        shell32 = ctypes.windll.shell32
        ole32 = ctypes.windll.ole32
        out = []
        for d1, d2, d3, d4 in _KNOWN_FOLDER_GUIDS:
            guid = _GUID(d1, d2, d3, (ctypes.c_uint8 * 8)(*d4))
            ptr = ctypes.c_wchar_p()
            hr = shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
            if hr == 0 and ptr.value:
                out.append(ptr.value)
            if ptr:
                ole32.CoTaskMemFree(ptr)
        return out
    except Exception as e:
        logger.debug(f'SHGetKnownFolderPath unavailable: {e}')
        return []


def _is_internal_mie_path(path: str) -> bool:
    '''True when path is inside MIE's own runtime data, scratch, or quarantine
    folders (prevents self-scan loops — Finding W-3).'''
    try:
        target = os.path.abspath(path)
        for internal in (paths.data_dir(), paths.scratch_dir(), paths.quarantine_dir()):
            internal_abs = os.path.abspath(internal)
            try:
                if os.path.commonpath([target, internal_abs]) == internal_abs:
                    return True
            except ValueError:
                continue
    except OSError:
        pass
    return False


class MalwareEventHandler(FileSystemEventHandler):

    def __init__(self, engine, notification_callback=None, result_callback=None,
                 scanner=None):
        self.engine = engine
        self.notification_callback = notification_callback
        self.result_callback = result_callback
        self.scanner = scanner
        self._recent = {}

    def on_created(self, event):
        if not event.is_directory:
            self._scan(event.src_path)

    def on_moved(self, event):
        # Downloads finish as a rename from foo.crdownload to foo
        if not event.is_directory:
            self._scan(event.dest_path)

    def _scan(self, path):
        if os.path.splitext(path)[1].lower() in IGNORED_EXTENSIONS:
            return
        if _is_internal_mie_path(path):
            return
        now = time.time()
        last = self._recent.get(path, 0)
        self._recent[path] = now
        if now - last < DEBOUNCE_SECONDS:
            return
        if len(self._recent) > 512:
            cutoff = now - 60
            self._recent = {p: t for p, t in self._recent.items() if t > cutoff}
        # Give the writing process a moment to finish flushing the file
        time.sleep(0.5)
        if not paths.is_regular_non_link(path):
            return
        try:
            results = self.engine.scan_file(path)
        except Exception as e:
            logger.error(f'Realtime scan failed for {path}: {e}')
            return
        if 'error' in results:
            return
        score = results.get('score', 0)
        verdict = results.get('verdict', 'UNKNOWN')
        logger.info(f'Realtime scan: {path} -> {verdict} ({score})')

        # Auto-quarantine confirmed threats before notifying, if enabled
        quarantined = False
        if (self.scanner and self.scanner.auto_quarantine
                and self.scanner.quarantine_callback
                and auto_quarantine_allowed(results)):
            try:
                self.scanner.quarantine_callback(path, results)
                quarantined = True
                results['auto_quarantined'] = True
            except Exception as e:
                logger.error(f'Auto-quarantine failed for {path}: {e}')

        if self.result_callback:
            self.result_callback(results)
        if needs_alert(results, ALERT_THRESHOLD) and self.notification_callback:
            suffix = ' - quarantined' if quarantined else ''
            self.notification_callback(
                'DEXMOND MIE Alert',
                f'{os.path.basename(path)}: {verdict} (Score: {score}/100){suffix}')


class RealtimeScanner:
    '''Folder watcher: scans files created in or moved into the watched user
    folders, after they are written, while the app runs. Files changed in
    place are not rescanned; nothing is blocked before it is opened.'''

    def __init__(self, rules_dir, notification_callback=None, result_callback=None,
                 engine=None, quarantine_callback=None):
        self.engine = engine or Engine(rules_dir)
        self.observer = None
        self.notification_callback = notification_callback
        self.result_callback = result_callback
        self.quarantine_callback = quarantine_callback
        self.auto_quarantine = False
        self.watched = []

    @staticmethod
    def default_watch_dirs():
        '''User folders where new files typically land (Downloads, Desktop,
        Documents — including OneDrive Known Folder Move locations on Windows).'''
        home = os.path.expanduser('~')
        if os.name == 'nt':
            raw = _windows_known_folders() + [
                os.path.join(home, 'Downloads'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Documents'),
            ]
        else:
            raw = [os.path.join(home, 'Downloads')]
        seen = set()
        result = []
        for d in raw:
            if not d or not os.path.isdir(d):
                continue
            norm = os.path.normcase(os.path.abspath(d))
            if norm not in seen and not _is_internal_mie_path(d):
                seen.add(norm)
                result.append(os.path.abspath(d))
        return result

    @property
    def is_active(self):
        return self.observer is not None

    def start(self, watch_dirs=None):
        if self.observer is not None:
            return self.watched
        if watch_dirs is None:
            watch_dirs = self.default_watch_dirs()
        elif isinstance(watch_dirs, str):
            watch_dirs = [watch_dirs]
        watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]
        if not watch_dirs:
            logger.warning('No valid watch directories; folder monitoring not started')
            return []
        handler = MalwareEventHandler(self.engine, self.notification_callback,
                                      self.result_callback, scanner=self)
        self.observer = Observer()
        for d in watch_dirs:
            self.observer.schedule(handler, d, recursive=True)
        self.observer.start()
        self.watched = watch_dirs
        logger.info(f'Folder monitoring active, watching: {", ".join(watch_dirs)}')
        return self.watched

    def stop(self):
        if self.observer is None:
            return
        self.observer.stop()
        self.observer.join()
        self.observer = None
        self.watched = []
        logger.info('Folder monitoring stopped')
