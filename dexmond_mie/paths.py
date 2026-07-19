import os
import sys
import shutil
import logging

logger = logging.getLogger('DEXMOND_MIE')

APP_NAME = 'DexmondMIE'


def is_frozen() -> bool:
    '''True when running from a PyInstaller-built executable.'''
    return getattr(sys, 'frozen', False)


def resource_dir() -> str:
    '''Base directory for read-only bundled files (rules, seed data).

    In a PyInstaller build these live in the temporary _MEIPASS extraction
    directory; in development they live at the project root.'''
    if is_frozen():
        return getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_dir() -> str:
    '''Writable directory for runtime files (token, state, quarantine).

    A packaged app cannot write next to its executable (Program Files is
    read-only and _MEIPASS is temporary), so installed builds use a per-user
    application-data folder. Development keeps everything under ./data.'''
    override = os.environ.get('DEXMOND_DATA_DIR')
    if override:
        path = override
    elif is_frozen():
        if os.name == 'nt':
            base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
        elif sys.platform == 'darwin':
            base = os.path.expanduser('~/Library/Application Support')
        else:
            base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
        path = os.path.join(base, APP_NAME)
    else:
        path = os.path.join(resource_dir(), 'data')
    os.makedirs(path, exist_ok=True)
    return path


def rules_dir() -> str:
    return os.environ.get('DEXMOND_RULES_DIR') or os.path.join(resource_dir(), 'rules')


def quarantine_dir() -> str:
    return os.environ.get('DEXMOND_QUARANTINE_DIR') or os.path.join(data_dir(), 'quarantine')


def state_file() -> str:
    return os.environ.get('DEXMOND_STATE_FILE') or os.path.join(data_dir(), 'state.json')


def token_file() -> str:
    return os.environ.get('DEXMOND_TOKEN_FILE') or os.path.join(data_dir(), '.auth_token')


def reputation_db() -> str:
    '''Writable reputation database path. On first run in a packaged build the
    bundled seed list is copied into the writable data directory so user
    additions persist across restarts.'''
    override = os.environ.get('DEXMOND_REPUTATION_DB')
    if override:
        return override
    target = os.path.join(data_dir(), 'reputation.json')
    if not os.path.exists(target):
        seed = os.path.join(resource_dir(), 'data', 'reputation.json')
        if os.path.exists(seed) and os.path.abspath(seed) != os.path.abspath(target):
            try:
                shutil.copyfile(seed, target)
            except OSError as e:
                logger.warning(f'Could not seed reputation DB: {e}')
    return target
