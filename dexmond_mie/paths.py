import os
import sys
import stat
import shutil
import logging
import subprocess

logger = logging.getLogger('DEXMOND_MIE')

APP_NAME = 'DexmondMIE'

# IsReparseTagNameSurrogate(): set on Windows symbolic links and junctions/mount
# points, NOT on OneDrive cloud-placeholder files (which remain scannable).
_REPARSE_TAG_NAME_SURROGATE = 0x20000000


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
    '''Writable directory for runtime files (token, state, quarantine, scratch).

    A packaged app cannot write next to its executable (Program Files is
    read-only and _MEIPASS is temporary), so installed builds use a per-user
    application-data folder. On Windows even source runs default to
    %LOCALAPPDATA%\\DexmondMIE so .auth_token inherits per-user profile ACLs.'''
    override = os.environ.get('DEXMOND_DATA_DIR')
    if override:
        path = override
    elif is_frozen() or os.name == 'nt':
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


def scratch_dir() -> str:
    '''Dedicated scratch folder for archive extraction and browser uploads
    (kept outside watched user folders and %TEMP% to prevent self-scan loops).'''
    path = os.environ.get('DEXMOND_SCRATCH_DIR') or os.path.join(data_dir(), 'scratch')
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


def is_symlink_or_junction_stat(st) -> bool:
    '''True if an lstat result represents a symlink or Windows junction.'''
    return bool(stat.S_ISLNK(st.st_mode)
                or (getattr(st, 'st_reparse_tag', 0) & _REPARSE_TAG_NAME_SURROGATE))


def is_symlink_or_junction(path: str) -> bool:
    try:
        return is_symlink_or_junction_stat(os.lstat(path))
    except OSError:
        return False


def is_regular_non_link(path: str) -> bool:
    '''True only when path exists, is NOT a symlink/junction, and is a regular
    file (refuses FIFOs, sockets, device nodes, directories, and links).'''
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if is_symlink_or_junction_stat(st):
        return False
    return stat.S_ISREG(st.st_mode)


def ensure_owner_only_file(path: str) -> None:
    '''Restricts file permissions to the current OS user (0600 on POSIX;
    owner + SYSTEM NTFS DACL on Windows).'''
    try:
        if os.name == 'nt':
            sys_root = os.environ.get('SystemRoot', r'C:\Windows')
            icacls = os.path.join(sys_root, 'System32', 'icacls.exe')
            user = os.environ.get('USERNAME', '')
            domain = os.environ.get('USERDOMAIN', '')
            account = f'{domain}\\{user}' if domain and user else user
            grants = ['*S-1-5-18:(F)', '*S-1-5-32-544:(F)']
            if account:
                grants.insert(0, f'{account}:(F)')
            cmd = [icacls, path, '/inheritance:r']
            for g in grants:
                cmd.extend(['/grant:r', g])
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False, timeout=5)
        else:
            os.chmod(path, 0o600)
    except Exception as e:
        logger.debug(f'Could not tighten permissions on {path}: {e}')
