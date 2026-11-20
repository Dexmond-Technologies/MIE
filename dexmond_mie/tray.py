import os
import sys
import threading
import time
import urllib.parse
import webbrowser

try:
    import requests
except ImportError:
    requests = None

try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = ImageDraw = None

try:
    import pystray
    from pystray import MenuItem as item
except Exception:
    pystray = None
    item = None

from . import paths

API_URL = os.environ.get('DEXMOND_API_URL', 'http://127.0.0.1:8888')
CHECK_INTERVAL = 5
_status_label = 'Status: Checking...'


def _auth_headers():
    try:
        with open(paths.token_file(), encoding='utf-8') as f:
            return {'X-DEXMOND-Token': f.read().strip()}
    except OSError:
        return {}


def _launch_url() -> str:
    try:
        resp = requests.post(f'{API_URL}/api/auth/ticket', timeout=2, headers=_auth_headers())
        if resp.ok:
            ticket = (resp.json() or {}).get('ticket', '')
            if ticket:
                return f'{API_URL}/launch?ticket={urllib.parse.quote(ticket, safe="")}'
    except requests.RequestException:
        pass
    return API_URL


def create_image(width=64, height=64, color1='black', color2='cyan'):
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
    return image


def open_dashboard(icon, _item):
    if hasattr(icon, 'webview_window') and icon.webview_window:
        try:
            icon.webview_window.show()
            return
        except Exception:
            pass
    webbrowser.open(_launch_url())


def exit_app(icon, _item):
    try:
        requests.post(f'{API_URL}/api/shutdown', timeout=2, headers=_auth_headers())
    except requests.RequestException:
        pass
    icon.stop()
    if hasattr(icon, 'webview_window') and icon.webview_window:
        try:
            icon.webview_window.destroy()
        except Exception:
            pass
    sys.exit(0)


def _derive_tray_status(data: dict) -> tuple:
    prot = (data or {}).get('protection') or {}
    active = bool(prot.get('active'))
    yara_status = str((data or {}).get('yara_status') or 'ON').upper()
    if yara_status == 'YARA-OFF':
        return ('DEXMOND MIE - YARA Off', 'Status: YARA Off')
    if yara_status == 'DEGRADED':
        state = 'Monitoring On' if active else 'Monitoring Off'
        return (f'DEXMOND MIE - YARA Degraded ({state})', f'Status: YARA Degraded ({state})')
    if not active:
        return ('DEXMOND MIE - Monitoring Off', 'Status: Monitoring Off')
    return ('DEXMOND MIE - Active', 'Status: Active')


def check_status(icon):
    global _status_label
    while icon.visible is not None:
        try:
            resp = requests.get(f'{API_URL}/status', timeout=3, headers=_auth_headers())
            if resp.ok:
                title, label = _derive_tray_status(resp.json())
                icon.title = title
                _status_label = label
            else:
                icon.title = 'DEXMOND MIE - Unauthorized / Degraded'
                _status_label = 'Status: Degraded'
        except (requests.RequestException, ValueError):
            icon.title = 'DEXMOND MIE - Offline'
            _status_label = 'Status: Offline'
        try:
            icon.update_menu()
        except Exception:
            pass
        time.sleep(CHECK_INTERVAL)


icon_instance = None


def show_notification(title, msg):
    if icon_instance is not None:
        try:
            icon_instance.notify(msg, title)
        except Exception:
            pass


def run_tray(window=None):
    global icon_instance
    if pystray is None or Image is None or requests is None:
        raise ImportError('System tray dependencies (pystray/Pillow/requests) or display server unavailable')
    try:
        from . import webapp
        webapp.protection.notification_callback = show_notification
    except Exception:
        pass
    image = create_image()
    menu = (
        item('Open Dashboard', open_dashboard, default=True),
        item(lambda _item: _status_label, lambda icon, _item: None, enabled=False),
        item('Exit', exit_app))
    icon = pystray.Icon('dexmond_mie', image, 'DEXMOND MIE', menu)
    icon.webview_window = window
    icon_instance = icon
    t = threading.Thread(target=check_status, args=(icon,), daemon=True)
    t.start()
    icon.run()


if __name__ == '__main__':
    run_tray()
