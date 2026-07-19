import os
import threading
import time
import webbrowser

import requests
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item

from . import paths

API_URL = os.environ.get('DEXMOND_API_URL', 'http://localhost:8888')
CHECK_INTERVAL = 5


def _auth_headers():
    try:
        with open(paths.token_file()) as f:
            return {'X-DEXMOND-Token': f.read().strip()}
    except OSError:
        return {}


def create_image(width=64, height=64, color1='black', color2='cyan'):
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
    return image


def open_dashboard(icon, item):
    if hasattr(icon, 'webview_window') and icon.webview_window:
        try:
            icon.webview_window.show()
            return
        except Exception:
            pass
    webbrowser.open(API_URL)


def exit_app(icon, item):
    icon.stop()
    if hasattr(icon, 'webview_window') and icon.webview_window:
        try:
            icon.webview_window.destroy()
        except Exception:
            pass
    os._exit(0)


def check_status(icon):
    while icon.visible is not None:
        try:
            resp = requests.get(f'{API_URL}/status', timeout=3, headers=_auth_headers())
            if resp.ok:
                icon.title = 'DEXMOND MIE - Active'
            else:
                icon.title = 'DEXMOND MIE - Degraded'
        except requests.RequestException:
            icon.title = 'DEXMOND MIE'
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
    image = create_image()
    menu = (
        item('Open Dashboard', open_dashboard, default=True),
        item('Status: Checking...', lambda icon, item: None, enabled=False),
        item('Exit', exit_app))
    icon = pystray.Icon('dexmond_mie', image, 'DEXMOND MIE', menu)
    icon.webview_window = window
    icon_instance = icon
    t = threading.Thread(target=check_status, args=(icon,), daemon=True)
    t.start()
    icon.run()


if __name__ == '__main__':
    run_tray()
