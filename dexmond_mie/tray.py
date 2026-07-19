# Source Generated with Decompyle++
# File: tray.pyc (Python 3.10)

import os
import sys
import threading
import time
import webbrowser
import requests
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item
API_URL = 'http://localhost:8000'
CHECK_INTERVAL = 5

def create_image(width, height, color1, color2 = (64, 64, 'black', 'cyan')):
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), color2, **('fill',))
    return image


def open_dashboard(icon, item):
    if hasattr(icon, 'webview_window') and icon.webview_window:
        
        try:
            icon.webview_window.show()
        finally:
            return None
            webbrowser.open(API_URL)
            return None
            webbrowser.open(API_URL)
            return None



def exit_app(icon, item):
    icon.stop()
    if hasattr(icon, 'webview_window') and icon.webview_window:
        
        try:
            icon.webview_window.destroy()
        finally:
            pass
        import os
        os._exit(0)
        return None



def check_status(icon):
    pass
# WARNING: Decompyle incomplete

icon_instance = None

def show_notification(title, msg):
    pass
# WARNING: Decompyle incomplete


def run_tray(window = (None,)):
    global icon_instance
    image = create_image()
    menu = (item('Open Dashboard', open_dashboard, True, **('default',)), item('Status: Checking...', (lambda icon, item: pass), False, **('enabled',)), item('Exit', exit_app))
    icon = pystray.Icon('dexmond_mie', image, 'DEXMOND MIE', menu)
    icon.webview_window = window
    icon_instance = icon
    t = threading.Thread(check_status, (icon,), True, **('target', 'args', 'daemon'))
    t.start()
    icon.run()

if __name__ == '__main__':
    run_tray()
    return None
