# Source Generated with Decompyle++
# File: realtime.pyc (Python 3.10)

import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core import Engine
logger = logging.getLogger('DEXMOND_REALTIME')

class MalwareEventHandler(FileSystemEventHandler):
    
    def __init__(self, engine, notification_callback = (None,)):
        self.engine = engine
        self.notification_callback = notification_callback

    
    def on_created(self, event):
        pass
    # WARNING: Decompyle incomplete



class RealtimeScanner:
    
    def __init__(self, rules_dir, notification_callback = (None,)):
        self.engine = Engine(rules_dir)
        self.observer = Observer()
        self.notification_callback = notification_callback

    
    def start(self, watch_dir = (None,)):
        pass
    # WARNING: Decompyle incomplete

    
    def stop(self):
        self.observer.stop()
        self.observer.join()


