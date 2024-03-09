from threading import Event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Lock
from yara_py import Yara_Py

YARA_SKENER = None

class Watchdog_Py:
    def __init__(self, watchdog_active: Event, shutdown_signal: Event, yara_skener: Yara_Py, watchdog_path="/home/testtest/Downloads/"):
        self.watchdog_active = watchdog_active
        self.shutdown_signal = shutdown_signal
        self.watchdog_path = ""
        self.observer = Observer()
        self.event_handler = Handler()
        global YARA_SKENER
        YARA_SKENER = yara_skener

        self.set_watchdog_path(watchdog_path)

    def set_watchdog_path (self, watchdog_path):
        self.watchdog_path = watchdog_path

    def start_watchdog(self):
        self.watchdog_active.set()
        self.observer.schedule(self.event_handler, self.watchdog_path, recursive=True)
        self.observer.start()
        
    def stop_watchdog(self):
        self.watchdog_active.clear()
        self.shutdown_signal.set()
        self.observer.stop()
        self.observer.unschedule(self.event_handler)
        

    def is_watchdog_active(self):
        return self.watchdog_active.is_set()

class Handler(FileSystemEventHandler):
    lock = Lock()
    global YARA_SKENER

    @staticmethod
    def on_any_event(event):
        with Handler.lock:
            if event.is_directory:
                return None
            elif event.event_type == 'created':
                YARA_SKENER.set_file_path(event.src_path)
                YARA_SKENER.scan()
