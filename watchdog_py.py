from threading import Event
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Lock
from yara_py import Yara_Py
from os import path, makedirs

YARA_SKENER = None
LOG_PATH = ""

class Watchdog_Py:
    def __init__(self, watchdog_active: Event, shutdown_signal: Event, yara_skener: Yara_Py, watchdog_path="/home/testtest/Downloads/", logs_path="./new_logs/watchdog_logs.log"):
        self.watchdog_active = watchdog_active
        self.shutdown_signal = shutdown_signal
        self.watchdog_path = ""
        self.observer = Observer()
        self.event_handler = Handler()
        global YARA_SKENER
        YARA_SKENER = yara_skener
        self.logs_path = ""

        self.set_watchdog_path(watchdog_path)
        self.set_logs_path(logs_path)

    def set_watchdog_path (self, watchdog_path):
        self.watchdog_path = watchdog_path

    def set_logs_path(self, logs_path):
        self.logs_path = logs_path
        global LOG_PATH
        LOG_PATH = logs_path
        self.check_and_create_paths(logs_path)

    def check_and_create_paths(self, file_path):
        folder_path = path.dirname(file_path)
        print(folder_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def start_watchdog(self):
        self.watchdog_active.set()
        self.observer.schedule(self.event_handler, self.watchdog_path, recursive=True)
        self.observer.start()
        
    def stop_watchdog(self):
        self.watchdog_active.clear()
        self.shutdown_signal.set()
        self.observer.stop()
        self.observer.join()
        self.observer = Observer()
        

    def is_watchdog_active(self):
        return self.watchdog_active.is_set()

class Handler(FileSystemEventHandler):
    lock = Lock()
    global YARA_SKENER
    global LOG_PATH

    @staticmethod
    def on_any_event(event):
        with Handler.lock:
            if event.is_directory:
                return None
            elif event.event_type == 'created':
                with open(LOG_PATH, 'a') as logs:
                    logs.write(f"{time.ctime()} - {event.src_path} Created\n")
                YARA_SKENER.set_file_path(event.src_path)
                YARA_SKENER.scan()