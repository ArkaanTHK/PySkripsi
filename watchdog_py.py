import time
from threading import Event
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class Watchdog_Py:
    def __init__(self, watchdog_active: Event, shutdown_signal: Event, watchdog_path= ""):
        self.watchdog_active = watchdog_active
        self.shutdown_signal = shutdown_signal
        self.watchdog_path = ""
        self.observer = Observer()

        self.set_watchdog_path(watchdog_path)

    def set_watchdog_path (self, watchdog_path):
        self.watchdog_path = watchdog_path

    def start_watchdog(self):
        event_handler = Handler()
        self.watchdog_active.set()
        self.observer.schedule(event_handler, self.watchdog_path, recursive=True)
        self.observer.start()
        try:
            while not self.shutdown_signal.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_watchdog()
        
        self.observer.join()

    def stop_watchdog(self):
        self.watchdog_active.clear()
        self.shutdown_signal.set()
        self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None
        elif event.event_type == 'created' or event.event_type == 'modified':
            print("Watchdog received created event - % s." % event.src_path)
            # cek pake yara disini