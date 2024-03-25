from menu import Menu
from threading import Thread, Event
from sniffer import Sniffer
from configuration import Configuration
from colorama import Fore, Style
from watchdog_py import Watchdog_Py
from yara_py import Yara_Py

if __name__ == "__main__":
    try:
        configuration = Configuration()

        shutdown_signal = Event()
        sniffing_active = Event()
        watchdog_active = Event()
        pcap_dir = configuration.get_value("PCAP_DIR")
        log_dir = configuration.get_value("LOG_DIR")
        watchdog_path = configuration.get_value("WATCHDOGDIR_PATH")
        yara_rules_path = configuration.get_value("YARA_RULES_PATH")
        yara_logs_path = configuration.get_value("YARA_LOGS_PATH")
        watchdog_logs_path = configuration.get_value("WATCHDOG_LOGS_PATH")

        sniffer = Sniffer(sniffing_active, shutdown_signal, pcap_dir, log_dir)
        yara_skener = Yara_Py(yara_rules_path, yara_logs_path)
        watchdog = Watchdog_Py(watchdog_active, shutdown_signal, yara_skener, watchdog_path, watchdog_logs_path)

        menu = Menu(sniffer, watchdog, configuration, shutdown_signal)
        menu.main_menu()
    except SystemExit:
        print(Fore.RED + "\nExiting the program." + Style.RESET_ALL)
        if sniffer.is_sniffing_active():
            print(f"\n{Fore.RED}Sniffer still running, shutting down. Please wait...{Style.RESET_ALL}")
            sniffer.stop_sniffing()
            watchdog.stop_watchdog()
        exit(0)