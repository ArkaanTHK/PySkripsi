#!/usr/bin python3

from menu import Menu
from threading import Thread, Event
from sniffer import Sniffer
from configuration import Configuration
from colorama import Fore, Style
from watchdog_py import Watchdog_Py

if __name__ == "__main__":
    try:
        configuration = Configuration()

        shutdown_signal = Event()
        sniffing_active = Event()
        watchdog_active = Event()
        pcap_path = configuration.get_value("PCAP_PATH")
        log_path = configuration.get_value("LOG_PATH")
        sniffer = Sniffer(sniffing_active, shutdown_signal, pcap_path, log_path)
        watchdog = Watchdog_Py(watchdog_active, shutdown_signal, pcap_path)

        menu = Menu(sniffer, watchdog, configuration, shutdown_signal)
        # menu_thread = Thread(target=menu.main_menu)
        # menu_thread.start()
        # menu_thread.join()
        menu.main_menu()
    except SystemExit:
        print(Fore.RED + "\nExiting the program." + Style.RESET_ALL)
        if sniffer.is_sniffing_active():
            print(f"\n{Fore.RED}Sniffer still running, shutting down. Please wait...{Style.RESET_ALL}")
            sniffer.stop_sniffing()
        exit(0)