from colorama import Fore, Style
from configuration import get_value

from menu import Menu
from sniffer import Sniffer
from threading import Event
from watchdog_py import Watchdog_Py

if __name__ == "__main__":
    try:
        # Event for signaling the shutdown of the program
        shutdown_signal = Event()
        sniffing_active = Event()
        watchdog_active = Event()

        # Get all necessary values from the configuration file
        pcap_dir = get_value("PCAP_DIR")
        log_dir = get_value("LOG_DIR")
        watchdog_path = get_value("WATCHDOGDIR_PATH")
        yara_rules_for_application_path = get_value("YARA_RULES_FOR_APPLICATION_PATH")
        yara_rules_for_watchdog_path = get_value("YARA_RULES_FOR_WATCHDOG_PATH")
        yara_logs_path = get_value("YARA_LOGS_PATH")
        watchdog_logs_path = get_value("WATCHDOG_LOGS_PATH")

        # Initialize the Sniffer and Watchdog
        sniffer = Sniffer(sniffing_active, shutdown_signal, yara_rules_for_application_path, yara_logs_path, pcap_dir, log_dir)
        watchdog = Watchdog_Py(watchdog_active, shutdown_signal, yara_rules_for_watchdog_path, yara_logs_path, watchdog_path, watchdog_logs_path)

        # Start the main menu
        menu = Menu(sniffer, watchdog, shutdown_signal)
        menu.main_menu()
    except SystemExit:
        print(Fore.RED + "\nExiting the program." + Style.RESET_ALL)
        if sniffer.is_sniffing_active():
            print(f"\n{Fore.RED}Sniffer still running, shutting down. Please wait...{Style.RESET_ALL}")
            sniffer.stop_sniffing()
            watchdog.stop_watchdog()
        exit(0)