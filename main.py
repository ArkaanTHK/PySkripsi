from colorama import Fore, Style

from menu import Menu
from sniffer import Sniffer
from threading import Event
from watchdog_py import Watchdog_Py

if __name__ == "__main__":
    try:
        # Event for signaling the shutdown of the program
        sniffing_active = Event()
        watchdog_active = Event()

        # Initialize the Sniffer and Watchdog
        sniffer = Sniffer(sniffing_active)
        watchdog = Watchdog_Py(watchdog_active)

        # Start the main menu
        menu = Menu(sniffer, watchdog)
        menu.main_menu()
    except SystemExit:
        print(Fore.RED + "\nExiting the program." + Style.RESET_ALL)
        if sniffer.is_sniffing_active():
            print(f"\n{Fore.RED}Sniffer still running, shutting down. Please wait...{Style.RESET_ALL}")
            sniffer.stop_sniffing()
        if watchdog.is_watchdog_active():
            print(f"\n{Fore.RED}Watchdog still running, shutting down. Please wait...{Style.RESET_ALL}")
            watchdog.stop_watchdog()
        exit(0)