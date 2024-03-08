from menu import Menu
from threading import Thread, Event
from sniffer import Sniffer
from colorama import Fore, Style

if __name__ == "__main__":
    try:
        shutdown_signal = Event()
        sniffing_active = Event()
        menu = Menu()
        sniffer = Sniffer(sniffing_active, shutdown_signal)
        menu_thread = Thread(target=menu.main_menu)
        menu_thread.start()
        menu_thread.join()
    except KeyboardInterrupt:
        sniffer.stop_sniffing()
        print(Fore.RED + "Exiting the program due to KeyboardInterrupt." + Style.RESET_ALL)