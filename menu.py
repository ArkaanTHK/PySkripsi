from colorama import Fore, Style
from configuration import get_all_values, set_value

from sniffer import Sniffer
from threading import Event
from watchdog_py import Watchdog_Py

class Menu:
    def __init__(self, sniffer: Sniffer,watchdog: Watchdog_Py) -> None:
        self.sniffer = sniffer
        self.watchdog = watchdog

    def print_menu(self, title, options) -> None:
        print("\033c")
        print(Fore.GREEN + Style.BRIGHT + f"=== {title} ===" + Style.RESET_ALL)
        for i, option in enumerate(options, start=1):
            if i == 1:
                if self.sniffer.is_sniffing_active():
                    checkmark_color = Fore.GREEN
                    checkmark = "\u2713"
                else:
                    checkmark_color = Fore.RED
                    checkmark = "X"

            elif i == 2:
                if self.watchdog.is_watchdog_active():
                    checkmark_color = Fore.GREEN
                    checkmark = "\u2713"
                else:
                    checkmark_color = Fore.RED
                    checkmark = "X"
            else:
                checkmark_color = ""
                checkmark = ""
            print(f"{Fore.YELLOW}{i}. {option}{checkmark_color} {checkmark}{Style.RESET_ALL}")
        
    def get_user_choice(self, length) -> int:
        try:
            while True:
                try:
                    choice = int(input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL))
                    if 1 <= choice <= length:
                        return choice
                    else:
                        print(Fore.RED + "Invalid choice. Please enter a valid option." + Style.RESET_ALL)
                except ValueError:
                    print(Fore.RED + "Invalid input. Please enter a number." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print(f"{Fore.RED}\n\nKeyboard Interrupt Detected!{Style.RESET_ALL}")
            raise SystemExit
        

    def main_menu(self) -> None:
        title = "System Control"
        options = ["Toggle Packet Sniffing", "Toggle Watchdog Scanning", "Configuration", "Exit"]

        try:
            while True:
                self.print_menu(title, options)
                choice = self.get_user_choice(len(options))
            
                if choice == 1:
                    if self.sniffer.is_sniffing_active():
                        self.sniffer.stop_sniffing()
                    else:
                        self.sniffer.start_sniffing()
                elif choice == 2:
                    print("You choose Option 2.")
                    if self.watchdog.is_watchdog_active():
                        self.watchdog.stop_watchdog()
                    else:
                        self.watchdog.start_watchdog()
                elif choice == 3:
                    self.show_config_menu()
                elif choice == 4:
                    self.sniffer.stop_sniffing()
                    print(Fore.GREEN + "Exiting the program. Goodbye! (Please wait until all activites to be stopped. The program will closed by itself)" + Style.RESET_ALL)
                    break
        except KeyboardInterrupt:
            print("keyboard interrupt dari main_menu")
            exit(0)

    def show_config_menu(self) -> None:
        configs = get_all_values()

        print("\033c")
        print(f"{Fore.YELLOW}=== Configuration ==={Style.RESET_ALL}")
        for i, (key, value) in enumerate(configs.items(), start=1):
            print(f"{Fore.YELLOW}{i}. {key}: {Fore.CYAN}{value}{Style.RESET_ALL}")

        print(f"{Fore.YELLOW}{len(configs) + 1}. Back")
        print(f"====================={Style.RESET_ALL}")

        choice = self.get_user_choice(len(configs) + 1)

        if 1 <= choice <= len(configs):
            key = list(configs.keys())[choice - 1]

            print(f"Enter new value for {key} ('-' to back): ", end="")
            new_value = input()

            if new_value != "-":
                setattr(self.configuration, key.lower(), new_value)
                set_value(key, new_value)
                
                print(f"{Fore.LIGHTGREEN_EX}{key} has been updated to {new_value}.{Style.RESET_ALL}")
                input("Press Enter to continue...")
        elif choice == len(configs) + 1:
            return
        else:
            print("Invalid choice. Please enter a valid option.")
            return