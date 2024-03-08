from threading import Thread
from colorama import Fore, Style
import sniffer

class Menu:
    def print_menu(title, options):
        print(Fore.GREEN + Style.BRIGHT + f"=== {title} ===" + Style.RESET_ALL)
        for i, option in enumerate(options, start=1):
            print(f"{Fore.YELLOW}{i}. {option}{Style.RESET_ALL}")
        
    def get_user_choice(self, options):
        while True:
            try:
                choice = int(input(Fore.CYAN + "Enter your choice: " + Style.RESET_ALL))
                if 1 <= choice <= len(options):
                    return choice
                else:
                    print(Fore.RED + "Invalid choice. Please enter a valid option." + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a number." + Style.RESET_ALL)

    def main_menu(self):
        title = "System Control"
        options = ["Toggle Packet Sniffing", "Option 2", "Option 3", "Exit"]

        while True:
            self.print_menu(title, options)
            choice = self.get_user_choice(options)

            if choice == 1:
                if sniffer.is_sniffing_active():
                    sniffer.stop_sniffing()
                else:
                    sniffer.start_sniffing()
            elif choice == 2:
                print("You chose Option 2.")
                # Add your logic here for Option 2
            elif choice == 3:
                print("You chose Option 3.")
                # Add your logic here for Option 3
            elif choice == 4:
                sniffer.stop_sniffing()
                print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                break