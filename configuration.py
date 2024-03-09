from dotenv import set_key, get_key, find_dotenv
from colorama import Fore, Style

class Configuration:
    def __init__(self):
        self.file_path = find_dotenv()
        self.yara_rules_path = "./yara_rules.yar"
        self.pcap_path = "./captured_packets.pcap"
        self.log_path = "./finals_packets.log"

        if self.file_path == "":
            self.write_default_values()
        
        else:
            self.load_values()
    
    def get_value(self, key):
        return get_key(self.file_path, key)
    
    def write_default_values(self):
        with open(".env", "w") as file:
            file.write("YARA_RULES_PATH=./yara_rules.yar\n")
            file.write("PCAP_PATH=./captured_packets.pcap\n")
            file.write("LOG_PATH=./finals_packets.log\n")
    
    def set_value(self, key, value):
        set_key(self.file_path, key, value)

    def load_values(self):
        # if there is no .env file, create one
        if not self.file_path:
            self.file_path = open(self.file_path, "w")
            self.file_path.close()
        
        # load values from .env file if they exist
        self.yara_rules_path = self.get_value("YARA_RULES_PATH") or self.yara_rules_path
        self.pcap_path = self.get_value("PCAP_PATH") or self.pcap_path
        self.log_path = self.get_value("LOG_PATH") or self.log_path

    def save_values(self):
        self.set_value("YARA_RULES_PATH", self.yara_rules_path)
        self.set_value("PCAP_PATH", self.pcap_path)
        self.set_value("LOG_PATH", self.log_path)