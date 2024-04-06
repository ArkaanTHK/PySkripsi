from dotenv import set_key, get_key, find_dotenv, dotenv_values

class Configuration:
    def __init__(self):
        self.file_path = find_dotenv()
        self.configurations = {}

        if self.file_path == "":
            self.write_default_values()
        
        else:
            self.load_values()
    
    def get_value(self, key):
        return get_key(self.file_path, key)
    
    def load_values(self):
        self.configurations = dotenv_values(self.file_path)

    def write_default_values(self):
        with open(".env", "w") as file:
            file.write("YARA_RULES_PATH=./yara_rules.yar\n")
            file.write("PCAP_PATH=./captured_packets.pcap\n")
            file.write("LOG_PATH=./finals_packets.log\n")
    
    def set_value(self, key, value):
        set_key(self.file_path, key, value)
        self.configurations[key] = value

    def get_all_values(self):
        # refresh configurations
        self.load_values()
        return self.configurations