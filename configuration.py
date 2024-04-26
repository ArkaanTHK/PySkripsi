from dotenv import set_key, get_key, find_dotenv, dotenv_values

def get_value(key) -> str:
    dotenv_path = check_file()
    return get_key(dotenv_path, key)

def set_value(key, value) -> None:
    dotenv_path = check_file()
    set_key(dotenv_path, key, value)
    
def get_all_values() -> dict:
    dotenv_path = check_file()
    return dotenv_values(dotenv_path)

def check_file() -> str:
    dotenv_path = find_dotenv()
    if dotenv_path == "":
        write_default_values()
        check_file()
    
    return dotenv_path

def write_default_values() -> None:
    with open(".env", "w") as file:
        file.write('YARA_RULES_FOR_APPLICATION_PATH="/mnt/hgfs/yara-rules-full.yar"\n')
        file.write('YARA_RULES_FOR_WATCHDOG_PATH="/mnt/hgfs/yara-rules-full.yar"\n')
        file.write('PCAP_DIR="./pcap/"\n')
        file.write('LOG_DIR="./logs/"\n')
        file.write('WATCHDOGDIR_PATH="/home/arkaan/Downloads/"\n')
        file.write('YARA_LOGS_PATH="./new_logs/yara_logs.log"\n')
        file.write('WATCHDOG_LOGS_PATH="./new_logs/watchdog_logs.log"\n')