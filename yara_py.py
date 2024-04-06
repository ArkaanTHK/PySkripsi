import yara
import os
import time
from os import path, makedirs
from configuration import Configuration

class Yara_Py:
    def __init__ (self, yara_rules_path='/home/maruu/skripsi/packages/core/yara-rules-core.yar', logs_path='./new_logs/yara_logs.log'):
        self.yara_rules_path = ""
        self.file_path = ""
        self.rules = None
        self.logs_path = ""

        yara.set_config(max_strings_per_rule=1000000, stack_size=99999999)
        self.set_yara_rules_path(yara_rules_path)
        self.set_yara_logs_path(logs_path)

    def set_yara_rules_path(self, yara_rules_path):
        self.yara_rules_path = yara_rules_path
        self.set_rules()

    def set_yara_logs_path(self, logs_path):
        self.logs_path = logs_path
        self.check_and_create_paths(logs_path)

    def check_and_create_paths(self, file_path):
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def set_file_path(self, file_path):
        self.file_path = file_path

    def set_rules(self):
        timeout = 60  # Adjust as needed
        compiling = False

        start_time = time.time()

        while True:
            try:
                # Compile YARA rules with error_on_warning=True
                if compiling == False:
                    self.rules = yara.compile(filepath=self.yara_rules_path)
                    compiling = True
                if self.rules is not None:
                    print("YARA rules compiled successfully.")
                    break  # Exit loop if compilation is successful
                else:
                    print("YARA rules still compiled with warnings. Retrying...")
                
            except yara.Error as e:
                print(f"Terjadi kesalahan dalam aturan YARA: {e}")
                print("apakah ingin mengatur ulang lokasi file yara rules? (y/n): ", end="")
                answer = input()
                if answer == "y":
                    print("Masukkan alamat file aturan YARA: ", end="")
                    self.yara_rules_path = input()
                    self.set_rules()
                    print("Lokasi file aturan YARA telah diatur ulang!\nPress enter to continue...")
                    input()
                    configuration = Configuration()
                    configuration.set_value("YARA_RULES_PATH", self.yara_rules_path)
                    del configuration
                else:
                    exit(1)
                
            # Check if timeout has been reached
            if time.time() - start_time >= timeout:
                print("Timeout reached. Failed to compile YARA rules within specified time.")
                break  # Exit loop if timeout is reached
                
            # Wait before checking again
            time.sleep(1)  # Adjust sleep time as needed

    def scan(self):
        if os.path.isfile(self.file_path):
            try:
                if self.rules is not None:
                    matches = self.rules.match(self.file_path, timeout=3600)
                    with open(self.logs_path, 'a') as logs:
                        if matches:
                            logs.write(f"{time.ctime()} - {self.file_path} - {matches}\n")
                        else:
                            logs.write(f"{time.ctime()} - {self.file_path} - No Match\n")
                else:
                    print("Tidak ada aturan YARA yang ditemukan.")
            except yara.Error as e:
                print(f"Error saat memindai {self.file_path}: {e}")
                