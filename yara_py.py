from yara import compile, SyntaxError as YaraSyntaxError, Error as YaraError
import os

class Yara_Py:
    def __init__ (self, yara_rules_path='/home/maruu/skripsi/packages/core/yara-rules-core.yar', directory_path='/home/maruu/skripsi2/'):
        self.yara_rules_path = ""
        self.directory_path = ""
        self.rules = None

        self.set_yara_rules_path(yara_rules_path)
        self.set_directory_path(directory_path)

    def set_yara_rules_path(self, yara_rules_path):
        self.yara_rules_path = yara_rules_path
        self.set_rules()

    def set_directory_path(self, directory_path):
        self.directory_path = directory_path

    def check_directory_validity(self):
        if not os.path.isdir(self.directory_path):
            print(f"Directory {self.directory_path} tidak valid")
            return False
        return True

    def set_rules(self):
        try:
            self.rules = compile(filepath=self.yara_rules_path)
        except YaraSyntaxError as e:
            print(f"Terjadi kesalahan syntax dalam aturan YARA: {e}")
            return

    def scan(self):
        if self.check_directory_validity():
            for file in os.listdir(self.directory_path):
                full_path = os.path.join(self.directory_path, file)
                if os.path.isfile(full_path):
                    try:
                        matches = self.rules.match(full_path)
                        if matches:
                            print(f"Kecocokan ditemukan di {full_path}: {matches}")
                        else :
                            print(f"Tidak ada kecocokan ditemukan di {full_path}")
                    except YaraError as e:
                        print(f"Error saat memindai {full_path}: {e}")