import yara
import os

class Yara_Py:
    def __init__ (self, yara_rules_path='/home/maruu/skripsi/packages/core/yara-rules-core.yar'):
        self.yara_rules_path = ""
        self.file_path = ""
        self.rules = None

        self.set_yara_rules_path(yara_rules_path)

    def set_yara_rules_path(self, yara_rules_path):
        self.yara_rules_path = yara_rules_path
        self.set_rules()

    def set_file_path(self, file_path):
        self.file_path = file_path

    def set_rules(self):
        try:
            self.rules = yara.compile(filepath=self.yara_rules_path)
        except yara.SyntaxError as e:
            print(f"Terjadi kesalahan syntax dalam aturan YARA: {e}")
            return

    def scan(self):
        if os.path.isfile(self.file_path):
            try:
                matches = self.rules.match(self.file_path, timeout=3600)
                if matches:
                    print(f"Kecocokan ditemukan di {self.file_path}: {matches}")
                else :
                    print(f"Tidak ada kecocokan ditemukan di {self.file_path}")
            except yara.Error as e:
                print(f"Error saat memindai {self.file_path}: {e}")
                