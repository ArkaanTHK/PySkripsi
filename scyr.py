import yara
import os

def main():
    # Lokasi file aturan YARA
    yara_rules_path = 'path_rules.yar'
    # Direktori yang ingin dipindai
    directory_to_scan = 'path'

    try:
        # Kompilasi aturan YARA dari file
        rules = yara.compile(filepath=yara_rules_path)
    except yara.SyntaxError as e:
        print(f"Terjadi kesalahan syntax dalam aturan YARA: {e}")
        return

    # Memastikan direktori yang diberikan valid
    if not os.path.isdir(directory_to_scan):
        print(f"Error: {directory_to_scan} bukan direktori yang valid.")
        return

    # Iterasi melalui setiap file dalam direktori (tanpa rekursif ke subdirektori)
    for file in os.listdir(directory_to_scan):
        full_path = os.path.join(directory_to_scan, file)
        if os.path.isfile(full_path):  # Memastikan hanya memproses jika itu adalah file
            try:
                matches = rules.match(full_path)
                if matches:
                    # Jika ada kecocokan, cetak lokasi file dan detail kecocokan
                    print(f"Kecocokan ditemukan di {full_path}: {matches}")
                else :
                    print(f"Tidak ada kecocokan ditemukan di {full_path}")
            except yara.Error as e:
                print(f"Error saat memindai {full_path}: {e}")

if __name__ == "__main__":
    main()