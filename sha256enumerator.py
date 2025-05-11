import os
import hashlib
import csv

def read_root_path(config_file="config.txt"):
    try:
        with open(config_file, "r") as f:
            path = f.readline().strip()
            if not os.path.isdir(path):
                raise ValueError(f"Invalid path in config.txt: {path}")
            return path
    except Exception as e:
        print(f"Error reading config file: {e}")
        exit(1)

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_directory(root_path, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['File Path', 'SHA256'])

        for dirpath, _, filenames in os.walk(root_path):
            for name in filenames:
                file_path = os.path.join(dirpath, name)
                sha256_hash = compute_sha256(file_path)
                if sha256_hash:
                    writer.writerow([file_path, sha256_hash])

if __name__ == "__main__":
    root_directory = read_root_path("config.txt")
    output_csv_file = "file_hashes.csv"

    scan_directory(root_directory, output_csv_file)
    print(f"Done. Hashes written to {output_csv_file}")

