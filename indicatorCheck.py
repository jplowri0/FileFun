#!/usr/bin/env python
import csv
import webbrowser
import sys

def createList(csv_file):
    """
    Reads SHA256 hashes and file paths from a CSV and returns a list of tuples
    (file_path, sha256) for each entry.
    """
    indicatorList = []
    try:
        with open(csv_file, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_path = row.get("File Path") or row.get("filepath")
                sha256 = row.get("SHA256") or row.get("hash")
                if file_path and sha256:
                    indicatorList.append((file_path.strip(), sha256.strip()))
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)
    return indicatorList


def openBrowser_and_collect(csv_file, output_csv="accepted_indicators.csv"):
    """
    Opens each VirusTotal URL in browser, prompts user to accept or skip,
    and writes accepted file paths and hashes to a new CSV.
    """
    indicators = createList(csv_file)
    accepted = []

    for file_path, sha256 in indicators:
        url = f"https://www.virustotal.com/gui/search/{sha256}"
        webbrowser.open(url, new=2)
        answer = input("Proceed with this indicator? (l = accept, a = skip): ")
        if answer.lower() == "l":
            accepted.append((file_path, sha256))
        else:
            print("Skipped.")

    # Write the accepted indicators to CSV
    try:
        with open(output_csv, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['File Path', 'SHA256'])
            for fp, h in accepted:
                writer.writerow([fp, h])
        print(f"Accepted indicators written to {output_csv}")
    except Exception as e:
        print(f"Error writing output CSV: {e}")


def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: python vt_checker.py <input_hashes.csv> [<output_accepted.csv>]")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) == 3 else "accepted_indicators.csv"
    openBrowser_and_collect(input_csv, output_csv)

if __name__ == '__main__':
    main()

