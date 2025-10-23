# File: vt_score_check.py

import csv
import sys
import time
import requests

API_KEYS = [
    "YOUR_FIRST_API_KEY_HERE",
    "YOUR_SECOND_API_KEY_HERE",
    "YOUR_THIRD_API_KEY_HERE",
]

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
TIMEOUT = 20
DELAY_BETWEEN_REQUESTS = 2


def get_vt_score(ip: str) -> str:
    """Query VirusTotal for an IP, rotating API keys on timeout or rate-limit."""
    for key_index, api_key in enumerate(API_KEYS):
        headers = {"x-apikey": api_key}
        try:
            resp = requests.get(API_URL.format(ip), headers=headers, timeout=TIMEOUT)
            if resp.status_code == 429:
                print(f"[!] Rate limit hit on key #{key_index + 1}, rotating key...")
                continue  # rotate to next key

            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            return f"{malicious}/{total}" if total > 0 else "N/A"

        except requests.exceptions.Timeout:
            print(f"[!] Timeout (> {TIMEOUT}s) on key #{key_index + 1}, rotating key...")
            continue
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error on key #{key_index + 1}: {e}")
            continue
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            continue

    return "Error: All keys failed"


def process_csv(input_file: str, output_file: str) -> None:
    """Read IPs from input CSV, query VT, and write results to output CSV."""
    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        writer.writerow(["IP Address", "VT Score"])

        for row in reader:
            if not row:
                continue
            ip = row[0].strip()
            if not ip:
                continue

            score = get_vt_score(ip)
            print(f"{ip} → {score}")

            writer.writerow([ip, score])
            time.sleep(DELAY_BETWEEN_REQUESTS)  # reduced delay


def main():
    if len(sys.argv) != 3:
        print("Usage: python vt_score_check.py input.csv output.csv")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]
    process_csv(input_file, output_file)
    print(f"Results written to {output_file}")


if __name__ == "__main__":
    main()
