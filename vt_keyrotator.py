#!/usr/bin/env python3
"""
VT-KeyRotator: A lightweight Python utility for scanning IPs via VirusTotal API
with automatic API key rotation to bypass rate limits.
"""

import json
import csv
import time
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import requests


class VTKeyRotator:
    """VirusTotal API client with automatic key rotation."""
    
    VT_API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_keys: List[str], retry_attempts: int = 3, 
                 retry_delay: int = 2, request_timeout: int = 10):
        """
        Initialize the VT Key Rotator.
        
        Args:
            api_keys: List of VirusTotal API keys
            retry_attempts: Number of retry attempts for failed requests
            retry_delay: Delay in seconds between retries
            request_timeout: Request timeout in seconds
        """
        if not api_keys:
            raise ValueError("At least one API key must be provided")
        
        self.api_keys = api_keys
        self.current_key_index = 0
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.request_timeout = request_timeout
        
    def _get_current_key(self) -> str:
        """Get the current API key."""
        return self.api_keys[self.current_key_index]
    
    def _rotate_key(self) -> None:
        """Rotate to the next API key."""
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        print(f"[INFO] Rotated to API key {self.current_key_index + 1}/{len(self.api_keys)}")
    
    def _make_request(self, url: str, headers: Dict[str, str]) -> Optional[requests.Response]:
        """
        Make an API request with retry logic.
        
        Args:
            url: API endpoint URL
            headers: Request headers
            
        Returns:
            Response object or None if all retries failed
        """
        for attempt in range(self.retry_attempts):
            try:
                response = requests.get(url, headers=headers, timeout=self.request_timeout)
                
                # Handle rate limiting (HTTP 429)
                if response.status_code == 429:
                    print(f"[WARN] Rate limit hit for API key {self.current_key_index + 1}")
                    self._rotate_key()
                    time.sleep(self.retry_delay)
                    continue
                
                # Handle quota exceeded (HTTP 204 or specific error in response)
                if response.status_code == 204:
                    print(f"[WARN] Quota exceeded for API key {self.current_key_index + 1}")
                    self._rotate_key()
                    time.sleep(self.retry_delay)
                    continue
                
                # Success
                if response.status_code == 200:
                    return response
                
                # Other errors
                print(f"[WARN] Request failed with status {response.status_code}, attempt {attempt + 1}/{self.retry_attempts}")
                time.sleep(self.retry_delay)
                
            except requests.exceptions.Timeout:
                print(f"[WARN] Request timeout, attempt {attempt + 1}/{self.retry_attempts}")
                self._rotate_key()
                time.sleep(self.retry_delay)
                
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Request error: {e}, attempt {attempt + 1}/{self.retry_attempts}")
                time.sleep(self.retry_delay)
        
        return None
    
    def scan_ip(self, ip_address: str) -> Optional[Tuple[int, int]]:
        """
        Scan an IP address using VirusTotal API.
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            Tuple of (malicious_count, total_count) or None if scan failed
        """
        url = f"{self.VT_API_BASE}/ip_addresses/{ip_address}"
        
        for key_rotation in range(len(self.api_keys)):
            headers = {
                "x-apikey": self._get_current_key(),
                "accept": "application/json"
            }
            
            response = self._make_request(url, headers)
            
            if response:
                try:
                    data = response.json()
                    
                    # Extract malicious stats from the response
                    if "data" in data and "attributes" in data["data"]:
                        stats = data["data"]["attributes"].get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values())
                        
                        return (malicious, total)
                    
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"[ERROR] Failed to parse response for {ip_address}: {e}")
                    return None
                
                return None
            
            # If request failed, try with next key
            if key_rotation < len(self.api_keys) - 1:
                self._rotate_key()
        
        print(f"[ERROR] All API keys exhausted for {ip_address}")
        return None
    
    def scan_ips_from_file(self, input_file: str, output_file: str) -> None:
        """
        Scan IPs from a file and save results to CSV.
        
        Args:
            input_file: Path to file containing IP addresses (one per line)
            output_file: Path to output CSV file
        """
        # Read IPs from file
        try:
            with open(input_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[ERROR] Input file not found: {input_file}")
            return
        except Exception as e:
            print(f"[ERROR] Failed to read input file: {e}")
            return
        
        if not ips:
            print("[WARN] No IP addresses found in input file")
            return
        
        print(f"[INFO] Scanning {len(ips)} IP addresses...")
        
        # Prepare CSV file
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP Address', 'Malicious/Total', 'Status'])
            
            for idx, ip in enumerate(ips, 1):
                print(f"[INFO] Scanning {ip} ({idx}/{len(ips)})...")
                
                result = self.scan_ip(ip)
                
                if result:
                    malicious, total = result
                    score = f"{malicious}/{total}"
                    status = "Clean" if malicious == 0 else "Malicious"
                    writer.writerow([ip, score, status])
                    print(f"[RESULT] {ip}: {score} ({status})")
                else:
                    writer.writerow([ip, "N/A", "Failed"])
                    print(f"[RESULT] {ip}: Scan failed")
                
                # Small delay to avoid hitting rate limits too quickly
                if idx < len(ips):
                    time.sleep(0.5)
        
        print(f"[INFO] Results saved to {output_file}")
    
    def scan_single_ip(self, ip_address: str) -> None:
        """
        Scan a single IP and print the result.
        
        Args:
            ip_address: IP address to scan
        """
        print(f"[INFO] Scanning {ip_address}...")
        result = self.scan_ip(ip_address)
        
        if result:
            malicious, total = result
            score = f"{malicious}/{total}"
            status = "Clean" if malicious == 0 else "Malicious"
            print(f"[RESULT] {ip_address}: {score} ({status})")
        else:
            print(f"[RESULT] {ip_address}: Scan failed")


def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Configuration file not found: {config_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in configuration file: {e}")
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="VT-KeyRotator: Scan IPs via VirusTotal API with automatic key rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single IP
  python vt_keyrotator.py --ip 8.8.8.8 --config config.json
  
  # Scan multiple IPs from a file
  python vt_keyrotator.py --input ips.txt --output results.csv --config config.json
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    parser.add_argument(
        '--ip',
        help='Single IP address to scan'
    )
    
    parser.add_argument(
        '--input', '-i',
        help='Input file containing IP addresses (one per line)'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='results.csv',
        help='Output CSV file for results (default: results.csv)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Validate configuration
    if 'api_keys' not in config or not config['api_keys']:
        print("[ERROR] No API keys found in configuration file")
        sys.exit(1)
    
    # Initialize the scanner
    scanner = VTKeyRotator(
        api_keys=config['api_keys'],
        retry_attempts=config.get('retry_attempts', 3),
        retry_delay=config.get('retry_delay', 2),
        request_timeout=config.get('request_timeout', 10)
    )
    
    # Scan based on input type
    if args.ip:
        scanner.scan_single_ip(args.ip)
    elif args.input:
        scanner.scan_ips_from_file(args.input, args.output)
    else:
        parser.print_help()
        print("\n[ERROR] Either --ip or --input must be specified")
        sys.exit(1)


if __name__ == "__main__":
    main()
