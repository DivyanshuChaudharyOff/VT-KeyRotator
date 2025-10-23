# VT-KeyRotator

A lightweight Python utility that scans IPs via the VirusTotal API, automatically rotating multiple API keys to bypass rate limits or timeouts. It efficiently logs malicious detection scores ("malicious/total") to a CSV file, ensuring reliable results with smart retry logic and reduced delays for faster lookups.

## Features

- 🔄 **Automatic API Key Rotation**: Seamlessly rotates through multiple API keys to bypass rate limits
- 🎯 **IP Address Scanning**: Scan single or multiple IP addresses via VirusTotal API
- 📊 **CSV Export**: Logs malicious detection scores in an easy-to-read CSV format
- 🔁 **Smart Retry Logic**: Automatically retries failed requests with configurable delays
- ⚡ **Optimized Performance**: Reduced delays between requests for faster lookups
- 🛡️ **Robust Error Handling**: Handles timeouts, rate limits, and API errors gracefully

## Installation

1. Clone the repository:
```bash
git clone https://github.com/DivyanshuChaudharyOff/VT-KeyRotator.git
cd VT-KeyRotator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure your API keys:
```bash
cp config.json.example config.json
# Edit config.json and add your VirusTotal API keys
```

## Configuration

Create a `config.json` file with your VirusTotal API keys:

```json
{
    "api_keys": [
        "your_virustotal_api_key_1",
        "your_virustotal_api_key_2",
        "your_virustotal_api_key_3"
    ],
    "retry_attempts": 3,
    "retry_delay": 2,
    "request_timeout": 10
}
```

### Configuration Options

- `api_keys`: List of VirusTotal API keys (at least one required)
- `retry_attempts`: Number of retry attempts for failed requests (default: 3)
- `retry_delay`: Delay in seconds between retries (default: 2)
- `request_timeout`: Request timeout in seconds (default: 10)

## Usage

### Scan a Single IP Address

```bash
python vt_keyrotator.py --ip 8.8.8.8 --config config.json
```

### Scan Multiple IP Addresses from a File

Create a text file with IP addresses (one per line):

```bash
# Create ips.txt with IP addresses
echo "8.8.8.8" > ips.txt
echo "1.1.1.1" >> ips.txt
echo "208.67.222.222" >> ips.txt
```

Then run the scanner:

```bash
python vt_keyrotator.py --input ips.txt --output results.csv --config config.json
```

### Command-Line Options

```
usage: vt_keyrotator.py [-h] [--config CONFIG] [--ip IP] [--input INPUT] [--output OUTPUT]

VT-KeyRotator: Scan IPs via VirusTotal API with automatic key rotation

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to configuration file (default: config.json)
  --ip IP               Single IP address to scan
  --input INPUT, -i INPUT
                        Input file containing IP addresses (one per line)
  --output OUTPUT, -o OUTPUT
                        Output CSV file for results (default: results.csv)
```

## Output Format

Results are saved to a CSV file with the following columns:

| IP Address | Malicious/Total | Status |
|------------|----------------|---------|
| 8.8.8.8 | 0/90 | Clean |
| 1.1.1.1 | 0/88 | Clean |
| 203.0.113.1 | 15/90 | Malicious |

## How It Works

1. **Key Rotation**: The utility maintains a pool of API keys and automatically rotates to the next key when:
   - Rate limit is hit (HTTP 429)
   - Quota is exceeded (HTTP 204)
   - Request timeout occurs

2. **Smart Retry**: Failed requests are retried up to the configured number of attempts with exponential backoff

3. **Efficient Scanning**: Minimal delays between requests (0.5s) to maximize throughput while respecting API limits

## Getting VirusTotal API Keys

1. Sign up for a free account at [VirusTotal](https://www.virustotal.com/)
2. Navigate to your [API key page](https://www.virustotal.com/gui/my-apikey)
3. Copy your API key and add it to `config.json`
4. For better rate limits, consider getting multiple free accounts or upgrading to a premium plan

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for educational and legitimate security research purposes only. Always ensure you have permission to scan IP addresses and comply with VirusTotal's Terms of Service.
