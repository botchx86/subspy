# subspy - Subdomain Scanner

subspy is a Python-based tool designed to scan and discover active subdomains for a given domain using a wordlist.

## Features

- **Subdomain Discovery:** Scans for subdomains based on a wordlist.
- **Verbose Mode:** Displays detailed output of every subdomain attempted, along with response status.
- **Error Handling:** Skips invalid or unreachable subdomains gracefully.
- **Timeout Control:** Configurable timeout for requests to improve efficiency.
- **File Output:** Output results of the scan to a file.

```
options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Specify the domain to scan for subdomains
  -w WORDLIST, --wordlist WORDLIST
                        Add a path to a wordlist file
  -v, --verbose         Enable verbose output
  -t TIMEOUT, --timeout TIMEOUT
                        Set request timeout in seconds. (Default = 5)
  -o OUTPUT, --output OUTPUT
                        Prints output to a file
```

## Requirements

- Python 3.7 or later
- `requests` library

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/botchx86/subspy.git
   cd subspy
2. Install requirements

   ```bash
   pip install -r requirements.txt
## Usage

```
python subs.py -u https://example.com -w path/to/wordlist.txt
```
