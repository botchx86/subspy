# subspy - Subdomain Scanner

subspy is a Python-based tool designed to scan and discover active subdomains for a given domain using a wordlist.

## Features

- **Subdomain Discovery:** Scans for subdomains based on a wordlist.
- **Verbose Mode:** Displays detailed output of every subdomain attempted, along with response status.
- **Error Handling:** Skips invalid or unreachable subdomains gracefully.
- **Timeout Control:** Configurable timeout for requests to improve efficiency.

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
