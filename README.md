# subspy - Advanced Subdomain Scanner

```
   _____ __  __ ____  _____   ____  __     __
  / ___// / / // __ )/ ___/  / __ \\ \   / /
  \__ \/ / / // __  |\__ \  / /_/ / \ \_/ /
 ___/ / /_/ // /_/ /___/ / / ____/   \   /
/____/\____//_____//____(_)/_/        |_|

```

subspy is a high-performance Python tool designed to discover active subdomains for a given domain using wordlist-based enumeration.

**Current Version: 1.0**

## Features

### Core Scanning
- **DNS Resolution First:** Checks DNS before HTTP requests for 5-10x speed improvement
- **Concurrent Threading:** Multi-threaded scanning with configurable thread count (default: 10 threads)
- **Progress Bar:** Real-time progress indicator with tqdm
- **Wildcard Detection:** Automatically detects wildcard DNS to identify false positives
- **Smart Protocol Detection:** Tries HTTPS first, skips HTTP if HTTPS succeeds

### Advanced Capabilities
- **Resume Support:** Save progress and resume interrupted scans
- **Multiple Output Formats:** Export results as TXT, JSON, or CSV
- **Configurable Status Codes:** Specify which HTTP status codes to consider as "found"
- **DNS-Only Mode:** Fast DNS enumeration without HTTP requests
- **Rate Limiting:** Configurable delay between requests
- **Enhanced Error Handling:** Specific handling for timeouts, connection errors, and DNS failures

### User Experience
- **Verbose Mode:** Detailed output for debugging and monitoring
- **Quiet Mode:** Minimal output showing only discovered subdomains
- **Color-Coded Output:** Easy-to-read colored terminal output with --no-color option
- **Statistics Summary:** Detailed scan statistics including speed and success rate
- **User-Agent Header:** Browser User-Agent for better compatibility
- **Timeout Control:** Configurable request timeout
- **Duplicate Prevention:** Automatically prevents duplicate results

## Options

### Required Arguments
```
  -u URL, --url URL           Specify the domain to scan for subdomains
  -w WORDLIST, --wordlist     Path to wordlist file
```

### Optional Arguments
```
  -h, --help                  Show this help message and exit
  -v, --verbose               Enable verbose output
  -q, --quiet                 Quiet mode - only output found subdomains
  -t TIMEOUT, --timeout       Request timeout in seconds (Default: 5)
  -o OUTPUT, --output         Output file path
  -d DELAY, --delay           Delay between requests in seconds (Default: 0)
  --threads THREADS           Number of concurrent threads (Default: 10)
  --status-codes CODES        Comma-separated status codes to consider found
                              (Default: 200,301,302,403)
  --dns-only                  Only perform DNS resolution, skip HTTP requests
  --resume                    Resume a previously interrupted scan
  --format {txt,json,csv}     Output format (Default: txt)
  --no-color                  Disable colored output
```

## Requirements

- Python 3.7 or later
- `requests` - HTTP library for making requests
- `dnspython` - DNS resolution toolkit
- `tqdm` - Progress bar library
- `colorama` - Cross-platform colored terminal output

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/botchx86/subspy.git
   cd subspy
   ```

2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

```bash
# Basic scan
python subs.py -u example.com -w wordlist.txt

# Fast concurrent scan with 20 threads
python subs.py -u example.com -w wordlist.txt --threads 20

# DNS-only enumeration (fastest)
python subs.py -u example.com -w wordlist.txt --dns-only --threads 50
```

## Usage

### Basic Scan
```bash
python subs.py -u example.com -w wordlist.txt
```

### Fast DNS-Only Scan
```bash
python subs.py -u example.com -w wordlist.txt --dns-only
```

### High-Speed Concurrent Scan
```bash
python subs.py -u example.com -w wordlist.txt --threads 50
```

### Save Results in JSON Format
```bash
python subs.py -u example.com -w wordlist.txt -o results.json --format json
```

### Custom Status Codes
```bash
python subs.py -u example.com -w wordlist.txt --status-codes 200,201,301,302,401,403
```

### Resume Interrupted Scan
```bash
python subs.py -u example.com -w wordlist.txt --resume
```

### Verbose Output with Progress
```bash
python subs.py -u example.com -w wordlist.txt -v
```

### Quiet Mode for Piping
```bash
python subs.py -u example.com -w wordlist.txt --quiet -o results.txt
```

### Disable Colored Output
```bash
python subs.py -u example.com -w wordlist.txt --no-color
```

## Performance Tips

- **Use DNS-only mode** (`--dns-only`) for initial reconnaissance - 10x faster
- **Increase threads** (`--threads 50`) for faster scanning on good network connections
- **Reduce delay** (`--delay 0`) when scanning your own infrastructure
- **Use resume** (`--resume`) for large wordlists that may take hours
- **Start with small wordlists** to test configuration before using large lists

## Output Formats

### Text (Default)
```
https://api.example.com (status code: 200)
https://www.example.com (status code: 200)
```

### JSON
```json
[
  {
    "subdomain": "api.example.com",
    "scheme": "https",
    "status_code": 200,
    "ip_addresses": ["93.184.216.34"],
    "url": "https://api.example.com"
  }
]
```

### CSV
```csv
subdomain,scheme,status_code,ip_addresses,url
api.example.com,https,200,"['93.184.216.34']",https://api.example.com
```

## Advanced Features

### Wildcard Detection
The tool automatically detects wildcard DNS configurations that resolve all subdomains:
```
[WARNING] Wildcard DNS detected on example.com. Results may include false positives.
```

### Resume Capability
Progress is automatically saved every 50 scanned subdomains when using `--resume`:
```
[*] Resuming scan - 450 subdomains already checked
```

### Thread-Safe Operation
All scanning operations are thread-safe, allowing high concurrency without data corruption.

## Troubleshooting

**Issue:** Slow scanning speed
**Solution:** Increase threads (`--threads 50`) or use DNS-only mode

**Issue:** Getting blocked by target
**Solution:** Reduce threads, increase delay (`--delay 1`)

**Issue:** Too many false positives
**Solution:** Check for wildcard DNS warning, adjust status codes

**Issue:** Scan interrupted
**Solution:** Use `--resume` flag to continue from where you left off

**Issue:** Import errors after installation
**Solution:** Ensure you're using Python 3.7+ and reinstall: `pip install -r requirements.txt --force-reinstall`

**Issue:** DNS resolution failures
**Solution:** Check your network/DNS settings, try a different DNS server

## Best Practices

### For Reconnaissance
1. Start with DNS-only mode to quickly identify existing subdomains
2. Use large wordlists (10k-100k entries) with high thread count
3. Export results to JSON for further processing

### For Web Application Testing
1. Use full HTTP scanning with custom status codes
2. Moderate thread count (10-20) to avoid rate limiting
3. Enable verbose mode to debug specific subdomains
4. Use resume for very large wordlists

### For Production Environments
1. Use minimal delay (`--delay 0.1`) for respectful scanning
2. Export to CSV for reporting
3. Enable resume for long-running scans
4. Monitor wildcard warnings

## Comparison with Other Tools

| Feature | subspy | subfinder | amass | sublist3r |
|---------|--------|-----------|-------|-----------|
| DNS Resolution First | ✅ | ✅ | ✅ | ❌ |
| Concurrent Threading | ✅ | ✅ | ✅ | ❌ |
| Progress Bar | ✅ | ❌ | ❌ | ❌ |
| Wildcard Detection | ✅ | ✅ | ✅ | ❌ |
| Resume Capability | ✅ | ❌ | ❌ | ❌ |
| Multiple Output Formats | ✅ | ✅ | ✅ | ❌ |
| Custom Status Codes | ✅ | ❌ | ❌ | ❌ |
| DNS-Only Mode | ✅ | ✅ | ❌ | ❌ |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. Always obtain proper authorization before scanning systems you do not own or have explicit permission to test.

## Author

**botchx86**

For questions, issues, or feature requests, please open an issue on GitHub.

