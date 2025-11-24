import requests
import os
import argparse
from urllib.parse import urlparse

VERSION = "0.6"
AUTHOR = "botchx86"

def banner():
    print(f"VERSION = {VERSION}")
    print(f"AUTHOR = {AUTHOR}")

def validateDomain(domain):
    # Parse the URL to remove schemes like http:// or https://
    parsed_url = urlparse(domain)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # Ensure no trailing slashes
    domain = domain.rstrip('/')

    # Validate domain structure
    if not domain or '.' not in domain:
        raise ValueError("Invalid domain. Please provide a valid domain.")
    
    return domain

def isValidSubdomain(sub):
    # Ensures the subdomain entry is non-empty and properly formatted (allows hyphens in labels)
    if not sub:
        return False
    return all(
        part
        and not part.startswith("-")
        and not part.endswith("-")
        and part.replace("-", "").isalnum()
        for part in sub.split(".")
    )

def scanSubdomains(domain, wordlist, verbose=False, timeout=5, output_file=None):
    # Scans for subdomains by combining domain with entries in the wordlist.
    
    try:
        with open(wordlist, 'r') as file:
            subdomains = [line.strip() for line in file if isValidSubdomain(line.strip())]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file '{wordlist}' not found")
        return

    print(f"[*] Scanning domain: {domain}")
    print(f"[*] Using wordlist: {wordlist}")
    
    results = []

    for sub in subdomains:
        for scheme in ["https", "http"]:
        # Construct the subdomain URL
            subdomain = f"{scheme}://{sub}.{domain}"

            if verbose:
                print(f"[*] Trying {subdomain}")

            try:
                response = requests.get(subdomain, timeout=timeout)

                if response.status_code in [200, 301, 302, 403]:
                    print(f"[FOUND] Active subdomain: {subdomain} (status code: {response.status_code})")
                    results.append(f"{subdomain} (status code: {response.status_code})")

            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"[*] Subdomain {subdomain} is unreachable")

    if output_file:
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True) if os.path.dirname(output_file) else None
            with open(output_file, 'w') as file:
                file.write("\n".join(results))
                
        except IOError as e:
            print(f"[ERROR] Could not write to file {output_file}: {e}")

    print(f"[SUMMARY] {len(results)} active subdomain(s) found.")
    if output_file and results:
        print(f"[SUMMARY] Results written to {output_file}")

def Main():
    try:
        banner()
        PARSER = argparse.ArgumentParser(
            prog="subspy",
            description="Tool to scan for subdomains on a given domain",
            epilog="Example Usage:\n python subs.py -u https://example.com -w path/to/wordlist",
            formatter_class=argparse.RawTextHelpFormatter
        )
        PARSER.add_argument("-u", "--url", required=True, help="Specify the domain to scan for subdomains")
        PARSER.add_argument("-w", "--wordlist", required=True, help="Add a path to a wordlist file")
        PARSER.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable verbose output")
        PARSER.add_argument("-t", "--timeout", required=False, type=int, default=5, help="Set request timeout in seconds. (Default = 5)")
        PARSER.add_argument("-o", "--output", required=False, type=str, default=None, help="Prints output to a file")

        ARGS = PARSER.parse_args()

        try:
            ARGS.url = validateDomain(ARGS.url)
        except ValueError as e:
            PARSER.error(str(e))

        if not os.path.exists(ARGS.wordlist):
            PARSER.error(f"Wordlist file '{ARGS.wordlist}' not found")

        if ARGS.verbose:
            print(f"[*] Starting scan on {ARGS.url}")

        scanSubdomains(ARGS.url, ARGS.wordlist, verbose=ARGS.verbose, timeout=ARGS.timeout, output_file=ARGS.output)
        
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user. Exiting.")

if __name__ == "__main__":
    Main()
