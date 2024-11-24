import requests
import os
import argparse
from urllib.parse import urlparse

VERSION = 0.5
AUTHOR = f"botchx86"

def banner():
    print(f"VERSION = {VERSION}")
    print(f"AUTHOR = {AUTHOR}")


def validateDomain(domain):
    # Validates provided domain
    parsed = urlparse(domain)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid domain: {domain}")
    return domain.strip()


def isValidSubdomain(sub):
    # Ensures the subdomain entry is non-empty and properly formatted
    return sub and all(part.isalnum() for part in sub.split("."))


def scanSubdomains(domain, wordlist, verbose=False, timeout=5):
    """
    Scans for subdomains by combining domain with entries in the wordlist.
    """
    domain = validateDomain(domain)

    try:
        with open(wordlist, 'r') as file:
            subdomains = [line.strip() for line in file if isValidSubdomain(line.strip())]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file '{wordlist}' not found")
        return

    print(f"[*] Scanning domain: {domain}")
    print(f"[*] Using wordlist: {wordlist}")

    for sub in subdomains:
        # Construct the subdomain URL
        subdomain = domain.replace("://", f"://{sub}.")

        if verbose:
            print(f"[*] Trying {subdomain}")

        try:
            response = requests.get(subdomain, timeout=timeout)

            if response.status_code in [200, 301, 302, 403]:
                print(f"[FOUND] Active subdomain {subdomain} (status code: {response.status_code})")

        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"[*] Subdomain {subdomain} is unreachable ({e})")


def Main():
    banner()
    PARSER = argparse.ArgumentParser(
        prog="subspy",
        description="Tool to scan for subdomains on a given domain",
        epilog="Example Usage:\n python subs.py https://example.com -w path/to/wordlist",
        formatter_class=argparse.RawTextHelpFormatter
    )
    PARSER.add_argument("-u", "--url", required=True, help="Specify the domain to scan for subdomains")
    PARSER.add_argument("-w", "--wordlist", help="Add a path to a wordlist file")
    PARSER.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable verbose output")
    PARSER.add_argument("-t", "--timeout", required=False, type=int, default=5, help="Set request timeout in seconds. (Default = 5)")

    ARGS = PARSER.parse_args()

    try:
        ARGS.url = validateDomain(ARGS.url)

    except ValueError as e:
        PARSER.error(str(e))

    if not ARGS.wordlist or not os.path.exists(ARGS.wordlist):
        PARSER.error("Wordlist file '{ARGS.wordlist}' not found")

    if ARGS.verbose:
        print(f"Scanning {ARGS.url}")

    scanSubdomains(ARGS.url, ARGS.wordlist, verbose=ARGS.verbose, timeout=ARGS.timeout)


if __name__ == "__main__":
    Main()
