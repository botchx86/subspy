import requests
import os
import argparse
import time
import json
import csv
import random
import dns.resolver
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

VERSION = "1.0"
AUTHOR = "botchx86"

# Thread-safe containers
results_lock = Lock()
found_subdomains_lock = Lock()

# Global flags for output control
QUIET_MODE = False
NO_COLOR = False

def print_colored(message, color=None, quiet=False):
    """Print colored message unless in quiet mode"""
    if QUIET_MODE and not quiet:
        return

    if NO_COLOR or color is None:
        print(message)
    else:
        print(f"{color}{message}{Style.RESET_ALL}")

def banner():
    print("""
   _____ __  __ ____  _____   ____  __     __
  / ___// / / // __ )/ ___/  / __ \\\\ \\   / /
  \\__ \\/ / / // __  |\\__ \\  / /_/ / \\ \\_/ /
 ___/ / /_/ // /_/ /___/ / / ____/   \\   /
/____/\\____//_____//____(_)/_/        |_|
    """)
    print(f"VERSION = {VERSION}")
    print(f"AUTHOR = {AUTHOR}")
    print()

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

def checkDNS(subdomain, domain):
    """Check if subdomain resolves via DNS"""
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        return True, [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False, []
    except Exception:
        return False, []

def detectWildcard(domain, timeout=5):
    """Detect if domain has wildcard DNS configured"""
    # Generate random subdomain that shouldn't exist
    random_sub = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20))
    resolves, ips = checkDNS(random_sub, domain)

    if resolves:
        print_colored(f"[WARNING] Wildcard DNS detected on {domain}. Results may include false positives.", Fore.YELLOW)
        return True, ips
    return False, []

def scanSingleSubdomain(sub, domain, verbose, timeout, headers, status_codes, dns_only):
    """Scan a single subdomain - designed for threading"""
    subdomain_found = False
    result_data = None

    # DNS resolution check first
    dns_resolves, ip_addresses = checkDNS(sub, domain)

    if not dns_resolves:
        if verbose:
            print_colored(f"[*] {sub}.{domain} - DNS resolution failed", Fore.RED)
        return None

    if dns_only:
        # Only return DNS results
        result_data = {
            'subdomain': f"{sub}.{domain}",
            'scheme': 'N/A',
            'status_code': 'N/A',
            'ip_addresses': ip_addresses,
            'dns_only': True
        }
        print_colored(f"[FOUND] {sub}.{domain} resolves to {', '.join(ip_addresses)}", Fore.GREEN, quiet=True)
        return result_data

    # Try HTTP/HTTPS if DNS resolves
    for scheme in ["https", "http"]:
        # Skip HTTP if HTTPS already succeeded
        if subdomain_found:
            break

        # Construct the subdomain URL
        subdomain = f"{scheme}://{sub}.{domain}"

        if verbose:
            print_colored(f"[*] Trying {subdomain}")

        try:
            response = requests.get(subdomain, timeout=timeout, headers=headers, allow_redirects=True)

            if response.status_code in status_codes:
                result_data = {
                    'subdomain': f"{sub}.{domain}",
                    'scheme': scheme,
                    'status_code': response.status_code,
                    'ip_addresses': ip_addresses,
                    'url': subdomain,
                    'dns_only': False
                }
                print_colored(f"[FOUND] Active subdomain: {subdomain} (status code: {response.status_code})", Fore.GREEN, quiet=True)
                subdomain_found = True

        except requests.exceptions.Timeout:
            if verbose:
                print_colored(f"[*] Subdomain {subdomain} timed out", Fore.YELLOW)
        except requests.exceptions.ConnectionError:
            if verbose:
                print_colored(f"[*] Subdomain {subdomain} connection failed", Fore.RED)
        except requests.exceptions.RequestException:
            if verbose:
                print_colored(f"[*] Subdomain {subdomain} is unreachable", Fore.RED)

    return result_data

def saveProgress(progress_file, scanned_subdomains):
    """Save progress to resume later"""
    try:
        with open(progress_file, 'w') as f:
            json.dump(list(scanned_subdomains), f)
    except IOError:
        pass

def loadProgress(progress_file):
    """Load previously scanned subdomains"""
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r') as f:
                return set(json.load(f))
        except (IOError, json.JSONDecodeError):
            return set()
    return set()

def saveResults(results, output_file, output_format='txt'):
    """Save results in specified format"""
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        if output_format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

        elif output_format == 'csv':
            with open(output_file, 'w', newline='') as f:
                if results:
                    fieldnames = results[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)

        else:  # txt format
            with open(output_file, 'w') as f:
                for result in results:
                    if result.get('dns_only'):
                        f.write(f"{result['subdomain']} - IPs: {', '.join(result['ip_addresses'])}\n")
                    else:
                        f.write(f"{result['url']} (status code: {result['status_code']})\n")

        return True
    except IOError as e:
        print_colored(f"[ERROR] Could not write to file {output_file}: {e}", Fore.RED, quiet=True)
        return False

def scanSubdomains(domain, wordlist, verbose=False, timeout=5, output_file=None, delay=0.5,
                   threads=10, status_codes=None, dns_only=False, resume=False, output_format='txt'):
    """Scans for subdomains by combining domain with entries in the wordlist."""

    if status_codes is None:
        status_codes = [200, 301, 302, 403]

    # Start timing
    start_time = time.time()

    # Load wordlist
    try:
        with open(wordlist, 'r') as file:
            subdomains = [line.strip() for line in file if isValidSubdomain(line.strip())]
    except FileNotFoundError:
        print_colored(f"[ERROR] Wordlist file '{wordlist}' not found", Fore.RED, quiet=True)
        return

    print_colored(f"[*] Scanning domain: {domain}")
    print_colored(f"[*] Using wordlist: {wordlist}")
    print_colored(f"[*] Total subdomains to check: {len(subdomains)}")
    print_colored(f"[*] Threads: {threads}")

    # Wildcard detection
    has_wildcard, wildcard_ips = detectWildcard(domain, timeout)

    results = []
    found_subdomains = set()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    # Resume support
    progress_file = f".subspy_progress_{domain.replace('.', '_')}.json"
    scanned_subdomains = set()

    if resume:
        scanned_subdomains = loadProgress(progress_file)
        if scanned_subdomains:
            print_colored(f"[*] Resuming scan - {len(scanned_subdomains)} subdomains already checked")
            subdomains = [s for s in subdomains if s not in scanned_subdomains]

    # Concurrent scanning with progress bar
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_sub = {
                executor.submit(scanSingleSubdomain, sub, domain, verbose, timeout,
                              headers, status_codes, dns_only): sub
                for sub in subdomains
            }

            # Process results with progress bar
            with tqdm(total=len(subdomains), desc="Scanning", unit="subdomain", disable=QUIET_MODE) as pbar:
                for future in as_completed(future_to_sub):
                    sub = future_to_sub[future]

                    try:
                        result = future.result()

                        if result:
                            with results_lock:
                                results.append(result)
                            with found_subdomains_lock:
                                found_subdomains.add(sub)

                        scanned_subdomains.add(sub)

                        # Rate limiting
                        if delay > 0:
                            time.sleep(delay)

                    except Exception as e:
                        if verbose:
                            print_colored(f"[ERROR] Exception scanning {sub}: {e}", Fore.RED)

                    finally:
                        pbar.update(1)

                        # Save progress periodically (every 50 subdomains)
                        if resume and len(scanned_subdomains) % 50 == 0:
                            saveProgress(progress_file, scanned_subdomains)

    except KeyboardInterrupt:
        print_colored("\n[INFO] Scan interrupted by user.", Fore.YELLOW, quiet=True)
        if resume:
            saveProgress(progress_file, scanned_subdomains)
            print_colored("[INFO] Progress saved. Use --resume to continue later.", quiet=True)
        raise

    # Clean up progress file on successful completion
    if resume and os.path.exists(progress_file):
        try:
            os.remove(progress_file)
        except OSError:
            pass

    # Calculate statistics
    end_time = time.time()
    elapsed_time = end_time - start_time
    total_checked = len(scanned_subdomains)

    # Save results
    if output_file and results:
        if saveResults(results, output_file, output_format):
            print_colored(f"[SUMMARY] Results written to {output_file} ({output_format} format)")

    # Print statistics summary
    print_colored(f"\n{'='*60}")
    print_colored(f"[SUMMARY] Scan Statistics", Fore.CYAN)
    print_colored(f"{'='*60}")
    print_colored(f"[+] Total Subdomains Checked: {total_checked}")
    print_colored(f"[+] Active Subdomains Found: {len(results)}", Fore.GREEN)
    print_colored(f"[+] Scan Duration: {elapsed_time:.2f} seconds")
    print_colored(f"[+] Scan Speed: {total_checked / elapsed_time:.2f} subdomains/sec")
    if total_checked > 0:
        success_rate = (len(results) / total_checked) * 100
        print_colored(f"[+] Success Rate: {success_rate:.2f}%")
    print_colored(f"{'='*60}\n")

    return results

def Main():
    global QUIET_MODE, NO_COLOR

    try:
        PARSER = argparse.ArgumentParser(
            prog="subspy",
            description="Tool to scan for subdomains on a given domain",
            epilog="Example Usage:\n python subs.py -u https://example.com -w path/to/wordlist",
            formatter_class=argparse.RawTextHelpFormatter
        )
        PARSER.add_argument("-u", "--url", required=True, help="Specify the domain to scan for subdomains")
        PARSER.add_argument("-w", "--wordlist", required=True, help="Add a path to a wordlist file")
        PARSER.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable verbose output")
        PARSER.add_argument("-q", "--quiet", action="store_true", default=False, help="Quiet mode - only output found subdomains")
        PARSER.add_argument("-t", "--timeout", required=False, type=int, default=5, help="Set request timeout in seconds. (Default = 5)")
        PARSER.add_argument("-o", "--output", required=False, type=str, default=None, help="Prints output to a file")
        PARSER.add_argument("-d", "--delay", required=False, type=float, default=0, help="Set delay between requests in seconds. (Default = 0)")
        PARSER.add_argument("--threads", required=False, type=int, default=10, help="Number of concurrent threads. (Default = 10)")
        PARSER.add_argument("--status-codes", required=False, type=str, default="200,301,302,403",
                          help="Comma-separated list of status codes to consider as found. (Default = 200,301,302,403)")
        PARSER.add_argument("--dns-only", action="store_true", default=False,
                          help="Only perform DNS resolution, skip HTTP requests")
        PARSER.add_argument("--resume", action="store_true", default=False,
                          help="Resume a previously interrupted scan")
        PARSER.add_argument("--format", required=False, type=str, default="txt",
                          choices=['txt', 'json', 'csv'], help="Output format: txt, json, or csv. (Default = txt)")
        PARSER.add_argument("--no-color", action="store_true", default=False,
                          help="Disable colored output")

        ARGS = PARSER.parse_args()

        # Set global flags
        QUIET_MODE = ARGS.quiet
        NO_COLOR = ARGS.no_color

        # Show banner unless in quiet mode
        if not QUIET_MODE:
            banner()

        try:
            ARGS.url = validateDomain(ARGS.url)
        except ValueError as e:
            PARSER.error(str(e))

        if not os.path.exists(ARGS.wordlist):
            PARSER.error(f"Wordlist file '{ARGS.wordlist}' not found")

        # Parse status codes
        try:
            status_codes = [int(code.strip()) for code in ARGS.status_codes.split(',')]
        except ValueError:
            PARSER.error("Invalid status codes format. Use comma-separated integers (e.g., 200,301,302)")

        if ARGS.verbose:
            print_colored(f"[*] Starting scan on {ARGS.url}")

        scanSubdomains(
            ARGS.url,
            ARGS.wordlist,
            verbose=ARGS.verbose,
            timeout=ARGS.timeout,
            output_file=ARGS.output,
            delay=ARGS.delay,
            threads=ARGS.threads,
            status_codes=status_codes,
            dns_only=ARGS.dns_only,
            resume=ARGS.resume,
            output_format=ARGS.format
        )

    except KeyboardInterrupt:
        print_colored("\n[INFO] Scan interrupted by user. Exiting.", Fore.YELLOW, quiet=True)

if __name__ == "__main__":
    Main()
