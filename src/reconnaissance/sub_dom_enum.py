import argparse
import requests
import socket
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from googlesearch import search

class Logger:
    @staticmethod
    def setup_logger(log_filename="domain_enum.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class DomainEnum:
    def __init__(self, domain, threads=10):
        self.domain = domain
        self.threads = threads
        self.resolved_domains = set()
        self.found_subdomains = set()

    def google_enum(self):
        """Uses Google Dorking to find subdomains."""
        print(f"[i] Searching Google for subdomains of {self.domain}...")
        query = f"site:{self.domain} -www"
        try:
            for result in search(query, num_results=20):
                match = re.search(r"https?://([\w.-]+)\."+re.escape(self.domain), result)
                if match:
                    subdomain = match.group(1) + "." + self.domain
                    self.found_subdomains.add(subdomain)
        except Exception as e:
            print(f"[-] Google search failed: {e}")
            logging.error(f"Google search failed: {e}")

    def dns_query(self, subdomain):
        """Resolve the IP address of a subdomain."""
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"[+] Resolved: {subdomain} -> {ip}")
            self.resolved_domains.add(f"{subdomain} -> {ip}")
            logging.info(f"Resolved: {subdomain} -> {ip}")
        except socket.gaierror:
            pass  # Ignore unresolved subdomains

    def resolve_subdomains(self):
        """Resolve found subdomains using DNS, avoiding duplicates."""
        unresolved = self.found_subdomains - {entry.split(" -> ")[0] for entry in self.resolved_domains}
        print(f"[i] Resolving {len(unresolved)} potential subdomains...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.dns_query, unresolved)

    def headers_vulnerability_scan(self):
        """Check HTTP headers for security weaknesses."""
        print("[i] Checking headers for potential vulnerabilities...")
        for entry in self.resolved_domains:
            fqdn = entry.split(" -> ")[0]
            for scheme in ["http", "https"]:
                try:
                    response = requests.get(f"{scheme}://{fqdn}", timeout=5)
                    print(f"[i] Headers for {fqdn} ({scheme}):")
                    for key, value in response.headers.items():
                        print(f"    {key}: {value}")
                    # Security checks
                    if "X-Powered-By" in response.headers:
                        print(f"[!] {fqdn} reveals server technology: {response.headers['X-Powered-By']}")
                    if "Server" in response.headers:
                        print(f"[!] {fqdn} reveals server type: {response.headers['Server']}")
                    break  # If HTTPS works, no need to check HTTP
                except requests.RequestException:
                    continue

    def run(self):
        """Run the enumeration process."""
        print(f"[i] Starting enumeration for domain: {self.domain}")
        self.google_enum()
        if self.found_subdomains:
            self.resolve_subdomains()
        if self.resolved_domains:
            self.headers_vulnerability_scan()

class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="Domain and Subdomain Enumeration Tool")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Target domain for enumeration")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli_args = CLI.argument_parse()
        domain_enum = DomainEnum(cli_args.domain, cli_args.threads)
        domain_enum.run()
    except KeyboardInterrupt:
        print("\n[i] Process interrupted by user.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        logging.error(f"An error occurred: {e}")
