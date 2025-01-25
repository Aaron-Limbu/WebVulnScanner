import argparse
import requests
import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from dns import resolver, exception

class Logger:
    @staticmethod
    def setup_logger(log_filename="domain_enum.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class DomainEnum:
    def __init__(self, domain, wordlist=None, threads=10):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.resolved_domains = []

    def dns_query(self, subdomain):
        try:
            fqdn = f"{subdomain}.{self.domain}"
            ip = socket.gethostbyname(fqdn)
            print(f"[+] Resolved: {fqdn} -> {ip}")
            self.resolved_domains.append(f"{fqdn} -> {ip}")
            logging.info(f"Resolved: {fqdn} -> {ip}")
        except socket.gaierror:
            pass  # Ignore unresolved subdomains

    def subdomain_bruteforce(self):
        if not self.wordlist:
            print("[-] No wordlist provided for subdomain brute-forcing.")
            return

        try:
            with open(self.wordlist, 'r') as file:
                subdomains = [line.strip() for line in file if line.strip()]
        except FileNotFoundError as fnf_error:
            print(f"[-] Wordlist not found: {fnf_error}")
            logging.error(f"Wordlist not found: {fnf_error}")
            return

        print(f"[i] Starting subdomain enumeration with {self.threads} threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.dns_query, subdomains)

        print("[+] Subdomain enumeration completed.")
        logging.info("Subdomain enumeration completed.")

    def headers_vulnerability_scan(self):
        print("[i] Checking headers for potential vulnerabilities...")
        for entry in self.resolved_domains:
            fqdn = entry.split(" -> ")[0]
            try:
                response = requests.get(f"http://{fqdn}", timeout=5)
                print(f"[i] Headers for {fqdn}:")
                for key, value in response.headers.items():
                    print(f"    {key}: {value}")
                # Check for potential issues in headers
                if "X-Powered-By" in response.headers:
                    print(f"[!] {fqdn} reveals server technology: {response.headers['X-Powered-By']}")
                if "Server" in response.headers:
                    print(f"[!] {fqdn} reveals server type: {response.headers['Server']}")
            except requests.RequestException as e:
                print(f"[-] Could not fetch headers for {fqdn}: {e}")
                logging.error(f"Could not fetch headers for {fqdn}: {e}")

    def run(self):
        print(f"[i] Starting enumeration for domain: {self.domain}")
        self.subdomain_bruteforce()
        if self.resolved_domains:
            self.headers_vulnerability_scan()

class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="Domain and Subdomain Enumeration Tool")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Target domain for enumeration")
        parser.add_argument("-w", "--wordlist", type=str, help="Wordlist for subdomain brute-forcing")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli_args = CLI.argument_parse()
        domain_enum = DomainEnum(cli_args.domain, cli_args.wordlist, cli_args.threads)
        domain_enum.run()
    except KeyboardInterrupt:
        print("\n[i] Process interrupted by user.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        logging.error(f"An error occurred: {e}")
