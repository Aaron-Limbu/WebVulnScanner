import logging
import argparse
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import requests
from concurrent.futures import ThreadPoolExecutor

class Logger:
    @staticmethod
    def setup_logger(log_filename="dns_enum.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class DNSEnum:
    def __init__(self, domain, wordlist=None, threads=10):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.subdomains = []

    def resolve(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        try:
            answers = dns.resolver.resolve(full_domain, "A")
            ips = [answer.to_text() for answer in answers]
            print(f"[+] Resolved: {full_domain} -> {', '.join(ips)}")
            self.subdomains.append(full_domain)
            logging.info(f"Resolved: {full_domain} -> {', '.join(ips)}")
        except dns.resolver.NXDOMAIN:
            logging.info(f"NXDOMAIN: {full_domain}")
        except dns.resolver.NoAnswer:
            logging.info(f"No Answer: {full_domain}")
        except Exception as e:
            logging.error(f"Failed to resolve {full_domain}: {e}")

    def check_zone_transfer(self):
        try:
            ns_records = dns.resolver.resolve(self.domain, "NS")
            for ns in ns_records:
                ns_ip = ns.to_text()
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain))
                    if zone:
                        print(f"[!] Zone transfer successful on {ns_ip}.")
                        logging.warning(f"Zone transfer successful on {ns_ip}.")
                        for name, node in zone.nodes.items():
                            print(f"\t{name.to_text()}")
                            logging.info(f"Zone data: {name.to_text()}")
                except dns.exception.DNSException as e:
                    logging.info(f"Zone transfer failed on {ns_ip}: {e}")
        except Exception as e:
            logging.error(f"Failed to check zone transfer: {e}")

    def brute_force(self):
        if not self.wordlist:
            print("[-] Wordlist not provided for brute-forcing subdomains.")
            return

        try:
            with open(self.wordlist, "r") as file:
                subdomains = [line.strip() for line in file if line.strip()]
        except FileNotFoundError as e:
            print(f"[-] Wordlist file not found: {e}")
            logging.error(f"Wordlist file not found: {e}")
            return

        print(f"[i] Starting brute-force for subdomains of {self.domain} with {self.threads} threads")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.resolve, subdomains)

    def scan_vulnerabilities(self):
        print(f"[i] Scanning vulnerabilities for discovered subdomains...")
        for subdomain in self.subdomains:
            try:
                response = requests.get(f"http://{subdomain}", timeout=5)
                headers = response.headers
                if "Server" in headers:
                    print(f"[+] {subdomain} exposes server information: {headers['Server']}")
                    logging.warning(f"{subdomain} exposes server information: {headers['Server']}")
                if "X-Powered-By" in headers:
                    print(f"[+] {subdomain} exposes technology: {headers['X-Powered-By']}")
                    logging.warning(f"{subdomain} exposes technology: {headers['X-Powered-By']}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to scan {subdomain}: {e}")

    def run(self):
        self.check_zone_transfer()
        self.brute_force()
        self.scan_vulnerabilities()

class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="DNS Enumeration Tool")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Target domain")
        parser.add_argument("-w", "--wordlist", type=str, help="Wordlist for subdomain brute-forcing")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli = CLI()
        args = cli.argument_parse()

        dns_enum = DNSEnum(args.domain, args.wordlist, args.threads)
        dns_enum.run()
    except KeyboardInterrupt:
        print("[i] Exiting...")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        logging.error(f"An error occurred: {e}")
