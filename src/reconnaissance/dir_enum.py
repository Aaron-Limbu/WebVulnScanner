import logging
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
import random
import multiprocessing

class Logger:
    @staticmethod
    def setup_logger(log_filename="dir_enum_vuln_scan.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class VulnerabilityScan:
    @staticmethod
    def check_headers(url):
        """Check for insecure headers."""
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers

            if "Server" in headers:
                server = headers["Server"]
                print(f"[i] Server Header: {server}")
                logging.info(f"Server Header: {server}")

                if "Apache/2.4.49" in server or "Apache/2.4.50" in server:
                    print("[!] Vulnerable Apache version detected")
                    logging.warning(f"Vulnerable Apache version detected: {server}")

            if "X-Powered-By" in headers:
                x_powered_by = headers["X-Powered-By"]
                print(f"[i] X-Powered-By Header: {x_powered_by}")
                logging.info(f"X-Powered-By Header: {x_powered_by}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to fetch headers for {url}: {e}")
            logging.error(f"Failed to fetch headers for {url}: {e}")

    @staticmethod
    def scan_common_vulnerabilities(url):
        """Check for common vulnerabilities."""
        endpoints = ["/admin", "/.git", "/config", "/backup", "/.env", "/wp-config.php"]
        for endpoint in endpoints:
            vuln_url = f"{url}{endpoint}"
            try:
                response = requests.get(vuln_url, timeout=5)
                if response.status_code == 200:
                    print(f"[!] Potentially sensitive endpoint found: {vuln_url}")
                    logging.warning(f"Potentially sensitive endpoint found: {vuln_url}")
                elif response.status_code == 403:
                    print(f"[i] Restricted endpoint: {vuln_url}")
                    logging.info(f"Restricted endpoint: {vuln_url}")
            except requests.exceptions.RequestException as e:
                print(f"[-] Failed to check endpoint {vuln_url}: {e}")
                logging.error(f"Failed to check endpoint {vuln_url}: {e}")

class DirectoryEnum:
    def __init__(self, url, wordlists, user_agent, cookies, threads=10):
        self.url = url.rstrip('/')
        self.wordlists = wordlists
        self.found_dir = []
        self.threads = max(min(threads, 10), 1)  # Ensure thread count is between 1 and 10
        self.cookies = cookies
        self.headers = {
            "User-Agent": user_agent if user_agent else random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ]),
            "Referer": url.split('?')[0],
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": cookies or ""
        }

    def directory_req(self, directory):
        t_url = f"{self.url}/{directory}"
        try:
            req = requests.get(t_url, timeout=5, headers=self.headers)
            if req.status_code == 200:
                print(f"[+] Found directory: {t_url}")
                self.found_dir.append(t_url)
                logging.info(f"Found directory: {t_url}")
                VulnerabilityScan.scan_common_vulnerabilities(t_url)
            elif req.status_code in [403, 404]:
                print(f"[-] Target restricted or not found: {t_url}")
                logging.info(f"Target restricted or not found: {t_url}")
            else:
                print(f"[i] Unexpected status code {req.status_code} for: {t_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {t_url}: {str(e)}")
            print(f"[-] Request failed for {t_url}: {str(e)}")

    def enum(self):
        try:
            with open(self.wordlists, 'r') as file:
                directories = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {self.wordlists}")
            logging.error(f"Wordlist file not found: {self.wordlists}")
            return

        print(f"[i] Starting directory enumeration for {self.url} with {self.threads} threads")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.directory_req, directories)

        print("[+] Enumeration completed. Found directories:")
        for directory in self.found_dir:
            print(directory)
        logging.info("Enumeration completed. Found directories: " + ", ".join(self.found_dir))

class Application:
    def __init__(self, url, wordlists, threads, cookies, user_agent):
        max_threads = min(10, multiprocessing.cpu_count())  # Use up to 10 or CPU cores
        self.threads = max(min(int(threads), max_threads), 1)  # Ensure valid thread count
        self.de = DirectoryEnum(url, wordlists, user_agent, cookies, self.threads)

    def run(self):
        self.de.enum()
        VulnerabilityScan.check_headers(self.de.url)

class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="Directory enumeration with vulnerability scanning")
        parser.add_argument("-w", "--wordlist", type=str, required=True, help="Wordlist location")
        parser.add_argument("-u", "--url", type=str, required=True, help="Website URL")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
        parser.add_argument("-a", "--user-agent", type=str, default="", help="Custom User-Agent string")
        parser.add_argument("-c", "--cookie", type=str, default="", help="Cookies for authentication")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli = CLI()
        args = cli.argument_parse()
        app = Application(args.url, args.wordlist, args.threads, args.cookie, args.user_agent)
        app.run()
    except KeyboardInterrupt:
        print("[i] Process interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
