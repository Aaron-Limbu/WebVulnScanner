import requests
import argparse
import logging
import re
import json
import threading
from queue import Queue

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("api_scanner.log"),
                logging.StreamHandler()
            ]
        )

class APIScanner:
    def __init__(self, url, token=None, wordlist=None, proxies=None, threads=5):
        self.url = url.rstrip('/')
        self.token = token
        self.wordlist = wordlist if wordlist else ["admin", "user", "api", "config", "debug", "backup"]
        self.proxies = {"http": proxies, "https": proxies} if proxies else None
        self.threads = threads
        self.headers = {
            "User-Agent": "APIScanner/2.0",
            "Accept": "application/json"
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        
        self.queue = Queue()
        for endpoint in self.wordlist:
            self.queue.put(endpoint)

    def check_endpoint(self):
        """Tests an API endpoint for security flaws."""
        while not self.queue.empty():
            endpoint = self.queue.get()
            full_url = f"{self.url}/{endpoint}"
            
            try:
                response = requests.get(full_url, headers=self.headers, proxies=self.proxies, timeout=5)
                status = response.status_code

                if status == 200:
                    logging.info(f"[+] Found API endpoint: {full_url} (Status: {status})")
                    self.check_sensitive_data(response.text)
                elif status in [401, 403]:
                    logging.warning(f"[-] Endpoint requires authentication: {full_url}")
                elif status == 500:
                    logging.error(f"[!] Possible misconfiguration or exposed debug mode: {full_url}")

            except requests.exceptions.Timeout:
                logging.error(f"[!] Timeout error for {full_url}")
            except requests.exceptions.ConnectionError:
                logging.error(f"[!] Connection error for {full_url}")
            except requests.exceptions.RequestException as e:
                logging.error(f"[!] Request error: {e}")

            self.queue.task_done()

    def check_sensitive_data(self, response_text):
        """Scans API response for sensitive information."""
        patterns = {
            "API Key": r"(?i)(api_key|apikey|access_token|secret)[:=\s]*['\"]?([A-Za-z0-9-_.]+)['\"]?",
            "Password": r"(?i)(password|passwd)[:=\s]*['\"]?([A-Za-z0-9@#$%^&*]+)['\"]?",
            "AWS Key": r"(AKIA[0-9A-Z]{16})",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b"
        }

        for label, pattern in patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                logging.critical(f"[!] Exposed {label}: {matches}")

    def scan(self):
        """Runs the API security scan with threading."""
        logging.info(f"[*] Scanning API: {self.url} with {self.threads} threads")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.check_endpoint)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        
        logging.info("[+] Scan completed.")

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Improved API Security Scanner")
        parser.add_argument("-u", "--url", required=True, help="Base URL of API (e.g., https://api.example.com)")
        parser.add_argument("-t", "--token", help="Authorization token (if required)")
        parser.add_argument("-w", "--wordlist", help="Custom wordlist file for API endpoints")
        parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
        parser.add_argument("-th", "--threads", type=int, default=5, help="Number of threads (default: 5)")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()

        wordlist = []
        if args.wordlist:
            try:
                with open(args.wordlist, "r") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logging.error(f"[-] Wordlist file {args.wordlist} not found. Using default list.")

        scanner = APIScanner(url=args.url, token=args.token, wordlist=wordlist, proxies=args.proxy, threads=args.threads)
        scanner.scan()

    except KeyboardInterrupt:
        logging.warning("[-] Scan interrupted by user.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
