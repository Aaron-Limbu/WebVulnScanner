import requests
import logging
import argparse
import time
import json
import re

# Setup logging
class Logger:
    @staticmethod
    def setuplogger(): 
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("auth_scanner.log"), logging.StreamHandler()]
        )

class AuthTester:
    def __init__(self, url, username, password, wordlist=None):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.wordlist = wordlist if wordlist else ["password", "admin123", "test123", "password123"]
        self.session = requests.Session()
        self.headers = {"User-Agent": "AuthTester/1.0"}

    def test_authentication(self):
        """Tests authentication with provided credentials."""
        login_url = f"{self.url}/login"
        payload = {"username": self.username, "password": self.password}
        
        try:
            response = self.session.post(login_url, json=payload, headers=self.headers, timeout=5)
            status = response.status_code

            if status == 200:
                logging.info(f"[+] Authentication successful: {login_url}")
                self.test_session_management()
                self.check_response_for_sensitive_data(response.text)
            elif status in [401, 403]:
                logging.warning(f"[-] Authentication failed: {login_url}")
            else:
                logging.error(f"[!] Unexpected response: {status}")

        except requests.exceptions.Timeout:
            logging.error(f"[!] Timeout error: {login_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Request error: {e}")

    def test_session_management(self):
        """Checks session expiration and fixation vulnerabilities."""
        session_token = self.session.cookies.get_dict()
        logging.info(f"[*] Checking session token: {session_token}")

        # Simulate session expiration
        logging.info("[*] Testing session expiration...")
        time.sleep(10)  # Wait for session expiration time (modify if needed)
        response = self.session.get(f"{self.url}/dashboard", headers=self.headers)
        if response.status_code in [401, 403]:
            logging.info("[+] Session expiration is working correctly.")
        else:
            logging.warning("[!] Session may not be expiring properly.")

        # Session fixation test
        logging.info("[*] Testing session fixation...")
        old_token = self.session.cookies.get_dict()
        self.session.cookies.set("sessionid", "testsession1234")  # Setting a fake session
        new_token = self.session.cookies.get_dict()

        if old_token == new_token:
            logging.warning("[!] Session fixation vulnerability detected!")

    def brute_force_auth(self):
        """Attempts brute-force login with a weak password list."""
        logging.info("[*] Brute-forcing login credentials...")
        for password in self.wordlist:
            payload = {"username": self.username, "password": password}
            response = self.session.post(f"{self.url}/login", json=payload, headers=self.headers)

            if response.status_code == 200:
                logging.info(f"[!!!] Weak password found: {password}")
                print(f"[i] password: {password}")
                break
            elif response.status_code in [401, 403]:
                logging.info(f"[-] Failed attempt: {password}")
            else:
                logging.error(f"[!] Unexpected response: {response.status_code}")
        return

    def check_security_headers(self):
        """Checks for missing security headers in responses."""
        response = self.session.get(f"{self.url}/dashboard", headers=self.headers)
        headers = response.headers

        missing_headers = []
        if "Set-Cookie" not in headers:
            missing_headers.append("Set-Cookie")
        if "Secure" not in headers.get("Set-Cookie", ""):
            missing_headers.append("Secure")
        if "HttpOnly" not in headers.get("Set-Cookie", ""):
            missing_headers.append("HttpOnly")
        if "Content-Security-Policy" not in headers:
            missing_headers.append("Content-Security-Policy")

        if missing_headers:
            logging.warning(f"[!] Missing security headers: {', '.join(missing_headers)}")
        else:
            logging.info("[+] All security headers are set correctly.")

    def check_response_for_sensitive_data(self, response_text):
        """Scans API responses for exposed authentication data."""
        patterns = {
            "Session Token": r"(?i)(sessionid|auth_token|jwt)[:=\s]*['\"]?([A-Za-z0-9-_.]+)['\"]?",
            "API Key": r"(?i)(api_key|apikey|access_token|secret)[:=\s]*['\"]?([A-Za-z0-9-_.]+)['\"]?"
        }

        for label, pattern in patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                logging.critical(f"[!!!] Exposed {label}: {matches}")

    def run_tests(self, brute_force=False):
        """Runs all authentication security tests."""
        logging.info(f"[*] Testing API Authentication at: {self.url}")
        self.test_authentication()
        self.check_security_headers()

        if brute_force:
            self.brute_force_auth()

        logging.info("[+] Tests completed.")

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="API Authentication Security Tester")
        parser.add_argument("-u", "--url", required=True, help="Base URL of API (e.g., https://api.example.com)")
        parser.add_argument("-usr", "--username", required=True, help="Username for login")
        parser.add_argument("-pwd", "--password", help="Password for login")
        parser.add_argument("-w", "--wordlist", help="Password wordlist file (optional)")
        parser.add_argument("-b", "--brute-force", action="store_true", help="Enable brute-force testing")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setuplogger()
        args = CLI.parse_arguments()

        # Load custom wordlist if provided
        wordlist = []
        if args.wordlist:
            try:
                with open(args.wordlist, "r") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logging.error(f"[-] Wordlist file {args.wordlist} not found. Using default list.")

        tester = AuthTester(url=args.url, username=args.username, password=args.password, wordlist=wordlist)
        tester.run_tests(brute_force=args.brute_force)

    except KeyboardInterrupt:
        logging.warning("[-] Scan interrupted by user.")
    except Exception as e:
        logging.error(f"[-] Error: {e}")
