import requests
import argparse
import logging
import random
from bs4 import BeautifulSoup


class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("CSRF_scanner.log"),
                logging.StreamHandler(),
            ],
        )


class CSRFTester:
    def __init__(self, url, cookies=None, agent=None):
        self.url = url
        self.session = requests.Session()
        self.cookies = {"Cookie": cookies} if cookies else {}

        self.headers = {
            "User-Agent": agent
            if agent
            else random.choice(
                [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
                    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36",
                ]
            ),
            "Referer": self.url,
            "Accept-Language": "en-US,en;q=0.9",
        }

    def fetch_csrf_token(self, response):
        soup = BeautifulSoup(response.text, "html.parser")
        token_fields = [
            "csrf_token",
            "token",
            "csrfmiddlewaretoken",
            "authenticity_token",
        ]  # Common CSRF token field names

        for field in token_fields:
            token_input = soup.find("input", {"name": field})
            if token_input:
                return token_input.get("value")

        meta_token = soup.find("meta", {"name": "csrf-token"})  # Check meta tags
        if meta_token:
            return meta_token.get("content")

        logging.warning("[!] No CSRF token found in the response.")
        return None

    def test_csrf_vulnerability(self):
        logging.info(f"[i] Testing CSRF vulnerability on: {self.url}")

        try:
            response = self.session.get(self.url, headers=self.headers, cookies=self.cookies)

            if response.status_code != 200:
                logging.error(f"[-] Failed to fetch page. Status code: {response.status_code}")
                return

            csrf_token = self.fetch_csrf_token(response)
            form_data = {"param": "test_value"} 

            if csrf_token:
                form_data["csrf_token"] = "INVALID_CSRF"

            logging.info(f"[i] Sending forged request with {'no' if not csrf_token else 'invalid'} CSRF token.")
            post_response = self.session.post(self.url, headers=self.headers, data=form_data, cookies=self.cookies)

            if post_response.status_code == 200 and "error" not in post_response.text.lower():
                logging.critical("[+] CSRF vulnerability detected! The request was accepted without a valid CSRF token.")
            else:
                logging.info("[-] CSRF protection is in place.")

        except requests.RequestException as e:
            logging.error(f"[-] Error while making requests: {e}")

    def test_csrf_token_reusability(self):
        logging.info("[i] Testing CSRF Token Reusability")

        try:
            response = self.session.get(self.url, headers=self.headers)
            csrf_token = self.fetch_csrf_token(response)

            if not csrf_token:
                logging.warning("[!] No CSRF token found.")
                return

            form_data = {"csrf_token": csrf_token, "param": "test_value"}
            post_response1 = self.session.post(self.url, headers=self.headers, data=form_data)
            post_response2 = self.session.post(self.url, headers=self.headers, data=form_data)

            if post_response1.status_code == 200 and post_response2.status_code == 200:
                logging.critical("[+] CSRF Token is Reusable! This is a vulnerability.")
            else:
                logging.info("[-] CSRF Token is unique per request.")

        except requests.RequestException as e:
            logging.error(f"[-] Error while making requests: {e}")

    def test_referer_validation(self):
        logging.info("[i] Testing Referer Header Validation")

        try:
            custom_headers = self.headers.copy()
            custom_headers["Referer"] = "https://malicious-site.com"

            response = self.session.post(self.url, headers=custom_headers, data={"param": "test_value"})

            if response.status_code == 200:
                logging.critical("[+] No Referer validation! Server accepted request from a different origin.")
            else:
                logging.info("[-] Referer header validation in place.")

        except requests.RequestException as e:
            logging.error(f"[-] Error while making requests: {e}")


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="CSRF Vulnerability Tester")
        parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
        parser.add_argument("-c", "--cookies", help="Session cookies (e.g., 'PHPSESSID=abcd1234')")
        parser.add_argument("-a", "--user-agent", type=str, help="User-Agent")
        return parser.parse_args()


if __name__ == "__main__":
    Logger.setup_logger()

    try:
        args = CLI.parse_arguments()
        detector = CSRFTester(args.url, args.cookies, args.user_agent)
        detector.test_csrf_vulnerability()
        detector.test_csrf_token_reusability()
        detector.test_referer_validation()

    except KeyboardInterrupt:
        logging.info("[-] User aborted execution.")
    except Exception as e:
        logging.error(f"[-] Unexpected error: {e}")
