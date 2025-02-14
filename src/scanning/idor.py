import requests
import logging
import argparse

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("idor.log"), logging.StreamHandler()]
        )

class IDORtest:
    def __init__(self, url, param, start_id, end_id, method="GET", headers=None, cookies=None, verbose=False):
        self.url = url
        self.param = param
        self.start_id = start_id
        self.end_id = end_id
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verbose = verbose
        self.session = requests.Session()  # Reuse session for efficiency

    def test_idor(self):
        logging.info(f"[i] Starting IDOR test on {self.url} (Method: {self.method})")
        
        # Get the baseline response to compare against
        baseline_response = self.send_request(self.start_id)
        if not baseline_response:
            logging.error("[!] Could not get a baseline response. Aborting test.")
            return
        
        baseline_length = len(baseline_response.text)

        for object_id in range(self.start_id, self.end_id + 1):
            test_response = self.send_request(object_id)
            if not test_response:
                continue  # Skip this iteration if the request failed

            response_length = len(test_response.text)

            if test_response.status_code == 200 and response_length != baseline_length:
                logging.info(f"[+] Potential IDOR Found! Accessible Object ID: {object_id}")
                logging.info(f"[+] Response Length: {response_length} (Baseline: {baseline_length})")
            elif self.verbose:
                logging.warning(f"[-] No access for ID: {object_id} (Response Code: {test_response.status_code})")

    def send_request(self, object_id):
        """Sends a GET or POST request and returns the response."""
        try:
            test_url = self.url.replace(f"{self.param}=", f"{self.param}={object_id}")#customize params 
            
            if self.method == "GET":
                response = self.session.get(test_url, headers=self.headers, cookies=self.cookies, timeout=5)
            else:
                response = self.session.post(self.url, data={self.param: object_id}, headers=self.headers, cookies=self.cookies, timeout=5)

            return response
        
        except requests.RequestException as e:
            logging.error(f"[!] Request failed for ID {object_id}: {e}")
            return None

class CLI:
    """Handles command-line argument parsing."""
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Insecure Direct Object (IDOR) Tester")
        parser.add_argument("-u", "--url", type=str, required=True, help="e.g., http://example.com/profile?id=")
        parser.add_argument("-p", "--param", type=str, required=True, help="Parameter to test (e.g., 'id')")
        parser.add_argument("-s", "--start", type=int, required=True, help="Starting object ID")
        parser.add_argument("-e", "--end", type=int, required=True, help="Ending object ID")
        parser.add_argument("-m", "--method", type=str, choices=["GET", "POST"], default="GET", help="HTTP method to use (default: GET)")
        parser.add_argument("--header", type=str, help="Custom headers (e.g., 'Authorization: Bearer token')")
        parser.add_argument("--cookie", type=str, help="Session cookies (e.g., 'PHPSESSID=123456')")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed output")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()

        # Parse headers & cookies if provided
        headers = {"Authorization": args.header} if args.header else None
        cookies = {args.cookie.split("=")[0]: args.cookie.split("=")[1]} if args.cookie else None

        # Create and run the IDOR test
        idor_tester = IDORtest(args.url, args.param, args.start, args.end, args.method, headers=headers, cookies=cookies, verbose=args.verbose)
        idor_tester.test_idor()

    except KeyboardInterrupt:
        logging.error("[-] Process interrupted by user.")
    except Exception as e:
        logging.error(f"[-] Unexpected error: {e}")
