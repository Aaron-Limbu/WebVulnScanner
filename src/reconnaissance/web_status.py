import requests
import logging
import argparse

class Logger:
    @staticmethod
    def setup_logger(log_filename="status.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logger initialized")

class WebStatusHandler:
    def __init__(self, domain):
        self.domain = domain

    def check_status(self):
        """Checks if the website is alive or dead."""
        try:
            response = requests.get(self.domain, timeout=5)
            if response.status_code == 200:
                logging.info(f"[+] {self.domain} is UP (Status Code: {response.status_code})")
                return f"[+] {self.domain} is UP"
            else:
                logging.warning(f"[-] {self.domain} is DOWN (Status Code: {response.status_code})")
                return f"[-] {self.domain} is DOWN (Status Code: {response.status_code})"
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Error checking {self.domain}: {e}")
            return f"[!] Error checking {self.domain}: {e}"

class CLI:
    @staticmethod
    def argument_parser():
        parser = argparse.ArgumentParser(description="Website Alive or Dead Checker")
        parser.add_argument("-d", "--domain", type=str, help="Single website URL (e.g., https://www.example.com)")
        parser.add_argument("-il", "--input-list", type=str, help="File containing a list of domains (one per line)")
        parser.add_argument("-o", "--output", type=str, help="Output file to save results")
        return parser.parse_args()

def process_domains(domains, output_file=None):
    results = []
    
    for domain in domains:
        checker = WebStatusHandler(domain.strip())
        result = checker.check_status()
        print(result)
        results.append(result)

    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(results))
        print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.argument_parser()

        if args.domain:
            process_domains([args.domain], args.output)
        elif args.input_list:
            with open(args.input_list, "r") as file:
                domains = file.readlines()
            process_domains(domains, args.output)
        else:
            print("[!] Please provide a domain (-d) or input file (-il). Use -h for help.")

    except KeyboardInterrupt:
        print("[!] Keyboard Interrupted")

    except Exception as e:
        print("[!] Error:", e)
