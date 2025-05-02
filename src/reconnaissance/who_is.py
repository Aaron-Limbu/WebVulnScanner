import os
import logging
import whois
import argparse
from urllib.parse import urlparse

class Logger:
    @staticmethod
    def setup_logger(log_filename="whois_recon.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logger initialized")


class WhoisHandler:
    def __init__(self, url):
        self.original_input = url
        self.url = self.extract_domain(url)
        self.whois_data = None
        if self.url:
            try:
                self.whois_data = whois.whois(self.url)
                if not self.whois_data:
                    logging.warning(f"No WHOIS data found for {self.url}")
            except Exception as e:
                logging.error(f"Failed to retrieve WHOIS data for {self.url}: {str(e)}")
        else:
            logging.error(f"Invalid input provided: {self.original_input}")

    def extract_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else url.strip()

    def get_whois_data(self):
        if self.whois_data:
            try:
                result = str(self.whois_data)
                logging.info(f"WHOIS data for {self.url} retrieved successfully.")
                return result
            except Exception as e:
                logging.error(f"Error processing WHOIS data for {self.url}: {str(e)}")
                return "[-] Error processing WHOIS data."
        else:
            return "[-] No WHOIS data available or invalid URL."


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="WHOIS Recon Tool")
        parser.add_argument("-u", "--url", type=str, required=True, help="URL to scan (e.g., https://example.com)")
        return parser.parse_args()


class Application:
    def __init__(self, url):
        self.whois_handler = WhoisHandler(url)

    def run(self):
        whois_data = self.whois_handler.get_whois_data()
        if "[-]" not in whois_data:
            print(f"[+] WHOIS Data for {self.whois_handler.url}:\n{whois_data}")
        else:
            print(whois_data)


if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli = CLI()
        args = cli.parse_arguments()
        app = Application(args.url)
        app.run()
    except KeyboardInterrupt:
        print("\n[-] Operation interrupted by user.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
