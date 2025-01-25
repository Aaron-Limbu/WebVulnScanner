import requests
import re
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from colorama import Fore, Style

class Logger:
    @staticmethod
    def setup_logger(log_filename="js_analyzer.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logger initialized")

class JSHandler:
    def __init__(self, url):
        self.url = url
        self.js_links = set()

    def extract_js_links(self):
        """Extract JavaScript file links from the given web page."""
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    full_url = urljoin(self.url, src)
                    self.js_links.add(full_url)
            logging.info(f"Extracted JS links: {self.js_links}")
        except requests.RequestException as e:
            logging.error(f"Error fetching URL: {e}")

    def download_js_file(self, url):
        """Download and return the content of a JavaScript file."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logging.error(f"Error downloading JS file: {e}")
            return None

    def analyze_js_content(self, content):
        urls = re.findall(r'(https?://[^\s"\'<>]+)', content)
        api_keys = re.findall(r'(?i)(api[_\-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+))', content)
        endpoints = re.findall(r'(\/[a-zA-Z0-9_\-/]+)', content)

        return {
            "URLs": urls,
            "API Keys": [key[1] for key in api_keys],
            "Endpoints": list(set(endpoints))
        }

    def run_analysis(self):
        self.extract_js_links()
        print(f"[i] links found: {self.js_links}")
        for js_url in self.js_links:
            print(f"[i] Analyzing JS File: {js_url}")
            js_content = self.download_js_file(js_url)
            if js_content:
                results = self.analyze_js_content(js_content)
                print(f"{Fore.GREEN}[+] URLs Found: {Fore.WHITE}{results['URLs']}")
                print(f"{Fore.GREEN}[+] API Keys Found: {Fore.WHITE}{results['API Keys']}")
                print(f"{Fore.GREEN}[+] Endpoints Found: {Fore.WHITE}{results['Endpoints']}")
                logging.info(f"Analysis Results for {js_url}: {results}")


class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="JavaScript Analyzer Toolkit")
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL for JS Analysis")
        return parser.parse_args()

if __name__ == "__main__":
    Logger.setup_logger()
    cli = CLI()
    args = cli.argument_parse()
    analyzer = JSHandler(args.url)
    analyzer.run_analysis()
