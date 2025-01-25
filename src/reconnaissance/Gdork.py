import requests
from bs4 import BeautifulSoup
import argparse
import logging

class Logger:
    @staticmethod
    def setup_logger(log_filename="google_dork_scanner.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class GoogleDorkScanner:
    def __init__(self, query, num_results=10):
        self.query = query
        self.num_results = num_results
        self.search_results = []

    def perform_search(self):
        print(f"[i] Performing Google Dork: {self.query}")
        search_url = f"https://www.google.com/search?q={self.query}&num={self.num_results}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        try:
            response = requests.get(search_url, headers=headers)
            if response.status_code == 200:
                self.parse_results(response.text)
            else:
                print(f"[-] Failed to fetch results. Status Code: {response.status_code}")
                logging.error(f"Failed to fetch results for {self.query}")
        except requests.RequestException as e:
            print(f"[-] Error fetching results: {e}")
            logging.error(f"Error fetching results for {self.query}: {e}")

    def parse_results(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and "url?q=" in href:
                url = href.split("url?q=")[1].split("&")[0]
                self.search_results.append(url)

        if self.search_results:
            print(f"[+] Found {len(self.search_results)} results!")
            for result in self.search_results:
                print(result)
                logging.info(f"Found result: {result}")
        else:
            print("[-] No results found!")
            logging.info("No results found for the query")


class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="Google Dork Scanner")
        parser.add_argument("-q", "--query", type=str, required=True, help="Google Dork query")
        parser.add_argument("-n", "--num_results", type=int, default=10, help="Number of results")
        return parser.parse_args()

if __name__ == "__main__":
    Logger.setup_logger()
    cli_args = CLI.argument_parse()
    scanner = GoogleDorkScanner(cli_args.query, cli_args.num_results)
    scanner.perform_search()
