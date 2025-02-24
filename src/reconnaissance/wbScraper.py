import requests
from bs4 import BeautifulSoup
import argparse
import logging

class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            filename="wayback_scraper.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class WBHandler:
    def __init__(self, domain, output):
        self.url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=html&fl=original&collapse=urlkey"
        self.domain = domain
        self.output = output

    def run(self):
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [link.text for link in soup.find_all('a')]

            with open(self.output, 'w') as file:
                for link in links:
                    file.write(link + '\n')

            print(f"[+] Scraped {len(links)} URLs from the Wayback Machine.")
            logging.info(f"Scraped {len(links)} URLs for {self.domain}")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching data from the Wayback Machine: {e}")
            logging.error(f"Error fetching data for {self.domain}: {e}")

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Wayback Machine Scraper Tool")
        parser.add_argument("-d", "--domain", type=str, required=True, help="Domain name to scrape")
        parser.add_argument("-o", "--output", type=str, required=True, help="Output filename to save results")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()
        wb = WBHandler(args.domain, args.output)
        wb.run()

    except KeyboardInterrupt:
        print("[-] Scan interrupted by user.")
        
    except Exception as e:
        print(f"[-] Error: {e}")
