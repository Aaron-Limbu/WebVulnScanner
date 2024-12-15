import logging
import os
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor


class Logger:
    @staticmethod
    def setup_logger(log_filename="dir_enum.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )


class DirectoryEnum:
    def __init__(self, url, wordlists, threads=10):
        self.url = url.rstrip('/')
        self.wordlists = wordlists
        self.found_dir = []
        self.threads = threads

    def directory_req(self, directory):
        t_url = f"{self.url}/{directory}"
        try:
            req = requests.get(t_url, timeout=5)
            if req.status_code == 200:
                print(f"[+] Found directory: {t_url}")
                self.found_dir.append(t_url)
                logging.info(f"Found directory: {t_url}")
            elif req.status_code in [403, 404]:
                print(f"[-] Target restricted or not found: {t_url}")
                logging.info(f"Target restricted or not found: {t_url}")
            else:
                print(f"[i] Unexpected status code {req.status_code} for: {t_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {t_url}: {str(e)}")
            print(f"[-] Request failed for {t_url}: {str(e)}")

    def enum(self):
        try:
            with open(self.wordlists, 'r') as file:
                directories = [line.strip() for line in file if line.strip()]
        except FileNotFoundError as fn:
            print(f"[-] File not found: {str(fn)}")
            logging.error(f"File not found: {str(fn)}")
            return

        print(f"[i] Starting directory enumeration for {self.url} with {self.threads} threads")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.directory_req, directories)

        print("[+] Enumeration completed. Found directories:")
        for directory in self.found_dir:
            print(directory)
        logging.info("Enumeration completed. Found directories: " + ", ".join(self.found_dir))


class Application:
    def __init__(self, url, wordlists, threads):
        self.de = DirectoryEnum(url, wordlists, threads)

    def run(self):
        self.de.enum()


class CLI:
    @staticmethod
    def argument_parse():
        parser = argparse.ArgumentParser(description="Directory enumeration")
        parser.add_argument("-w", "--wordlist", type=str, required=True, help="Wordlist location")
        parser.add_argument("-u", "--url", type=str, required=True, help="Website URL")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli = CLI()
        args = cli.argument_parse()
        app = Application(args.url, args.wordlist, args.threads)
        app.run()
    except KeyboardInterrupt as ke:
        print(f"[i] {ke}")
    except Exception as e:
        print(f"[-] {e}")
        logging.error(e)
