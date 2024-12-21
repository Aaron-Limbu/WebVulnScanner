import os
import logging
import whois
import argparse

class Logger:
    @staticmethod
    def setup_logger(log_filename="who_is.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info("Logger initialized")


class WhoisHandler:
    def __init__(self, url):
        self.url = url
        try:
            self.whois_data = whois.whois(self.url)
            if self.whois_data is None:
                logging.warning(f"No WHOIS data found for {self.url}")
        except Exception as e:
            logging.error(f"Failed to retrieve WHOIS data for {self.url}: {str(e)}")
            self.whois_data = None

    def get_whois_data(self):
        if self.whois_data:
            try:
                result = str(self.whois_data)
                logging.info(f"WHOIS data for {self.url}:\n{result}")
                return result
            except Exception as e:
                logging.error(f"Error processing WHOIS data for {self.url}: {str(e)}")
                return "[-] Error processing WHOIS data"
        else:
            return "[-] No WHOIS data available"


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="WHOIS Recon Tool")
        parser.add_argument("-u", "--url", type=str, required=True, help="URL to scan")
        return parser.parse_args()


class Application:
    def __init__(self, url):
        self.whois_handler = WhoisHandler(url)

    def run(self):
        data = self.whois_handler.get_whois_data()
        print(f"[+] {data}")


if __name__ == "__main__":
    try: 
        Logger.setup_logger()
        cli = CLI()
        args = cli.parse_arguments()
        app = Application(args.url)
        app.run()
    except KeyboardInterrupt as ke : 
        print(f"[-] {ke}")
    except Exception as e : 
        print(f"[-] {e}")
