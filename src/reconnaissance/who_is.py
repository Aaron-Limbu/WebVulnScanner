import os 
import logging
import whois
import argparse 

class Logger: 
    @staticmethod 
    def setup_logger(log_filename="whois.log"):
        logging.basicConfig(filename=log_filename,level=logging.INFO,format="%(asctime)s - %(levelname)s - %(message)s")


class WhoisHandler:
    def __init__(self,url):
        self.url = url 
        try: 
            self.whois_data = whois.whois(self.url)
        except Exception as e: 
            logging.error(f"Failed to retrieve WHOIS data of {url}: {str(e)}")
            self.whois_data = None

    def getWhoisData(self): 
        if self.whois_data: 
            result = self.whois_data
            logging.info(f"Data of {self.url}:\n{result}")
        else:
            logging.error(f"No WHOIS data found for {self.url}")
            return "No WHOIS data was found "

class CLI: 
    @staticmethod
    def parse_argument():
        parser = argparse.ArgumentParser(description="WHOIS recon tool")
        parser.add_argument("-u","--url",type=str,required=True,help="URL to scan")
        return parser.parse_args()

class Application: 
    def __init__(self,url):
        self.whois_handler = WhoisHandler(url)
    def WD(self): 
        data = self.whois_handler.getWhoisData()
        print(data)
    
if __name__ == "__main__":
    Logger.setup_logger()
    cli = CLI()
    args = cli.parse_argument()
    app = Application(args.url)
    app.WD()
