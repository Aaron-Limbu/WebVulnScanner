import requests
from bs4 import BeautifulSoup 
import argeparse
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
    def __init__(self,domain,output):
        self.url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=html&fl=original&collapse=urlkey"
        self.domain = domain
        self.output = output
    
    def run(self):
    
    	try: 
            response = requests.get(self.url,timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text,'html.parser')
            linke = [link.text for link in soup.find_all('a')]
            with open(self.output,'w') as file:
                for link in links: 
                    file.write(link+'\n')

            print(f"[+] Scrapped {len(links)} URLS from the wayback tool")
            logging.info(f"Scrapped {len(links)} URLS for {self.domain}")

        except requests.exceptions.RequestException as e: 
            print(f"[-] Error fetching data from waback tool: {e}")
            loggin.error(f"Error fetching data for {self.domain}: {e}")

class CLI:
    @staticmethod
    def parse_arguments():
       parse = argeparse.ArgumentParser(description="wayback scraper tool")
       parse.add_argument("-d","--domain",type=str,help="domain name")
       parse.add_argument("-o","--output",type=str,help="output filename")
       return parse.parse_args()

if __name__ == "__main__":
    try: 
        Logger.setup_logger()
        cli = CLI()
        args= cli.parse_arguments()
        wb= WBHandler(args.domain,args.output)
	wb.run()
    except KeyboardInterrupt as ke: 
        print(f"[-] {ke}")
        
    except Exception as e :
        print(f"[-] Error: {e}")
