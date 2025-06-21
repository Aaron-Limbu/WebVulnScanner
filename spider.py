import argparse
import pyfiglet
import requests
import threading
import os 
import multiprocessing
import random
import requests.cookies


class Spider():
    def __init__(self,url,nssl,ip,sc,a,sm,o,pt,ua):
        self.url = url 
        self.noSSL = True if nssl and nssl.lower() == "true" else False
        self.ipaddr = ip
        self.scan = sc 
        self.auto = a 
        self.scanMethod = sm
        self.output = o
        self.port = pt 
        self.wordlists = ""
        self.foundRoutes = []
        self.foundLinks = []
        self.foundDirectories = []
        self.foundFiles = []
        self.bannerResult = ""
        self.httpResult = {} 
        self.sslResult = {}
        self.cookie = {}
        self.useragent = {
            "User-Agent": ua if ua else random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ]),
            "Accept-Language": "en-US,en;q=0.9",
        }
    def recon(self):
        try: 
            from reconnaissance.banner_grabber import BannerGrabber as BG
            from reconnaissance.Header import SSLAnalysis as SL
            from reconnaissance.Header import HTTPHeaderAnalysis as HG
            bg = BG(self.ipaddr,self.port)
            hg = HG(self.url)
            bg_thread = threading.Thread(target=bg.grab_banner)
            hg_thread = threading.Thread(target=hg.analyze_headers)
            bg_thread.start()
            bg_thread.join()
            hg_thread.start()
            self.httpResult = hg.httpresult
            hg_thread.join()
            if self.noSSL == False:
                sl = SL(self.url)
                sl_thread = threading.Thread(target=sl.analyze_ssl)
                sl_thread.start()
                self.sslResult = sl.sslresult
                sl_thread.join()
            else: 
                print(f"[i] SSL check is off.")
            session = requests.Session()
            resp = session.get(self.url)
            self.cookie = resp.cookies.get_dict()
            from reconnaissance.dir_enum import DirectoryEnum as DE
            self.wordlists = os.path.join(os.getcwd(),"data","wordlists","directory_enumeration","directory_list_medium.txt")
            de = DE(self.url,self.wordlists,self.useragent,self.cookie,5)
            de_thread = threading.Thread(target=de.enum)
            de_thread.start()
            de_thread.join()
            self.foundDirectories = de.found_dir
            self.wordlists = os.path.join(os.getcwd(),"data","wordlists","fileEnum","fileEnum.txt")
            fe = DE(self.url,self.wordlists,self.useragent,self.cookie,5)
            fe_thread = threading.Thread(target=fe.enum)
            fe_thread.start()
            fe_thread.join()
            self.foundFiles = fe.found_dir
        
        except requests.exceptions.RequestException as re: 
            print(f"[-] Error: {re}")

        except Exception as e: 
            print(f"[-] Error: {e}")

    def generateReport(self): 
        try: 
            
            with open('banner_grabber','r') as bgrslt : 
                self.bannerResult = bgrslt.read()
                
            html_content = """
                    <html>
                        <head>
                            <meta charset="UTF-8">
                            <meta http-equiv="X-UA-Compatible" content="IE=edge">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Spiderscan Result</title>
                            <style>
                                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
                                h1 {{ color: #333; }}
                                ul {{ background-color: #fff; padding: 10px; border-radius: 5px; }}
                                li {{ margin-bottom: 5px; }}
                                .report {{
                                    justify-content: center;
                                    align-items: center; 

                                }}
                            <style/>

                        </head>
                        <body>
                            <div>
                                <h1>Spider Scan Report</h1>
                                <h2>Target: {self.url}</h2>
                                <div class="report">
                                    <h2>Web Banner </h2>
                                    <p>{self.bannerResult}</p>
                                    <h2>Web SSL analysis</h2>
                                    <p>{self.sslResult}</p>
                                    <h2>Header Analysis</h2>
                                    <p>{self.httpResult}</p>
                                </div>
                            </div>
                        </body>
                    </html>
                """
            with open(self.filename,"w") as result: 
                result.write(html_content)            
            print(f"[+] html result generated at ../data/logs/html/{self.filename}")
        except Exception as e: 
            print(f"[i] Error: {e}")

class DisplayInfo:
    def __init__(self, args):
        self.args = args

    def show_arguments(self):
        print("\n[+] Spider scan")
        print(f"Target URL     : {self.args.url}")
        print(f"No SSL Scan    : {self.args.nossl if self.args.nossl else 'SSL scan on'}")
        print(f"Target IP Addr : {self.args.ipaddr if self.args.ipaddr else 'Not specified'}")
        print(f"Scan Type      : {'Without Recon' if self.args.scan == 1 else 'With Recon' if self.args.scan == 2 else 'Default'}")
        print(f"Auto Mode      : {self.args.auto}")
        print(f"Scan Method    : {self.args.scanmethod}\n")
        print("--------------------------------------------------------------------------------------")
class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        banner = pyfiglet.figlet_format("SPIDER SCAN", font="slant")
        print(banner)
        return super().add_usage(usage, actions, groups, prefix)

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter)
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (example:- https://example.com)")
        parser.add_argument("-nssl", "--nossl", type=str, required=False,choices=["true","false"], help="No SSL scan")
        parser.add_argument("-ip", "--ipaddr", type=str, required=False, help="Target IP address (example:- 10.10.10.10)")
        parser.add_argument("-sc", "--scan", type=int, required=False, default=0, choices=[1, 2],
                            help="1. Scan without recon\n2. Scan with Recon (will scan all domains)")
        parser.add_argument("-a", "--auto", action='store_true', help="Enable auto mode")
        parser.add_argument("-sm", "--scanmethod", type=int, required=True, default=0,
                            choices=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                            help="1. API Auth scan\n2. API Test scan\n3. Bruteforce scan\n4. Command Injection\n"
                                 "5. CSRF\n6. IDOR\n7. LFI\n8. NMAP\n9. SQLi\n10. SSRF\n11. XEE\n12. XSS")
        parser.add_argument("-p","--port",type=str,required=False,default="80,443",help="example: -p 80,443")
        parser.add_argument("-o","--output",type=str,required=False,help="-o output.txt")
        parser.add_argument("-ua","--useragent",type=str,required=False,help="example: -ua \"Mozilla blah blah blah bleh bleh blu blu blu\"")
        return parser.parse_args()

if __name__ == "__main__":
    try:
        cli_args = CLI.parse_arguments()
        info = DisplayInfo(cli_args)
        info.show_arguments()

    except KeyboardInterrupt:
        print("[-] Keyboard interrupt")
    except Exception as e:
        print(f"[-] Error: {e}")
