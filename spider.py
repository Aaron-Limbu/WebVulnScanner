import argparse
import pyfiglet
import requests
import threading
import os
import random
import importlib
import requests.cookies


class Spider():
    def __init__(self, url, nssl, ip, sc, a, sm, o, pt, ua, c):
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
        self.cookie = c
        self.filename = o if o else "scan_report.html"
        self.useragent = {
            "User-Agent": ua if ua else random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)"
            ]),
            "Accept-Language": "en-US,en;q=0.9",
        }

    def recon(self):
        try:
            from reconnaissance.banner_grabber import BannerGrabber as BG
            from reconnaissance.Header import SSLAnalysis as SL
            from reconnaissance.Header import HTTPHeaderAnalysis as HG
            from reconnaissance.dir_enum import DirectoryEnum as DE
            bg = BG(self.ipaddr, self.port)
            hg = HG(self.url)
            bg_thread = threading.Thread(target=bg.grab_banner)
            hg_thread = threading.Thread(target=hg.analyze_headers)
            bg_thread.start()
            bg_thread.join()
            hg_thread.start()
            hg_thread.join()
            self.httpResult = hg.httpresult
            if not self.noSSL:
                sl = SL(self.url)
                sl_thread = threading.Thread(target=sl.analyze_ssl)
                sl_thread.start()
                sl_thread.join()
                self.sslResult = sl.sslresult
            else:
                print("[i] SSL check is off.")
            session = requests.Session()
            resp = session.get(self.url)
            self.cookie = resp.cookies.get_dict()
            self.wordlists = os.path.join("data", "wordlists", "directory_enumeration", "directory_list_medium.txt")
            de = DE(self.url, self.wordlists, self.useragent, self.cookie, 5)
            de_thread = threading.Thread(target=de.enum)
            de_thread.start()
            de_thread.join()
            self.foundDirectories = de.found_dir
            self.wordlists = os.path.join("data", "wordlists", "fileEnum", "fileEnum.txt")
            fe = DE(self.url, self.wordlists, self.useragent, self.cookie, 5)
            fe_thread = threading.Thread(target=fe.enum)
            fe_thread.start()
            fe_thread.join()
            self.foundFiles = fe.found_dir

        except requests.exceptions.RequestException as re:
            print(f"[-] Request Error: {re}")
        except Exception as e:
            print(f"[-] Recon Error: {e}")

    def run_scan_method(self):
        print(f"[i] Running scan method {self.scanMethod}")
        module_map = {
            1: "apiAuth",
            2: "ApiTest",
            3: "Bruteforce",
            4: "CmdInj",
            5: "CSRF",
            6: "idor",
            7: "LFI",
            8: "nmap_scan",
            9: "sql_inj",
            10: "SSRF",
            11: "XEE",
            12: "XSS",
        }

        module_name = module_map.get(self.scanMethod)
        if not module_name:
            print("[-] Invalid scan method.")
            return

        try:
            scan_module = importlib.import_module(f"vuln_scans.{module_name}")
            if hasattr(scan_module, "run"):
                scan_module.run(self.url, self.useragent, self.cookie)
            else:
                print(f"[-] Module {module_name} has no run() function.")
        except ImportError as e:
            print(f"[-] Failed to import module {module_name}: {e}")
        except Exception as e:
            print(f"[-] Scan error in {module_name}: {e}")

    def generateReport(self):
        try:
            if os.path.exists("banner_grabber"):
                with open("banner_grabber", 'r') as bgrslt:
                    self.bannerResult = bgrslt.read()

            html_content = f"""
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
                        </style>
                    </head>
                    <body>
                        <div>
                            <h1>Spider Scan Report</h1>
                            <h2>Target: {self.url}</h2>
                            <div class="report">
                                <h2>Web Banner</h2>
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

            with open(self.filename, "w") as result:
                result.write(html_content)
            print(f"[+] HTML result generated at ./data/logs/html/{self.filename}")

        except Exception as e:
            print(f"[i] Report Generation Error: {e}")


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
        print("Written By: Escalon")
        return super().add_usage(usage, actions, groups, prefix)


class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter)
        parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (example: https://example.com)")
        parser.add_argument("-nssl", "--nossl", type=str, choices=["true", "false"], help="Disable SSL scan")
        parser.add_argument("-ip", "--ipaddr", type=str, help="Target IP address")
        parser.add_argument("-p", "--port", type=str, default="80,443", help="Ports to scan (default: 80,443)")
        parser.add_argument("-ua", "--useragent", type=str, help="Custom User-Agent")
        parser.add_argument("-c", "--cookie", type=str, help="Cookie string (example: PHPSESSID=123456)")
        parser.add_argument("-t", "--threads", type=int, default=3, help="Number of threads")
        parser.add_argument("-sc", "--scan", type=int, choices=[1, 2], default=0, help="1: Without Recon, 2: With Recon")
        parser.add_argument("-a", "--auto", action='store_true', help="Enable auto mode")
        parser.add_argument("-sm", "--scanmethod", type=int, required=True,
                            choices=list(range(1, 13)),
                            help="Scan type: 1-API Auth, 2-API Test, 3-Bruteforce, 4-Command Injection, "
                                 "5-CSRF, 6-IDOR, 7-LFI, 8-NMAP, 9-SQLi, 10-SSRF, 11-XEE, 12-XSS")
        parser.add_argument("-o", "--output", type=str, help="Output HTML filename")
        return parser.parse_args()


if __name__ == "__main__":
    try:
        cli_args = CLI.parse_arguments()
        info = DisplayInfo(cli_args)
        info.show_arguments()

        spider = Spider(cli_args.url, cli_args.nossl, cli_args.ipaddr, cli_args.scan,
                        cli_args.auto, cli_args.scanmethod, cli_args.output,
                        cli_args.port, cli_args.useragent, cli_args.cookie)

        if cli_args.scan == 2:
            spider.recon()

        spider.run_scan_method()

        if cli_args.output:
            spider.generateReport()

    except KeyboardInterrupt:
        print("[-] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected Error: {e}")
