import threading
import sys
from src.GUI.process.log_update_callback import RedirectOutput
import os
import multiprocessing

"""
    This program runs the scripts for the GUI.
    _setup_output_redirection redirects the print() content to the GUI
"""
import os
import multiprocessing

class ReconProcess:
    def __init__(self, url, port, useragent, cookie, thread, wordlists, input_list, n, output_file, log_update_callback, filename):
        self.url = url

        # Validate port input
        if port:
            try:
                self.port = [int(p.strip()) for p in str(port).split(",") if p.strip().isdigit()]
            except ValueError:
                self.port = []  # Default to empty list if invalid port input
        else:
            self.port = []

        self.cookie = cookie or ""
        self.useragent = useragent or ""

        # Ensure thread is treated as a string before calling strip()
        if isinstance(thread, int):  
            self.thread = thread  # Already an integer, no need to strip
        elif isinstance(thread, str) and thread.strip().isdigit():  
            self.thread = int(thread.strip())  
        else:  
            self.thread = 10  # Default to 10 if invalid input

        # Validate n value
        self.n = n if isinstance(n, int) else 10

        # Ensure thread count doesn't exceed available cores
        max_threads = min(10, multiprocessing.cpu_count())
        self.thread = min(self.thread, max_threads)

        self.wordlists = os.path.join(os.getcwd(), "data", "wordlists", wordlists)
        self.log_update_callback = log_update_callback
        self.log_path = os.path.join(os.getcwd(), "logs", f"{filename}.log")
        self.output_file = output_file or "output"
        self.input_list_text = input_list



    def _setup_output_redirection(self):
        """Redirects stdout and stderr to both UI and log file."""
        redirect_output = RedirectOutput(self.log_update_callback, self.log_path)
        sys.stdout = redirect_output
        sys.stderr = redirect_output

    def BannerGrabber(self):
        self._setup_output_redirection()
        """Starts the Banner Grabber tool."""
        from src.reconnaissance.banner_grabber import BannerGrabber as BG
        bg = BG(self.url,self.port)
        banner_thread = threading.Thread(target=lambda: (bg.run(), sys.stdout.flush(), sys.stderr.flush()))
        banner_thread.start()

    def DNSenum(self): 
        self._setup_output_redirection()
        """Starts the DNS enumeration tool"""
        from src.reconnaissance.dns_enum import DNSEnum as DE
        de = DE(self.url,self.wordlists,self.thread)
        dns_enum_thread = threading.Thread(target=lambda:(de.run(),de.scan_vulnerabilities(),sys.stdout.flush(),sys.stderr.flush()))
        dns_enum_thread.start()

    def DirEnum(self): 
        self._setup_output_redirection()
        """Starts the Directory Enumeration tool"""
        from src.reconnaissance.dir_enum import Application as DirE
        dire = DirE(self.url,self.wordlists,self.thread,self.cookie,self.useragent)
        dire_thread = threading.Thread(target=lambda:(dire.run(),sys.stdout.flush(),sys.stderr.flush()))
        dire_thread.start()

    def HeaderGrabber(self):
        self._setup_output_redirection()
        """Starts the Header Grabber tool."""
        from src.reconnaissance.Header import Application as HG
        hg = HG(self.url)
        header_thread = threading.Thread(target=lambda: (hg.run(),sys.stdout.flush(),sys.stderr.flush()))  
        header_thread.start()      
    def Gdork(self): 
        self._setup_output_redirection()
        """Starts the Google Dork tool"""
        from src.reconnaissance.Gdork import GoogleDorkScanner as GD
        gd = GD(self.url,self.n)
        gdork_thread = threading.Thread(target=lambda:(gd.perform_search(),sys.stdout.flush(),sys.stderr.flush()))
        gdork_thread.start()
        
    def JSfAnalyz(self):
        self._setup_output_redirection()
        """Starts the JS file analyzer tool"""
        from src.reconnaissance.js_file_analyzer import JSHandler as JF
        jf = JF(self.url)
        jf_thread = threading.Thread(target=lambda:(jf.run_analysis(),sys.stdout.flush(),sys.stderr.flush()))
        jf_thread.start()

    def ShodanEnum(self): 
        self._setup_output_redirection()
        """Starts the Shodan Recon tool"""
        
        
    def SubDomEnum(self): 
        self._setup_output_redirection()
        """Starts the Sub domain enumeration tool"""
        from src.reconnaissance.sub_dom_enum import DomainEnum as SD 
        sd = SD(self.url,self.thread)
        sd_thread = threading.Thread(target=lambda:(sd.run(),sys.stdout.flush(),sys.stderr.flush()))
        sd_thread.start()

    def WebScrap(self): 
        self._setup_output_redirection()
        """Starts the Web scraper tool"""
        from src.reconnaissance.wbScraper import WBHandler as WS
        ws = WS(self.url,self.output_file)
        ws_thread = threading.Thread(target=lambda:(ws.run(),sys.stdout.flush(),sys.stderr.flush()))
        ws_thread.start()
    
    def WebStatus(self): 
        self._setup_output_redirection()
        """Starts the web status tool"""
        from src.reconnaissance.web_status import WebStatusHandler as W
        ws = W(self.url,self.input_list_text,self.output_file)
        ws_thread = threading.Thread(target=lambda: (ws.check_status(),sys.stdout.flush(),sys.stderr.flush()))
        ws_thread.start()

    def Wis(self): 
        self._setup_output_redirection()
        """Starts the whois tool"""
        from src.reconnaissance.who_is import Application as WHO
        who = WHO(self.url)
        who_thread = threading.Thread(target=lambda:(who.run(),sys.stdout.flush(),sys.stderr.flush()))
        who_thread.start()

    
