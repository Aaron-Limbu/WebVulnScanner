import threading
import sys
from src.GUI.process.log_update_callback import RedirectOutput
import os

"""This program runs the scripts for the GUI"""

class ReconProcess:
    def __init__(self, url, port, useragent, cookie, thread, wordlists, log_update_callback, filename):
        self.url = url
        self.port = [int(p.strip()) for p in port.split(",") if p.strip()] if port else [] 
        self.cookie = cookie or ""
        self.useragent = useragent or ""
        self.thread = thread or 1 
        self.wordlists = wordlists or [] 
        self.log_update_callback = log_update_callback
        self.log_path = f"{os.getcwd()}\\logs\\{filename}.log"


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

    def HeaderGrabber(self):
        self._setup_output_redirection()
        """Starts the Header Grabber tool."""
        from src.reconnaissance.Header import Application as HG
        hg = HG(self.url)
        header_thread = threading.Thread(target=lambda: (hg.run(),sys.stdout.flush(),sys.stderr.flush()))  
        header_thread.start()      

    