import threading
import sys
from src.GUI.process.log_update_callback import RedirectOutput

import src.reconnaissance.dns_enum
import src.reconnaissance.Gdork
import src.reconnaissance.Header
import src.reconnaissance.js_file_analyzer
import src.reconnaissance.shodan_recon
import src.reconnaissance.sub_dom_enum
import src.reconnaissance.wbScraper
import src.reconnaissance.web_status
import src.reconnaissance.who_is
import os


        


class ReconProcess:
    def __init__(self, url, port, log_update_callback, filename):
        self.url = url
        self.port = [int(p.strip()) for p in port.split(",") if p.strip()]
        self.log_update_callback = log_update_callback

        self.log_path = f"{os.getcwd()}\\logs\\{filename}.log"

    def BannerGrabber(self):
        # Redirect stdout/stderr to the callback for the UI
        redirect_output = RedirectOutput(self.log_update_callback,self.log_path)
        sys.stdout = redirect_output
        sys.stderr = redirect_output
        from src.reconnaissance.banner_grabber import BannerGrabber as BG

        # Start the Banner Grabber
        bg = BG(self.url, self.port)

        # Run the banner grabbing process in a separate thread
        banner_thread = threading.Thread(target=lambda: (bg.run(), sys.stdout.flush(), sys.stderr.flush()))
        banner_thread.start()