import nmap
import logging
import argparse

class Logger:
    @staticmethod
    def setup_logger(log_filename="nmap_recon.log"):
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

class NmapHandler:
    def __init__(self, ip, ports, arguments, script):
        self.scanner = nmap.PortScanner()
        self.ip = ip
        self.ports = ports
        self.arguments = arguments
        self.script = script

    def scan(self):
        try:
            scan_arguments = self.arguments
            if self.script:
                scan_arguments += f" --script={self.script}"

            scan_result = self.scanner.scan(hosts=self.ip, ports=self.ports, arguments=scan_arguments)

            for host in self.scanner.all_hosts():
                state = self.scanner[host].state()
                hostname = self.scanner[host].hostname()
                logging.info(f"Host: {host}, State: {state}, Hostname: {hostname}")
                print(f"[i] Host: {host}")
                print(f"[i] State: {state}")
                print(f"[i] Hostname: {hostname}")

                for protocol in self.scanner[host].all_protocols():
                    print(f"[i] Protocol: {protocol}")
                    ports = self.scanner[host][protocol].keys()
                    for port in ports:
                        portname = self.scanner[host][protocol][port]['name']
                        state = self.scanner[host][protocol][port]['state']
                        service = self.scanner[host][protocol][port].get('product', 'N/A')
                        print(f"  Port: {port} ({portname}), State: {state}, Service: {service}")

                if 'osmatch' in self.scanner[host]:
                    for os in self.scanner[host]['osmatch']:
                        print(f"  Detected OS: {os['name']} with {os['accuracy']}% accuracy")

            return scan_result
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            print(f"[-] Error: {e}")

class Application:
    def __init__(self, ip, arguments, ports, script):
        self.nmap_handler = NmapHandler(ip, ports, arguments, script)

    def run(self):
        print("[i] Starting scan...")
        result = self.nmap_handler.scan()
        print("[i] Scan completed.")
        return result

class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Network port scanning with Nmap")
        parser.add_argument("-ip", "--ipaddr", type=str, help="IP address of device or network", required=True)
        parser.add_argument("-p", "--ports", type=str, help="Ports for scanning (e.g., 20-80). Default scans major ports", default="20-80")
        parser.add_argument("-a", "--arguments", type=str, help="Arguments for scanning (e.g., '-sS -O'). Use quotes for multiple arguments.", default="-sS -sV")
        parser.add_argument("-s", "--script", type=str, help="Nmap script to use during scanning (e.g., 'http-title')", default=None)
        return parser.parse_args()

if __name__ == "__main__":
    try:
        Logger.setup_logger()
        cli = CLI()
        args = cli.parse_arguments()
        app = Application(args.ipaddr, args.arguments, args.ports, args.script)
        app.run()
    except KeyboardInterrupt:
        print("[i] Scan interrupted by user.")
    except Exception as e:
        logging.error(f"Unhandled error: {e}")
        print(f"[i] Error: {e}")
