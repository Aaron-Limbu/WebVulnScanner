import socket
import logging
import os
import argparse
import ssl

class Logger:
    @staticmethod
    def setup_logger(log_filename):
        os.makedirs(os.path.dirname(log_filename), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )

class BannerGrabber:
    def __init__(self, ipaddr, ports):
        self.ipaddr = ipaddr
        self.ports = ports

    def grab_banner(self, ipaddr, port):
        try:
            with socket.create_connection((ipaddr, port), timeout=5) as sock:
                if port == 443:
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=ipaddr) as ssock:
                        ssock.sendall(f"HEAD / HTTP/1.1\r\nHost: {ipaddr}\r\n\r\n".encode())
                        banner = ssock.recv(1024).decode(errors="ignore").strip()
                else:
                    sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {ipaddr}\r\n\r\n".encode())
                    banner = sock.recv(1024).decode(errors="ignore").strip()

            print(f"[+] Banner for {ipaddr}:{port}:\n{banner}\n")
            logging.info(f"[+] Banner for {ipaddr}:{port}:\n{banner}\n")
            return banner
        except (socket.timeout, socket.error, ssl.SSLError) as e:
            print(f"[-] Unable to grab banner for {ipaddr}:{port}: {e}")
            logging.error(f"[-] Unable to grab banner for {ipaddr}:{port}: {e}")
            return None

    def run(self):
        try:
            log_path = os.path.join("logs", "banner_grabber.log")
            Logger.setup_logger(log_path)

            resolved_ip = socket.gethostbyname(self.ipaddr)
            print(f"[+] Target resolved to IP: {resolved_ip}")
            print("[+] Starting banner grabbing...")
            logging.info(f"[+] Target resolved to IP: {resolved_ip}")
            logging.info("[+] Starting banner grabbing...")

            for port in self.ports:
                print(f"[i] Scanning port {port}...")
                logging.info(f"[i] Scanning port {port}...")
                self.grab_banner(resolved_ip, port)

            print("[+] Banner grabbing completed.")
            logging.info("[+] Banner grabbing completed.")
        except socket.gaierror as e:
            print(f"[-] Error resolving hostname {self.ipaddr}: {e}")
            logging.error(f"[-] Error resolving hostname {self.ipaddr}: {e}")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            logging.error(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Banner Grabbing Tool")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--ports", type=str, required=False, default="80,443", help="Comma-separated list of ports to scan"
    )
    args = parser.parse_args()

    ipaddr = args.target
    ports = [int(port.strip()) for port in args.ports.split(",")]

    grabber = BannerGrabber(ipaddr, ports)
    grabber.run()
