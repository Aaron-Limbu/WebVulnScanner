import ssl
import socket
import requests
import argparse
from datetime import datetime

class HTTPHeaderAnalysis:
    def __init__(self, url):
        self.url = url

    def analyze_headers(self):
        print(f"[+] Analyzing HTTP headers for {self.url}...")
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers

            print(f"\n[+] HTTP Headers:")
            for header, value in headers.items():
                print(f"    {header}: {value}")

            print("\n[+] Security Header Analysis:")
            security_headers = {
                "Content-Security-Policy": "Protects against XSS attacks",
                "Strict-Transport-Security": "Enforces HTTPS",
                "X-Frame-Options": "Mitigates clickjacking",
                "X-XSS-Protection": "Enables XSS filter",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "Referrer-Policy": "Controls referrer information",
                "Permissions-Policy": "Restricts browser features",
            }

            for header, description in security_headers.items():
                if header in headers:
                    print(f"    [+] {header}: Present ({description})")
                else:
                    print(f"    [-] {header}: Missing ({description})")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching HTTP headers: {e}")


class SSLAnalysis:
    def __init__(self, hostname):
        self.hostname = hostname

    def analyze_ssl(self):
        print(f"\n[+] Analyzing SSL/TLS for {self.hostname}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

                    print("\n[+] SSL Certificate Details:")
                    print(f"    Subject: {cert.get('subject')}")
                    print(f"    Issuer: {cert.get('issuer')}")
                    valid_from = datetime.strptime(cert.get('notBefore'), '%b %d %H:%M:%S %Y %Z')
                    valid_to = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                    print(f"    Valid From: {valid_from}")
                    print(f"    Valid To: {valid_to}")

                    if valid_to < datetime.utcnow():
                        print("    [-] Certificate has expired!")
                    else:
                        print("    [+] Certificate is valid.")

        except (ssl.SSLError, socket.error) as e:
            print(f"[-] SSL/TLS analysis failed: {e}")


class Application:
    def __init__(self, url):
        if not url.startswith("http"):
            url = f"http://{url}"
        self.url = url
        self.hostname = url.split("//")[-1].split("/")[0]

    def run(self):
        http_analysis = HTTPHeaderAnalysis(self.url)
        http_analysis.analyze_headers()

        ssl_analysis = SSLAnalysis(self.hostname)
        ssl_analysis.analyze_ssl()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Header and SSL Analysis Tool")
    parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    app = Application(args.url)
    app.run()
