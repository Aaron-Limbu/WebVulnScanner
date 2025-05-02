import os
import logging
import json
from dotenv import load_dotenv
from shodan import Shodan
import argparse


class Logger:
    @staticmethod
    def setup_logger(log_file="shodan.log"):
        logging.basicConfig(filename=log_file, level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")


class ShodanHandler:
    def __init__(self, api_key):
        self.api = Shodan(api_key)

    def get_host_info(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                'IP': host['ip_str'],
                'Organization': host.get('org', 'N/A'),
                'OS': host.get('os', 'N/A'),
                'Ports': host['ports']
            }
        except Exception as e:
            logging.error(f"Error in get_host_info: {e}")
            return {"error": str(e)}

    def get_open_ports(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                port: service['product'] if 'product' in service else 'Unknown'
                for service in host.get('data', [])
                for port in [service.get('port')]
            }
        except Exception as e:
            logging.error(f"Error in get_open_ports: {e}")
            return {"error": str(e)}

    def search_vulns(self, query, limit=10):
        try:
            results = self.api.search(query)
            return [
                {
                    'IP': result['ip_str'],
                    'Vulnerabilities': result.get('vulns', []),
                    'Data': result['data']
                } for result in results['matches'][:limit]
            ]
        except Exception as e:
            logging.error(f"Error in search_vulns: {e}")
            return {"error": str(e)}

    def get_domain_info(self, domain):
        try:
            domain_info = self.api.dns.domain_info(domain)
            return {
                'Domain': domain,
                'Subdomains': domain_info.get('subdomains', []),
                'IPs': domain_info.get('ips', [])
            }
        except Exception as e:
            logging.error(f"Error in get_domain_info: {e}")
            return {"error": str(e)}

    def find_devices(self, device_query, limit=10):
        try:
            results = self.api.search(device_query)
            return [
                {
                    'IP': match['ip_str'],
                    'Data': match['data']
                } for match in results['matches'][:limit]
            ]
        except Exception as e:
            logging.error(f"Error in find_devices: {e}")
            return {"error": str(e)}

    def get_geolocation(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                'Latitude': host.get('latitude', 'N/A'),
                'Longitude': host.get('longitude', 'N/A'),
                'City': host.get('city', 'N/A'),
                'Country': host.get('country_name', 'N/A')
            }
        except Exception as e:
            logging.error(f"Error in get_geolocation: {e}")
            return {"error": str(e)}

    def get_account_status(self):
        try:
            account_info = self.api.info()
            return {
                'Total Queries': account_info['query_credits'],
                'Used Queries': account_info['used_credits'],
                'Plan': account_info['plan']
            }
        except Exception as e:
            logging.error(f"Error in get_account_status: {e}")
            return {"error": str(e)}


def parse_arguments():
    parser = argparse.ArgumentParser(prog='Shodan Recon', description='Recon tool using Shodan API')
    parser.add_argument('-i', '--ip_addr', type=str, help='Target IP address')
    parser.add_argument('-d', '--domain', type=str, help='Target domain name')
    parser.add_argument('-q', '--query', type=str, help='Shodan search query')
    parser.add_argument('-dq', '--device_query', type=str, help='Device search query')
    parser.add_argument('-s', '--status', action='store_true', help='Get Shodan account status')
    return parser.parse_args()


def main(ip_addr=None, domain=None, query=None, device_query=None, status=False):
    try:
        Logger.setup_logger()
        load_dotenv()

        API_KEY = os.getenv("SHODAN_API_KEY")
        if not API_KEY:
            logging.error("API key not found in environment variables!")
            exit("Error: API key missing. Check your .env file.")

        shodan_handler = ShodanHandler(API_KEY)

        if ip_addr:
            print("[+] Host Information:")
            print(json.dumps(shodan_handler.get_host_info(ip_addr), indent=4))
            print("\n[+] Open Ports:")
            print(json.dumps(shodan_handler.get_open_ports(ip_addr), indent=4))

        if domain:
            print("\n[+] Domain Information:")
            print(json.dumps(shodan_handler.get_domain_info(domain), indent=4))

        if query:
            print("\n[+] Vulnerability Search Results:")
            print(json.dumps(shodan_handler.search_vulns(query), indent=4))

        if device_query:
            print("\n[+] Device Search Results:")
            print(json.dumps(shodan_handler.find_devices(device_query), indent=4))

        if status:
            print("\n[+] Account Status:")
            print(json.dumps(shodan_handler.get_account_status(), indent=4))

    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"[-] An error occurred: {e}")


if __name__ == "__main__":
    args = parse_arguments()
    main(
        ip_addr=args.ip_addr,
        domain=args.domain,
        query=args.query,
        device_query=args.device_query,
        status=args.status
    )
    