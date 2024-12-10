from shodan import Shodan
import os
import logging
from dotenv import load_dotenv
import argparse

class Logger: 
    @staticmethod 
    def setup_logger(log_file="shodan.log"):
        logging.basicConfig(filename=log_file, level=logging.INFO)

class ShodanHandler:
    def __init__(self, api_key):
        self.api = Shodan(api_key)

    def getHostInfo(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                'IP': host['ip_str'],
                'Organization': host.get('org', 'N/A'),
                'OS': host.get('os', 'N/A'),
                'Ports': host['ports']
            }
        except Exception as e:
            logging.error("Error occurred in getHostInfo: {}".format(str(e)))
            return {"error": str(e)}

    def getOpenPorts(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                port: service['product'] if 'product' in service else 'Unknown'
                for service in host.get('data', [])
                for port in [service.get('port')]
            }
        except Exception as e:
            logging.error("Error occurred in getOpenPorts: {}".format(str(e)))
            return {"error": str(e)}

    def searchVuln(self, query, limit=10):
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
            logging.error("Error occurred in searchVuln: {}".format(str(e)))
            return {"error": str(e)}

    def getDomainInfo(self, domain):
        try:
            domain_info = self.api.dns.domain_info(domain)
            return {
                'Domain': domain,
                'Subdomains': domain_info.get('subdomains', []),
                'IPs': domain_info.get('ips', [])
            }
        except Exception as e:
            logging.error("Error occurred in getDomainInfo: {}".format(str(e)))
            return {"error": str(e)}

    def findDevices(self, device_query, limit=10):
        try:
            results = self.api.search(device_query)
            return [
                {
                    'IP': match['ip_str'],
                    'Data': match['data']
                } for match in results['matches'][:limit]
            ]
        except Exception as e:
            logging.error("Error occurred in findDevices: {}".format(str(e)))
            return {"error": str(e)}

    def getGeolocation(self, ip_addr):
        try:
            host = self.api.host(ip_addr)
            return {
                'Latitude': host.get('latitude', 'N/A'),
                'Longitude': host.get('longitude', 'N/A'),
                'City': host.get('city', 'N/A'),
                'Country': host.get('country_name', 'N/A')
            }
        except Exception as e:
            logging.error("Error occurred in getGeolocation: {}".format(str(e)))
            return {"error": str(e)}

    def getAccountStatus(self):
        try:
            account_info = self.api.info()
            return {
                'Total Queries': account_info['query_credits'],
                'Used Queries': account_info['used_credits'],
                'Plan': account_info['plan']
            }
        except Exception as e:
            logging.error("Error occurred in getAccountStatus: {}".format(str(e)))
            return {"error": str(e)}

class CLI: 
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(prog='Shodan Recon', description='Recon tool using Shodan API')
        parser.add_argument('-i', '--ip_addr', type=str, required=True, help='Target IP address')
        parser.add_argument('-u', '--url', type=str, help='Target URL')
        parser.add_argument('-d', '--domain', type=str, help='Target domain name')
        parser.add_argument('-dq', '--device_query', type=str, help='Device search query')
        parser.add_argument('-q', '--query', type=str, help='Shodan search query')
        args = parser.parse_args()
        return args

class Application: 
    def __init__(self, api_key):
        self.shodan_handler = ShodanHandler(api_key)

    def HI(self, ip): 
        result = self.shodan_handler.getHostInfo(ip)
        print(f"Host info: {result}")

    def OP(self, ip):
        result = self.shodan_handler.getOpenPorts(ip)
        print(f"Open Ports: {result}")

    def SV(self, query, limit=10):
        result = self.shodan_handler.searchVuln(query, limit)
        print(f"Searched vulnerabilities: {result}")

    def DI(self, domain):
        result = self.shodan_handler.getDomainInfo(domain)
        print(f"Domain info: {result}")

    def FD(self, device_query, limit=10):
        result = self.shodan_handler.findDevices(device_query, limit)
        print(f"Devices found: {result}")
    
    def GL(self, ip):
        result = self.shodan_handler.getGeolocation(ip)
        print(f"Geolocation: {result}")

    def AS(self):
        result = self.shodan_handler.getAccountStatus()
        print(f"Account status: {result}")

if __name__ == "__main__":
    Logger.setup_logger()
    load_dotenv()
    API_KEY = os.getenv("shodan_api_key")
    if not API_KEY: 
        logging.error("API key not found in .env variables!")
        exit("API key missing!")
    cli = CLI()
    args = cli.parse_arguments()
    app = Application(API_KEY)
    app.HI(args.ip_addr)
    app.OP(args.ip_addr)
    app.SV(args.query)
    app.DI(args.domain)
    app.FD(args.device_query)
    app.GL(args.ip_addr)
    app.AS()
