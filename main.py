import pyfiglet
from src.reconnaissance.shodan_recon import ShodanHandler
from src.reconnaissance.dir_enum import Application as dApp
import argparse
from colorama import Fore, Style
from tabulate import tabulate

def main():
    try:
        print(f"{Fore.GREEN}     ____                      ,")
        print(f"{Fore.GREEN}    /---.'.__             ____//")
        print(f"{Fore.GREEN}         '--.\\           /.---'")
        print(f"{Fore.GREEN}    _______  \\\\         //")
        print(f"{Fore.GREEN}  /.------.\\  \\|      .'/  ______")
        print(f"{Fore.GREEN} //  ___  \\ \\ ||/|\\  //  _/_----.\\__")
        print(f"{Fore.GREEN}|/  /.-.\\  \\ \\:|< >|// _/.'..\\   '--'")
        print(f"{Fore.GREEN}   //   \\' | \\'|.'/ /_/ /  \\\\")
        print(f"{Fore.GREEN}  //     \\ \\_\\/\\\" ' ~\\-'.-'    \\\\")
        print(f"{Fore.GREEN} //       '-._| :H: |'-.__     \\\\")
        print(f"{Fore.GREEN}//           (/==='\\)'-._\\     ||")  
        print(f"{Fore.GREEN}||                        \\\\    \\|")
        print(f"{Fore.GREEN}||                         \\\\    '")
        print(f"{Fore.GREEN}|/                          \\\\")
        print(f"{Fore.GREEN}                              ||")
        print(f"{Fore.GREEN}                              ||{Style.RESET_ALL}")

        banner = pyfiglet.figlet_format("SpiderScan", font="slant")
        print(f"{Fore.RED}{banner}{Style.RESET_ALL}")

        data = [
            [f"{Fore.GREEN}[+] Banner Grabber", f"{Fore.GREEN}[+] Nmap Scan"],
            [f"{Fore.GREEN}[+] Directory Enumeration", f"{Fore.GREEN}[+] SQL Injection"],
            [f"{Fore.GREEN}[+] DNS Enumeration", f"{Fore.GREEN}[+] CSRF testing"],
            [f"{Fore.GREEN}[+] Domain & Subdomain Enumeration", f"{Fore.GREEN}[+] API Testing"],
            [f"{Fore.GREEN}[+] Header Recon", f"[+] Broken Authentication and Session Security Tester"],
            [f"{Fore.GREEN}[+] Shodan Recon", f"[+] XSS test"],
            [f"{Fore.GREEN}[+] WHOIS Recon",f"[+] Insecure direct object reference(IDOR) test" ],
            [f"{Fore.GREEN}[+] JS File Analyzer", ""],
            [f"{Fore.GREEN}[+] Wayback Scraper", ""],
            [f"{Fore.GREEN}[+] Google Dork", ""],
            [f"{Fore.GREEN}[+] Website status",""]
        ] 
        print(tabulate(data, headers=[f"{Fore.CYAN}[i] Reconnaissance", f"{Fore.CYAN}[i] Scanning"], tablefmt="grid"))
        opt = input('Choose an option: ') 

    except KeyboardInterrupt as ke:
        print(f"{Fore.RED}[-] {ke}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    try: 
        parser = argparse.ArgumentParser(description="[1] Reconnaissance tools [2] Scanning tools")
        main()
    except KeyboardInterrupt as ke: 
        print(f"[-] {ke}")
    
    except Exception as e:
        print(f"[-] Error: {e}")
