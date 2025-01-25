import pyfiglet
from src.reconnaissance.shodan_recon import ShodanHandler
from src.reconnaissance.dir_enum import Application as dApp
import argparse
from colorama import Fore, Style

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

        print(f"{Fore.RED}[1] reconnaissance\t\t\t [2] scanning{Style.RESET_ALL}")
        print(f"{Fore.RED}[+] banner grabber \t\t\t [+] nmap scan\n[+] directory enumeration\t\t [+] SQL injection\n[+] DNS enumeration\n[+] Domain and subdomain enumeration\n[+] Header recon\n[+] Shodan recon\n[+] whois recon\n[+] js file analyzer\n[+] Wayback scraper\n[+] Google dork\n{Style.RESET_ALL}")


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
