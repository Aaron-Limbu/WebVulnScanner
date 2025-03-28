import threading
import sys
from src.GUI.process.log_update_callback import RedirectOutput
import os 

class VulnScanProcess:
    def __init__(self,url,username,password,wordlist_path,thread,tokens,cookies, useragent,http_method,headers,delay,keyword_filter,encoding, param_id1,param_id2,parameter,ip, ports,scan_argument,script,dns_rebinding,time_based,attack_type, target_file,log_update_callback,filename): 
        self.url =url
        self.username = username or "test"
        self.password = password or "test"
        self.wordlists = wordlist_path or ""
        self.log_update_callback = log_update_callback
        self.log_path = f"{os.getcwd()}\\logs\\{filename}.log"
        self.thread = thread or 1
        self.tokens = tokens 
        self.cookies = cookies or ""
        self.user_agent = useragent
        self.http_method = http_method
        self.headers= headers
        self.delay = delay
        self.keyword_filter = keyword_filter
        self.encoding = encoding
        self.param1 = param_id1
        self.param2 = param_id2
        self.parameter = parameter
        self.ip_addr = ip 
        if ports:
            try:
                self.port = [int(p.strip()) for p in ports.split(",") if p.strip()]
            except ValueError:
                self.port = []  # Default to empty list if invalid port input
        else:
            self.port = []
        self.scan_arguments =scan_argument
        self.script_scan =script
        self.dns_rebind = dns_rebinding
        self.time_based = time_based
        self.attack_type = attack_type
        self.target_file = target_file

    def _setup_output_redirection(self): 
        redirect_output = RedirectOutput(self.log_update_callback,self.log_path)
        sys.stdout = redirect_output
        sys.stderr = redirect_output
    
    def ApiAuthTest(self): 
        self._setup_output_redirection()
        from src.scanning.apiAuth import AuthTester as AT
        at = AT(self.url,self.username,self.password,self.wordlists)
        at_thread = threading.Thread(target=lambda: (at.run_tests(),sys.stdout.flush(),sys.stderr.flush()))
        at_thread.start()
    
    def ApiTest(self): 
        self._setup_output_redirection()
        from src.scanning.ApiTest import APIScanner as AP 
        ap = AP(self.url,self.tokens,self.wordlists,self.thread)
        ap_thread = threading.Thread(target=lambda:(ap.scan(),sys.stdout.flush(),sys.stderr.flush()))
        ap_thread.start()

    def Bruteforce(self): 
        self._setup_output_redirection()
        from src.scanning.Bruteforce import BruteForcer as BF
        bf = BF(self.url,self.username,self.wordlists,self.param1,self.param2,self.http_method,self.thread,self.keyword_filter)
        bf_thread = threading.Thread(target=lambda: (bf.start_attack(),sys.stdout.flush(),sys.stderr.flush()))
        bf_thread.start()

    def CommandInjection(self): 
        self._setup_output_redirection()
        from src.scanning.CmdInj import CommandInjectionTester as CI
        ci = CI(self.url,self.parameter,self.http_method,self.headers,self.cookies,self.delay,True,self.wordlists,self.thread,self.keyword_filter,self.encoding)
        ci_thread = threading.Thread(target=lambda:(ci.run_tests(),sys.stdout.flush(),sys.stderr.flush()))
        ci_thread.start()
    
    def CSRF(self): 
        self._setup_output_redirection()
        from src.scanning.CSRF import CSRFTester as CSRF
        csrf = CSRF(self.url,self.cookies,self.user_agent)
        csrf_thread = threading.Thread(target=lambda:(csrf.test_csrf_vulnerability(),csrf.test_csrf_token_reusability,csrf.test_referer_validation(),sys.stdout.flush(),sys.stderr.flush()))
        csrf_thread.start()
    
    def IDOR(self): 
        self._setup_output_redirection()
        from src.scanning.idor import IDORtest as I
        i = I(self.url,self.parameter,self.param1,self.param2,self.http_method,self.headers,self.cookies,True)
        i_thread = threading.Thread(target=lambda:(i.test_idor(),sys.stdout.flush(),sys.stderr.flush()))
        i_thread.start()

    def LFI (self): 
        self._setup_output_redirection()
        from src.scanning.LFI import LFIExploiter as LF
        lf = LF(self.url,self.parameter,self.encoding,self.cookies,self.headers,self.thread)
        lf_thread = threading.Thread(target=lambda:(lf.run(),sys.stdout.flush(),sys.stderr.flush()))
        lf_thread.start()

    def nmapscan(self): 
        self._setup_output_redirection()
        from src.scanning.nmap_scan import Applicationr as NP 
        np = NP(self.ip ,self.port,self.scan_arguments,self.script_scan)
        np_thread = threading.Thread(target=lambda:(np.run(),sys.stdout.flush(),sys.stderr.flush()))
        np_thread.start()
    
    def SQL_Injection(self): 
        self._setup_output_redirection()
        from src.scanning.sql_inj import SQLScanner as SQL 
        db_errors = {
        "MySQL": [
            "You have an error in your SQL syntax",
            "MySQL server version for the right syntax to use",
            "Warning: mysql_fetch_array()",
            "Warning: mysql_num_rows()",
            "supplied argument is not a valid MySQL result resource",
            "MySQL result index",
            "MySQL server has gone away",
            "Error: query failed",
            "Error: invalid SQL statement",
        ],
        "MSSQL": [
            "Microsoft SQL Native Client error",
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Warning: mssql_query()",
            "Warning: mssql_fetch()",
            "SQL Server driver",
            "Cannot insert duplicate key row",
            "Arithmetic overflow error",
            "Conversion failed when converting",
        ],
        "NoSQL": [
            "MongoError",
            "Command failed with error",
            "Unrecognized pipeline stage name",
            "BSONObj size must be between",
            "Error processing query",
            "Couchbase error",
            "Document not found",
            "Invalid query or key",
        ],
        "Oracle": [
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            "ORA-00936: missing expression",
            "Warning: oci_execute()",
            "ORA-01722: invalid number",
            "ORA-06550: line",
            "PLS-00103: Encountered the symbol",
            "ORA-00942: table or view does not exist",
        ],
        "Cross-Platform": [
            "SQL syntax error",
            "Warning: SQL",
            "Warning: PDO",
            "Prepared statement needs to be re-prepared",
            "General error: invalid SQL",
            "Division by zero in query",
            "Syntax error in query expression",
            "Database disk image is malformed",
            "Unknown column in field list",
         ],
        }
        sql = SQL(self.url, self.user_agent,db_errors,self.http_method,self.cookies)
        sql_thread = threading.Thread(target=lambda:(sql.run(),sys.stdout.flush(),sys.stderr.flush()))
        sql_thread.start()

    def SSRF(self): 
        self._setup_output_redirection()
        from src.scanning.SSRF import SSRFTester as RF
        rf = RF(self.url,self.parameter,self.http_method,self.cookies,self.delay,True,self.wordlists,self.dns_rebind,self.time_based)
        rf_thread =threading.Thread(target=lambda:(rf.run_tests(),sys.stdout.flush(),sys.stderr.flush()))
        rf_thread.start()

    def XEE(self): 
        self._setup_output_redirection()
        from src.scanning.XEE import XXEExploiter as XX
        xx = XX(self.url,self.http_method,self.headers,self.cookies,self.attack_type,self.target_file,self.encoding)
        xx_thread = threading.Thread(target= lambda: (xx.send_request(),sys.stdout.flush(),sys.stderr.flush()))
        xx_thread.start()

    def XSS(self): 
        self._setup_output_redirection()
        from src.scanning.XSS import XSSHandler as XS
        xs = XS(self.user_agent, self.cookies,self.url,self.thread)
        xs_thread = threading.Thread(target= lambda: (xs.scan(self.wordlists,sys.stdout.flush(),sys.stderr.flush())))
        xs_thread.start()