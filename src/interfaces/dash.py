import customtkinter as ctk
from tkinter import messagebox

class Dash(ctk.CTk): 
    def __init__(self):
        super().__init__()
        self.geometry("800x600")
        self.title("Spiderscan")
        self.resizable(False,False)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1,weight=1)
        self.grid_rowconfigure(0,weight=1)
        self.content_frame=None
        self.show_sidebar()
        self.show_content()
    
    def show_sidebar(self): 
        self.sidebar = ctk.CTkFrame(self,corner_radius=10,width=150,fg_color="transparent")
        self.sidebar.grid(row=0,column=0,sticky="ns",padx=20,pady=20)
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0,weight=1)
        label1 = ctk.CTkLabel(self.sidebar,text="Overview",font=("Arial",18))
        label1.grid(row=0,column=0,padx=10,pady=10,sticky="ew")
        home_btn = ctk.CTkButton(self.sidebar,text="Home",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_content,height=30,width=200)
        home_btn.grid(row=1,column=0,padx=10,pady=10)
        UH_btn = ctk.CTkButton(self.sidebar,text="Programmes",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_programmes,height=30,width=200)
        UH_btn.grid(row=2,column=0,padx=10,pady=10)
        tools_btn = ctk.CTkButton(self.sidebar,text="Tools",font=("Arial",14),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_tools,height=30,width=200 )
        tools_btn.grid(row=3,column=0,padx=10,pady=10)
        label2 = ctk.CTkLabel(self.sidebar,text="Logging",font=("Arial",18))
        label2.grid(row=4,column=0,padx=10,pady=10,sticky="ew")
        log_btn = ctk.CTkButton(self.sidebar,text="URL Log",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200)
        log_btn.grid(row=5,column=0,padx=10,pady=10)
        log_btn2 = ctk.CTkButton(self.sidebar,text="Export Log",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200)
        log_btn2.grid(row=6,column=0,padx=10,pady=10)
        label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",18))
        label3.grid(row=7,column=0,padx=10,pady=10,sticky="ew")
        toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200)
        toggl_btn.grid(row=8,column=0,padx=10,pady=10)

        clabel = ctk.CTkLabel(self.sidebar,text="Created by:\n Aaron Limbu",font=("Arial",10))
        clabel.grid(row=9,column=0,padx=10,pady=(80,10))
        # label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",20))
        # label3.grid(row=6,column=0,padx=10,pady=10,sticky="ew")
        # toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",font=("Arial",15))
        # toggl_btn.grid(row=7,column=0,padx=10,pady=10)

    def show_content(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1) 
        title_label = ctk.CTkLabel(self.content_frame,text="About this Application",font=("Arial",40,"bold"),text_color="white")
        title_label.grid(row=0,column=0,padx=10,pady=(20,5),sticky="n")
        sub_tlabel = ctk.CTkLabel(self.content_frame,text="Identify Web Vulnerabilities (OWASP TOP 10)",font=("Arial",20),text_color="#AAAAAA")
        sub_tlabel.grid(row=1,column=0,padx=10,pady=0,sticky="n")
        owasp_frame = ctk.CTkFrame(self.content_frame,fg_color="#252525",corner_radius=10)
        owasp_frame.grid(row=2,column=0,padx=20,pady=10,sticky="ew")
        owasp_text=ctk.CTkLabel(owasp_frame,
                                text="The OWASP Top 10 is a standard awareness document for developers and security professionals."
                                "It represents the most critical security risks to web applications.",
                                font=("Arial",15,),
                                text_color="white",
                                wraplength=500,
                                justify="left"
                                )
        owasp_text.pack(padx=10,pady=15)
        owasp_details = [
            (
                "1. Injection",
                "Injection Flaws, such as SQL, NoSQL and XSS occur when untrusted data is sent to a server, allowing attackers to execute unauthorized commands and access data."
            ),
            (
                "2 Broken Authentication",
                "Weak authentication mechanism allow attackers to compromise user crendentials, leading to unauthorize access, identity theft and system control."
            ),
            (
                "3 Sensitive Data Exposure",
                "Applications that fail to protect sensitive data(e.g. passwords, credit card info) using encryption or proper access controls leave data vulnerable to breaches"
            ),
            (
                "4 Security Misconfiguration",
                "Improper security settings, such as default credentials, open directories, or exposed debug modes, can lead to system compromises."
            ),
            (
                "5 Cross-Site Scripting (XSS)",
                "XSS vulnerabilities allow attackers to inject malicious scripts into web pages, affecting users by stealing credentials or modifying site content."
            ),
            (
                "6 Insecure Deserialization",
                "Flaws in deserialization allow attackers to execute remote code, escalate privileges, or cause denial-of-service attacks."
            ),
            (
                "7 Using Components with known vulnerabilities",
                "Libraries, frameworks and software modules with known security flaws can be exploited if not updated or patched."
            ),
            (
                "8 Insufficient Logging and Monitoring",
                "Lack of proper logging and real-time monitoring makes it difficult to detect breaches and respond effectively to security incidents."
            )
        ]
        owasp_frame2 = ctk.CTkScrollableFrame(self.content_frame,fg_color="transparent")
        owasp_frame2.grid(row=3,column=0,padx=20,pady=10,sticky="nsew")
        owasp_frame2.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(3,weight=1)
        for i,(title,description) in enumerate(owasp_details): 
            title_label = ctk.CTkLabel(
                owasp_frame2,
                text=title,
                font=("Arial",20,"bold"),
                text_color="#FFFFFF",
                wraplength=600
            )
            title_label.grid(row=i*2,column=0,padx=10,pady=(10,2),sticky="w")
            desc_label = ctk.CTkLabel(
                owasp_frame2,
                text=description,
                font=("Arial",15),
                text_color="#DDDDDD",
                wraplength=400,
                justify="left"
            )
            desc_label.grid(row=i*2+1,column=0,padx=15,pady=(0,10),sticky="w")
    
    def show_programmes(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        title_label = ctk.CTkLabel(self.content_frame,text="Programmes",font=("Arial",40,"bold"),text_color="white")
        title_label.grid(row=0,column=0,padx=30,pady=(20,5),sticky="n")
        sub_tlabel = ctk.CTkLabel(self.content_frame,text="List of Ongoing programmes",font=("Arial",20),text_color="#AAAAAA")
        sub_tlabel.grid(row=1,column=0,padx=30,pady=0,sticky="n")
        programmes = [
            ('test1', 'this is a test program'),
            ('test2','this is a test program 2')
        ]

        self.programme_list = ctk.CTkFrame(self.content_frame)
        self.programme_list.grid(row=2, column=0, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)

        nj = 0  # Initialize `nj` before the loop

        for i, (name, description) in enumerate(programmes):
            j = nj + 0  # This is unnecessary, just use `j = nj`

            programme_label = ctk.CTkLabel(self.programme_list, text=name, font=("Arial", 20, "bold"))
            programme_label.grid(row=i * 3, column=0, padx=10, pady=10)

            desc_label = ctk.CTkLabel(self.programme_list, text=description, font=("Arial", 15))
            desc_label.grid(row=i * 3 + 1, column=0, padx=10, pady=10)

            nj = j + 1  # Increment `nj`

            # Remove `value=nj`, it's not a valid parameter
            btn = ctk.CTkButton(self.programme_list, text="Start", command=lambda n=nj: print(f"Button {n} clicked"))
            btn.grid(row=i * 3 + 2, column=0, padx=10, pady=10)
            
        
    def show_tools(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        label1 = ctk.CTkLabel(self.content_frame,text="Python Tools",font=("Arial",40,"bold"),text_color="white")
        label1.grid(row=0,column=0,columnspan=2,pady=(20,5),sticky="n")
        recon_btn = ctk.CTkButton(self.content_frame,text="Reconnaissance",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40,command=self.recon_tools)
        recon_btn.grid(row=1,column=0,padx=30,pady=0,sticky="n")
        scan_btn = ctk.CTkButton(self.content_frame,text="Scanning",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40,command=self.scanning_tools)
        scan_btn.grid(row=1,column=1,padx=30,pady=0,sticky="n")
        recon_descriptions = {
            "Banner Grabber": "Fetches service banners from open ports to identify running software and versions.",
            "Directory Enumeration": "Finds hidden directories and files on a web server using wordlists.",
            "DNS Enumeration": "Extracts DNS records (A, CNAME, MX, TXT, etc.) to map a domain’s infrastructure.",
            "Google Dork": "Uses advanced Google search queries to find sensitive information exposed online.",
            "Header Grabber": "Retrieves HTTP headers from a website, revealing security configurations.",
            "JS File Analyzer": "Analyzes JavaScript files for API keys, sensitive data, and potential vulnerabilities.",
            "Shodan Recon": "Uses the Shodan search engine to gather information about exposed devices and services.",
            "Subdomain Enumeration": "Finds subdomains of a target domain to expand the attack surface.",
            "Web Scraper": "Extracts data from web pages using HTML parsing techniques.",
            "Web Status": "Checks whether a website is online or offline based on HTTP response codes.",
            "Whois": "Retrieves domain registration details, including owner, registrar, and expiration date."
        }
        scrollable_frame1 = ctk.CTkScrollableFrame(self.content_frame, width=500)
        scrollable_frame1.grid(row=2, columnspan=2, padx=10, pady=10, sticky="nsew")
        label2 = ctk.CTkLabel(scrollable_frame1,text="Reconnaissance tool list",font=("arial",20,"bold"))
        label2.grid(row=0,columnspan=2,padx=10,pady=10)
        tl = ctk.CTkLabel(scrollable_frame1,text="Tools",font=("arial",20,"bold"))
        tl.grid(row=1,column=0,padx=10,pady=10,sticky="w")
        dl = ctk.CTkLabel(scrollable_frame1,text="Tool Descriptions",font=("arial",20,"bold"))
        dl.grid(row=1,column=1,padx=10,pady=10,sticky="w")

        for row_index, (tool, description) in enumerate(recon_descriptions.items(),2):
            tool_label = ctk.CTkLabel(scrollable_frame1, text=tool, font=("Arial", 18, "bold"))
            tool_label.grid(row=row_index, column=0, padx=10, pady=10, sticky="w")

            desc_label = ctk.CTkLabel(scrollable_frame1, text=description, font=("Arial", 16), wraplength=300, justify="left")
            desc_label.grid(row=row_index, column=1, padx=0, pady=(20,10), sticky="w")
        scan_descriptions = {
            "API Authentication Scan":"Checks the security of API authentication mechanisms to ensure they resist unauthorized access attempts.",
            "API Testing":"Evaluates the functionality, security, and performance of APIs to ensure they meet expected standards and specifications.",
            "Bruteforce":"Attempts to discover valid credentials or sensitive information by systematically trying all possible combinations of passwords or inputs.",
            "Command Injection":"Tests for vulnerabilities that allow unauthorized execution of arbitrary commands on the server through user input fields.",
            "CSRF Scan":"Detects Cross-Site Request Forgery vulnerabilities, where unauthorized commands are transmitted from a user that the web application trusts.",
            "Insecure Direct Object Reference (IDOR)":"Identifies flaws where an application exposes direct references to internal objects such as files or database keys, allowing unauthorized access.",
            "Local File Inclusion (LFI)":"Checks for vulnerabilities that allow an attacker to include files on the server through the web application, potentially accessing sensitive files.",
            "Network Scan(nmap)": "Uses nmap to conduct network scans, identifying open ports, services running on those ports, and other vulnerabilities or misconfigurations.",
            "SQL Injection(Error based)":"Tests for SQL injection vulnerabilities by manipulating input to generate SQL errors, revealing the structure, content of the database or any other vulnerable database versions.",
            "Server Side Request Forgery (SSRF)":"Identifies vulnerabilities where an attacker can manipulate a server to send unauthorized requests to internal or external resources, potentially accessing sensitive information, internal services, or even exploiting cloud metadata endpoints.",
            "XML External Entity (XEE)":"Identifies vulnerabilities in XML processors that allow attackers to exploit external entities for unauthorized data access or server-side request forgery.",
            "Cross Site Scripting(XSS)":"Detects vulnerabilities where attackers inject malicious scripts into web pages viewed by other users, compromising their session data or executing unauthorized actions."
        }
        scrollable_frame2 = ctk.CTkScrollableFrame(self.content_frame,width=500)
        scrollable_frame2.grid(row=3,columnspan=2,padx=10,pady=10,sticky="nsew")
        label3 = ctk.CTkLabel(scrollable_frame2,text="Scanning tool list",font=("arial",20,"bold"))
        label3.grid(row=0,columnspan=2,padx=10,pady=10)
        tl2 = ctk.CTkLabel(scrollable_frame2,text="Tools",font=("arial",20,"bold"))
        tl2.grid(row=1,column=0,padx=10,pady=10,sticky="w")
        dl2 = ctk.CTkLabel(scrollable_frame2,text="Tool Descriptions",font=("arial",20,"bold"))
        dl2.grid(row=1,column=1,padx=10,pady=10,sticky="w")
        for r_i , (t,d) in enumerate(scan_descriptions.items(),2):
            t_l = ctk.CTkLabel(scrollable_frame2,text=t,font=("arial",18,"bold"),wraplength=250,justify="left")
            t_l.grid(row=r_i,column=0,padx=0,pady=10,sticky="w")
            d_l = ctk.CTkLabel(scrollable_frame2,text=d,font=("arial",16),wraplength=300,justify="left")
            d_l.grid(row=r_i,column=1,padx=(5,0),pady=(20,10),sticky="w")

    def recon_tools(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        label1 = ctk.CTkLabel(self.content_frame,text="Recon Tools",font=("Arial",40,"bold"),text_color="white")
        label1.grid(row=0,column=0,columnspan=2,pady=(20,5),sticky="n")
        
        self.tools = [
            "Banner Grabber", "Directory Enumeration", "DNS Enumeration", "Google Dork", "Header Grabber", 
            "JS File Analyzer", "Shodan Recon", "Subdomain Enumeration", "Web Scraper", "Web Status", "Whois"
        ]
        tools_menu= ctk.CTkButton(self.content_frame,text="Tools menu",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",20,"bold"),height=40,command=self.show_tools)
        tools_menu.grid(row=1,columnspan=2,padx=10,pady=0,sticky="n")
        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        for i, (name) in enumerate(self.tools):
            btn = ctk.CTkButton(self.tool_lists, text=name,corner_radius=30,font=("arial",22,"bold"),command=lambda n=name: self.form(n),border_color="#3C3D37",border_width=6,fg_color="transparent",hover_color="#3C3D37",height=50,width=500)
            btn.grid(row=i* 2 + 1, columnspan=2, padx=10, pady=(20, 20), sticky="n")
    
    def scanning_tools(self):
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        label1 = ctk.CTkLabel(self.content_frame,text="Recon Tools",font=("Arial",40,"bold"),text_color="white")
        label1.grid(row=0,column=0,columnspan=2,pady=(20,5),sticky="n")
        
        self.tools = [
           "API Authentication Scanning","API testing","Bruteforce","Command Injection","CSRF scanning","IDOR scan","LFI scan","nmap scan","SQL Injection(Error based)","XEE scan","XSS scan"
        ]
        tools_menu= ctk.CTkButton(self.content_frame,text="Tools menu",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",20,"bold"),height=40,command=self.show_tools)
        tools_menu.grid(row=1,columnspan=2,padx=10,pady=0,sticky="n")
        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        for i, (name) in enumerate(self.tools):
            btn = ctk.CTkButton(self.tool_lists, text=name,corner_radius=30,font=("arial",22,"bold"),command=lambda n=name: self.form(n),border_color="#3C3D37",border_width=6,fg_color="transparent",hover_color="#3C3D37",height=50,width=500)
            btn.grid(row=i* 2 + 1, columnspan=2, padx=10, pady=(20, 20), sticky="n")
    

    def form(self,n):       
        if n.lower() in ["banner grabber"]:
            self.framefortool()
            Label1 = ctk.CTkLabel(self.content_frame,text="Banner Grabber ",font=("arial",40,"bold"))
            Label1.grid(row=0,columnspan=2,padx=25, pady=10)
            ip_label = ctk.CTkLabel(self.content_frame, text="Enter IP Address:", font=("Arial", 16))
            ip_label.grid(row=1, column=0, padx=10, pady=(40,20), sticky="e")
            self.ip_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))
            self.ip_entry.grid(row=1, column=1, padx=10, pady=(40,20), sticky="w")
            port_label = ctk.CTkLabel(self.content_frame, text="Enter Port:", font=("Arial", 16))
            port_label.grid(row=2, column=0, padx=10, pady=(40,20), sticky="e")
            self.port_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))
            self.port_entry.grid(row=2, column=1, padx=10, pady=(40,20), sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["directory enumeration"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame, text="Directory Enumeration", font=("Arial", 40, "bold"))
            url_label.grid(row=0, columnspan=2, padx=25, pady=10)   
            url_label1 = ctk.CTkLabel(self.content_frame, text="Enter URL:", font=("Arial", 16))
            url_label1.grid(row=1, column=0, padx=10, pady=(30,20), sticky="e")
            self.url_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))  # Keep reference using self.
            self.url_entry.grid(row=1, column=1, padx=10, pady=(30,20), sticky="w")
            cookie_label = ctk.CTkLabel(self.content_frame,text="Enter Cookie : ",font=('arial',16,"bold"))
            cookie_label.grid(row=2,column=0,padx=10,pady=(30,20),sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.cookie_entry.grid(row=2,column=1,padx=10,pady=(30,20),sticky="w")
            th_label =ctk.CTkLabel(self.content_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=3,column=0,padx=10,pady=(30,20),sticky="e")
            self.th_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.th_entry.grid(row=3,column=1,padx=10,pady=(30,20),sticky="w")
            u_agent = ctk.CTkLabel(self.content_frame,text="User agent :",font=("arial",16,"bold"))
            u_agent.grid(row=4,column=0,padx=10,pady=(30,20),sticky="e")
            self.agent_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.agent_entry.grid(row=4,column=1,padx=10,pady=(30,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=5,column=0,padx=10,pady=(30,20),sticky="e")
            self.word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.word_entry.grid(row=5,column=1,padx=10,pady=(30,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=6, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["dns enumeration"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="DNS enumeration",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            th_label =ctk.CTkLabel(self.content_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=3,column=0,padx=10,pady=(30,20),sticky="e")
            self.th_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.th_entry.grid(row=3,column=1,padx=10,pady=(30,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=4,column=0,padx=10,pady=(30,20),sticky="e")
            self.word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.word_entry.grid(row=4,column=1,padx=10,pady=(30,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))


        if n.lower() in ["google dork"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Google Dork",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
            query_label = ctk.CTkLabel(self.content_frame,text="Enter Query : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            query_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            query_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            num_label = ctk.CTkLabel(self.content_frame,text="Number of results : ",font=("arial",16,"bold"))
            num_label.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e")
            num_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            num_entry.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["header grabber"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Header Grabber",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
            query_label = ctk.CTkLabel(self.content_frame,text="Enter Query : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            query_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            query_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=6,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["js file analyzer"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="JS Analyzer",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)
            query_label = ctk.CTkLabel(self.content_frame,text="Enter URL : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            query_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            query_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))


        if n.lower() in ["shodan recon"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Shodan Reconnaissance",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["subdomain enumeration"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Sub Domain Enumeration",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            th_label = ctk.CTkLabel(self.content_frame,text="Enter threads : ",font=("arial",16,"bold"))
            th_label.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e")
            th_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",20))
            th_entry.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=5,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["web scrapper"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Web Scapper",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["web status"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Web Status",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter Domain (for one): ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky=("w"))
            input_list = ctk.CTkLabel(self.content_frame,text="Enter File path(for multiple domain) : ",font=("arial",16,"bold"))
            input_list.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e")
            input_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            input_entry.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            output = ctk.CTkLabel(self.content_frame,text="Enter output file name : ",font=("arial",16,"bold"))
            output.grid(row=4,column=0,padx=10,pady=(40,20),sticky="e")
            output_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            output_entry.grid(row=4,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=6,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))


        if n.lower() in ["whois"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="WHO IS",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))
        if n.lower() in ["api authentication scanning"]:
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="API Authentication scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            user_name = ctk.CTkLabel(self.content_frame,text="Enter Username : ",font=("arial",18))
            user_name.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e" )
            u_entery = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            u_entery.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            pas_label = ctk.CTkLabel(self.content_frame,text="Enter dummy password : ",font=("arial",18,"bold"))
            pas_label.grid(row=4,column=0,padx=10,pady=(40,20),sticky="e")
            pas_entry  = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            pas_entry.grid(row=4,column=1,padx=10,pady=(40,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Enter wordlist path: ",font=("arial",18,"bold"))
            word_label.grid(row=5,column=0,padx=10,pady=(40,20),sticky="e")
            word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            word_entry.grid(row=5,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=6, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))
        
        if n.lower() in ["api testing"]:
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="API Testing",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            token_label = ctk.CTkLabel(self.content_frame,text="Enter Token : ",font=("arial",16,"bold"))
            token_label.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e")
            token_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            token_entry.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            thread_label = ctk.CTkLabel(self.content_frame,text="Enter Threads : ",font=("arial",18))
            thread_label.grid(row=4,column=0,padx=10,pady=(40,20),sticky="e")
            thread_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            thread_entry.grid(row=4,column=1,padx=10,pady=(40,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Enter wordlists : ",font=("arial",16,"bold"))
            word_label.grid(row=5,column=0,padx=10,pady=(40,20),sticky="e")
            word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            word_entry.grid(row=5,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=6, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))
        
        if n.lower() in ["bruteforce"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Bruteforce",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            user_name = ctk.CTkLabel(self.content_frame,text="Enter Username : ",font=("arial",16,"bold"))
            user_name.grid(row=3,column=0,padx=10,pady=(40,20),sticky="e")
            user_entry= ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            user_entry.grid(row=3,column=1,padx=10,pady=(40,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Enter wordlist path : ",font=("arial",16,"bold"))
            word_label.grid(row=4,column=0,padx=10,pady=(40,20),sticky="e")
            word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            word_entry.grid(row=4,column=1,padx=10,pady=(40,20),sticky="w")
            pu_label = ctk.CTkLabel(self.content_frame,text="Parameter username : ",font=("arial",16,"bold"))
            pu_label.grid(row=5,column=0,padx=10,pady=(40,20),sticky="e")
            pu_entry =ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            pu_entry.grid(row=5,column=1,padx=10,pady=(40,20),sticky="w")
            pp_label = ctk.CTkLabel(self.content_frame,text="Parameter password : ",font=("arial",16,"bold"))
            pp_label.grid(row=6,column=0,padx=10,pady=(40,20),sticky="e")
            pp_entry =ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            pp_entry.grid(row=6,column=1,padx=10,pady=(40,20),sticky="w")
            m_label =ctk.CTkLabel(self.content_frame,text="Method : ",font=("arial",16,"bold"))
            m_label.grid(row=7,column=0,padx=10,pady=(40,20),sticky="e")
            m_entry=ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            m_entry.grid(row=7,column=1,padx=10,pady=(40,20),sticky="w")
            thread_label= ctk.CTkLabel(self.content_frame,text="Enter thread : ",font=("arial",16,"bold"))
            thread_label.grid(row=8,column=0,padx=10,pady=(40,20),stick="e")
            thread_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            thread_entry.grid(row=8,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=9, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=10,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))


    def framefortool(self):
        if hasattr(self, "content_frame") and self.content_frame:  
            self.content_frame.destroy()
        self.content_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)


if __name__ == "__main__": 
    try: 
        app = Dash()
        app.mainloop()
    except KeyboardInterrupt as ke : 
        print(f"[!] Keyboard Interrupt")
    except Exception as e : 
        print(f"[!] Error: {e}")