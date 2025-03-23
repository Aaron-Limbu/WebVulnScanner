import customtkinter as ctk
from tkinter import messagebox
from dotenv import load_dotenv
import requests
import os

load_dotenv()
# Initialize main app
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

APP_URL = os.getenv("APP_URL")

class AuthApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("800x600")
        self.resizable(False,False)
        self.main_frame = ctk.CTkFrame(self,corner_radius=0)
        self.main_frame.pack(expand=True)  
        self.frame_login = None
        self.frame_register = None   
        self.show_login()  
        self.headers={"Content-Type":"application/json"}

    def show_login(self):
        self.title("Login ")
        if self.frame_register:
            self.frame_register.destroy()
        self.frame_login = ctk.CTkFrame(self.main_frame)
        self.frame_login.pack(pady=40, padx=40)
        ctk.CTkLabel(self.frame_login, text="Login", font=("Arial", 20)).pack(pady=20)
        self.login_email = ctk.CTkEntry(self.frame_login, placeholder_text="Email", width=300, height=40)
        self.login_email.pack(pady=10)
        self.login_password = ctk.CTkEntry(self.frame_login, placeholder_text="Password", show="*", width=300, height=40)
        self.login_password.pack(pady=10)
        login_btn = ctk.CTkButton(self.frame_login, text="Login", width=300, height=40, command=self.login_action)
        login_btn.pack(pady=10)
        switch_to_register = ctk.CTkButton(self.frame_login, text="Register", fg_color="transparent",command=self.show_register,width=300, height=40)
        switch_to_register.pack(pady=5)

    def show_register(self):
        self.title("Register")
        self.frame_login.destroy()
        self.frame_register = ctk.CTkFrame(self.main_frame)
        self.frame_register.pack(pady=20, padx=40)
        ctk.CTkLabel(self.frame_register, text="Register", font=("Arial", 20)).pack(pady=20)
        self.reg_username = ctk.CTkEntry(self.frame_register, placeholder_text="Username", width=300, height=40)
        self.reg_username.pack(pady=10)
        self.reg_email = ctk.CTkEntry(self.frame_register, placeholder_text="Email", width=300, height=40)
        self.reg_email.pack(pady=10)
        self.reg_password = ctk.CTkEntry(self.frame_register, placeholder_text="Password", show="*", width=300, height=40)
        self.reg_password.pack(pady=10)
        self.reg_password2 = ctk.CTkEntry(self.frame_register, placeholder_text="Re-type password", show="*", width=300, height=40)
        self.reg_password2.pack(pady=10)
        register_btn = ctk.CTkButton(self.frame_register, text="Register", width=300, height=40, command=self.register_action)
        register_btn.pack(pady=10)
        switch_to_login = ctk.CTkButton(self.frame_register, text="Back to Login", fg_color="transparent",width=300, height=40, command=self.show_login)
        switch_to_login.pack(pady=5)

    def login_action(self):
        try: 
            email = self.login_email.get()
            password = self.login_password.get()
            response = requests.post(f"{APP_URL}/login",json={"email":email,"password":password},headers=self.headers)
            if response.status_code == 200:                
                messagebox.showinfo("Login Successful", "Welcome back!")
                self.frame_login.destroy()
                self.withdraw()
                dash_win= Dash()
                dash_win.mainloop()
                
            else:
                messagebox.showerror("Login Failed", "Invalid email or password")
        except KeyboardInterrupt : 
            print("[i] Keyboard Interrupted")
        except requests.RequestException as re: 
            messagebox.showerror("Error",re)
        except Exception as e: 
            print("[!] Error: ",e)

    def register_action(self):
        try:
            username = self.reg_username.get()
            email = self.reg_email.get()
            password = self.reg_password.get()
            password2 = self.reg_password2.get()
            response = requests.post(f"{APP_URL}/register",json={"username":username,"email":email,"password":password,"password-confirmation":password2},headers=self.headers)
            if response.status_code == 201:
                messagebox.showinfo("Registration Successful", "You can now log in!")
                self.show_login()
            else:
                messagebox.showerror("Registration Failed", "All fields are required!")
        except requests.RequestException as re: 
            messagebox.showerror("Error",re)

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
        self.tools = [
            "Banner Grabber", "Directory Enumeration", "DNS Enumeration", "Google Dork", "Header Grabber", 
            "JS File Analyzer", "Shodan Recon", "Subdomain Enumeration", "Web Scraper", "Web Status", "Whois"
        ]
        self.tools2 = [
           "API Authentication Scanning","API testing","Bruteforce","Command Injection","CSRF scanning",
           "IDOR scan","LFI scan","NMAP scan","SQL Injection(Error based)","SSRF scan","XEE scan","XSS scan"
        ]

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
    # recon tools list
    def recon_tools(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        label1 = ctk.CTkLabel(self.content_frame,text="Recon Tools",font=("Arial",40,"bold"),text_color="white")
        label1.grid(row=0,column=0,columnspan=2,pady=(20,5),sticky="n")
        tools_menu= ctk.CTkButton(self.content_frame,text="Tools menu",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",20,"bold"),height=40,command=self.show_tools)
        tools_menu.grid(row=1,columnspan=2,padx=10,pady=0,sticky="n")
        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        for i, (name) in enumerate(self.tools):
            btn = ctk.CTkButton(self.tool_lists, text=name,corner_radius=30,font=("arial",22,"bold"),command=lambda n=name: self.form(n),border_color="#3C3D37",border_width=6,fg_color="transparent",hover_color="#3C3D37",height=50,width=500)
            btn.grid(row=i* 2 + 1, columnspan=2, padx=10, pady=(20, 20), sticky="n")
    # scanning tools button list
    def scanning_tools(self):
        if self.content_frame: 
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        label1 = ctk.CTkLabel(self.content_frame,text="Recon Tools",font=("Arial",40,"bold"),text_color="white")
        label1.grid(row=0,column=0,columnspan=2,pady=(20,5),sticky="n")
        tools_menu= ctk.CTkButton(self.content_frame,text="Tools menu",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",20,"bold"),height=40,command=self.show_tools)
        tools_menu.grid(row=1,columnspan=2,padx=10,pady=0,sticky="n")
        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        for i, (name) in enumerate(self.tools2):
            btn = ctk.CTkButton(self.tool_lists, text=name,corner_radius=30,font=("arial",22,"bold"),command=lambda n=name: self.form(n),border_color="#3C3D37",border_width=6,fg_color="transparent",hover_color="#3C3D37",height=50,width=500)
            btn.grid(row=i* 2 + 1, columnspan=2, padx=10, pady=(20, 20), sticky="n")
    
    # tools pages 
    def form(self,n):       
        if n.lower() in ["banner grabber"]:
            self.framefortool("Banner Grabber")
            ip_label = ctk.CTkLabel(self.content_frame, text="Enter IP Address:", font=("Arial", 16))
            ip_label.grid(row=2, column=0, padx=10, pady=(40,20), sticky="e")
            self.ip_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))
            self.ip_entry.grid(row=2, column=1, padx=10, pady=(40,20), sticky="w")
            port_label = ctk.CTkLabel(self.content_frame, text="Enter Port:", font=("Arial", 16))
            port_label.grid(row=3, column=0, padx=10, pady=(40,20), sticky="e")
            self.port_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))
            self.port_entry.grid(row=3, column=1, padx=10, pady=(40,20), sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=5,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["directory enumeration"]: 
            self.framefortool("Directory Enumeration")
            url_label1 = ctk.CTkLabel(self.content_frame, text="Enter URL:", font=("Arial", 16))
            url_label1.grid(row=2, column=0, padx=10, pady=(30,20), sticky="e")
            self.url_entry = ctk.CTkEntry(self.content_frame,width=250,height=40,font=("Arial",18))  # Keep reference using self.
            self.url_entry.grid(row=2, column=1, padx=10, pady=(30,20), sticky="w")
            cookie_label = ctk.CTkLabel(self.content_frame,text="Enter Cookie : ",font=('arial',16,"bold"))
            cookie_label.grid(row=3,column=0,padx=10,pady=(30,20),sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.cookie_entry.grid(row=3,column=1,padx=10,pady=(30,20),sticky="w")
            th_label =ctk.CTkLabel(self.content_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=4,column=0,padx=10,pady=(30,20),sticky="e")
            self.th_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.th_entry.grid(row=4,column=1,padx=10,pady=(30,20),sticky="w")
            u_agent = ctk.CTkLabel(self.content_frame,text="User agent :",font=("arial",16,"bold"))
            u_agent.grid(row=5,column=0,padx=10,pady=(30,20),sticky="e")
            self.agent_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.agent_entry.grid(row=5,column=1,padx=10,pady=(30,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=6,column=0,padx=10,pady=(30,20),sticky="e")
            self.word_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            self.word_entry.grid(row=6,column=1,padx=10,pady=(30,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=7, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=8,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))

        if n.lower() in ["dns enumeration"]: 
            self.framefortool("DNS Enumeration")  
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
            self.framefortool("Google Dork")
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
            self.framefortool("Header Grabber")
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
            self.framefortool("JS File Analyzer")
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
            self.framefortool("Subdomain Enumeration")
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
            self.framefortool("Web Scraper")
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
            self.framefortool("Web Status")
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
            self.framefortool("Whois")
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
            self.framefortool("API Authentication Scanning")
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
            self.framefortool("API testing")
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
            self.framefortool("Bruteforce")
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
        
        if n.lower() in ["command injection"]:
            self.framefortool("Command Injection")
            domain_label = ctk.CTkLabel(self.content_frame,text="Enter Domain : ", font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.content_frame,width=250,font=("arial",18))
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            param_label = ctk.CTkLabel(self.content_frame, text="Specific parameter:", font=("arial", 16, "bold"))
            param_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            self.param_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.param_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.content_frame, text="HTTP method:", font=("arial", 16, "bold"))
            method_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            self.method_var = ctk.StringVar(self.content_frame)  
            self.method_var.set("GET") 
            methods = ["GET", "POST"]
            self.method_dropdown = ctk.CTkOptionMenu(self.content_frame, variable=self.method_var, values=methods)
            self.method_dropdown.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            header_label = ctk.CTkLabel(self.content_frame, text="Custom headers:", font=("arial", 16, "bold"))
            header_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            self.header_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.header_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.content_frame, text="Session cookies:", font=("arial", 16, "bold"))
            cookie_label.grid(row=6, column=0, padx=10, pady=(10, 10), sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.cookie_entry.grid(row=6, column=1, padx=10, pady=(10, 10), sticky="w")
            delay_label = ctk.CTkLabel(self.content_frame, text="Delay (seconds):", font=("arial", 16, "bold"))
            delay_label.grid(row=7, column=0, padx=10, pady=(10, 10), sticky="e")
            self.delay_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.delay_entry.grid(row=7, column=1, padx=10, pady=(10, 10), sticky="w")
            wordlist_label = ctk.CTkLabel(self.content_frame, text="Path to wordlist:", font=("arial", 16, "bold"))
            wordlist_label.grid(row=9, column=0, padx=10, pady=(10, 10), sticky="e")
            self.wordlist_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.wordlist_entry.grid(row=9, column=1, padx=10, pady=(10, 10), sticky="w")
            threads_label = ctk.CTkLabel(self.content_frame, text="Number of threads:", font=("arial", 16, "bold"))
            threads_label.grid(row=10, column=0, padx=10, pady=(10, 10), sticky="e")
            self.threads_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.threads_entry.grid(row=10, column=1, padx=10, pady=(10, 10), sticky="w")
            filter_label = ctk.CTkLabel(self.content_frame, text="Keyword filter:", font=("arial", 16, "bold"))
            filter_label.grid(row=11, column=0, padx=10, pady=(10, 10), sticky="e")
            self.filter_entry = ctk.CTkEntry(self.content_frame, width=250, font=("arial", 18))
            self.filter_entry.grid(row=11, column=1, padx=10, pady=(10, 10), sticky="w")
            encoding_label = ctk.CTkLabel(self.content_frame, text="Encoding:", font=("arial", 16, "bold"))
            encoding_label.grid(row=12, column=0, padx=10, pady=(10, 40), sticky="e")
            encodings = ["base64", "hex", "url", "double-url", "none"]
            self.encoding_dropdown = ctk.CTkOptionMenu(self.content_frame,values=encodings)
            self.encoding_dropdown.grid(row=12, column=1, padx=10, pady=(10, 40), sticky="w")
            submit_button = ctk.CTkButton(self.content_frame,text="Start Scan",font=("arial",20),width=400, height=40)  #command=self.start_banner_grabber)
            submit_button.grid(row=13, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=14,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"))
            log_label.grid(row=0,columnspan=2,pady=(20,5))
        
        if n.lower() in ["csrf scanning"]:
            self.framefortool("CSRF scanning")
            url_label = ctk.CTkLabel(self.content_frame,text="CSRF scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["idor scan"]:
            self.framefortool("IDOR scan")
            url_label = ctk.CTkLabel(self.content_frame,text="IDOR scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["lfi scan"]:
            self.framefortool("LFI scan")
            url_label = ctk.CTkLabel(self.content_frame,text="LFI scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["nmap scan"]:
            self.framefortool("NMAP scan")
            url_label = ctk.CTkLabel(self.content_frame,text="NMAP scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["sql injection(error based)"]:
            self.framefortool("SQL Injection(Error based)")
            url_label = ctk.CTkLabel(self.content_frame,text="SQL Injection",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["ssrf scan"]:
            self.framefortool("SSRF scan")
            url_label = ctk.CTkLabel(self.content_frame,text="SSRF scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["xee scan"]:
            self.framefortool("XEE scan")
            url_label = ctk.CTkLabel(self.content_frame,text="XEE scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        if n.lower() in ["xss scan"]:
            self.framefortool("XSS scan")
            url_label = ctk.CTkLabel(self.content_frame,text="XSS scan",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10) 
        

    def framefortool(self,title):
        if hasattr(self, "content_frame") and self.content_frame:  
            self.content_frame.destroy()
        self.content_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="#1e1e1e")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5,20), pady=20)
        self.content_frame.grid_columnconfigure(0,weight=1)
        self.content_frame.grid_columnconfigure(1,weight=1)
        url_label = ctk.CTkLabel(self.content_frame,text=title,font=("arial",40,"bold"))
        url_label.grid(row=0,columnspan=2,padx=25, pady=10) 
        if title in self.tools:
            recon_btn = ctk.CTkButton(self.content_frame,text="Reconnaissance",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40,command=self.recon_tools)
            recon_btn.grid(row=1,columnspan=2,padx=30,pady=0,sticky="n")
 
        if title in self.tools2:
            scan_btn = ctk.CTkButton(self.content_frame,text="Scanning",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40,command=self.scanning_tools)
            scan_btn.grid(row=1,columnspan=2,padx=30,pady=0,sticky="n")

if __name__ == "__main__": 
    try: 
        app = Dash()
        app.mainloop()
    except KeyboardInterrupt as ke : 
        print(f"[!] Keyboard Interrupt")
    except Exception as e : 
        print(f"[!] Error: {e}")