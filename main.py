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
        recon_btn = ctk.CTkButton(self.content_frame,text="Reconnaissance",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40)
        recon_btn.grid(row=1,column=0,padx=30,pady=0,sticky="n")
        scan_btn = ctk.CTkButton(self.content_frame,text="Scanning",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40)
        scan_btn.grid(row=1,column=1,padx=30,pady=0,sticky="n")
        self.tools = [
            "Banner Grabber", "Directory Enumeration", "DNS Enumeration", "Google Dork", "Header Grabber", 
            "JS File Analyzer", "Shodan Recon", "Subdomain Enumeration", "Web Scraper", "Web Status", "Whois"
        ]

        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        self.tool_lists.grid_columnconfigure(1, weight=1)
        for i, (name) in enumerate(self.tools):
            row = i % 6 if i < 6 else (i - 6) % 5 
            col = 0 if i < 6 else 1 
            programme_label = ctk.CTkLabel(self.tool_lists, text=name, font=("Arial", 15, "bold"))
            programme_label.grid(row=row * 2, column=col, padx=10, pady=(10, 0), sticky="n")
            btn = ctk.CTkButton(self.tool_lists, text="Start", command=lambda n=name: self.form(n),fg_color="#3C3D37")
            btn.grid(row=row * 2 + 1, column=col, padx=10, pady=(0, 10), sticky="n")
    
    def form(self,n):
        
        if n.lower() in ["banner grabber"]:
            self.framefortool()
            Label1 = ctk.CTkLabel(self.content_frame,text="Banner Grabber ",font=("arial",40,"bold"))
            Label1.grid(row=0,columnspan=2,padx=25, pady=10)
            ip_label = ctk.CTkLabel(self.content_frame, text="Enter IP Address:", font=("Arial", 16))
            ip_label.grid(row=1, column=0, padx=10, pady=(40,20), sticky="e")
            self.ip_entry = ctk.CTkEntry(self.content_frame, width=200)
            self.ip_entry.grid(row=1, column=1, padx=10, pady=(40,20), sticky="w")
            port_label = ctk.CTkLabel(self.content_frame, text="Enter Port:", font=("Arial", 16))
            port_label.grid(row=2, column=0, padx=10, pady=(40,20), sticky="e")
            self.port_entry = ctk.CTkEntry(self.content_frame, width=200)
            self.port_entry.grid(row=2, column=1, padx=10, pady=(40,20), sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan")  #command=self.start_banner_grabber)
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
            self.url_entry = ctk.CTkEntry(self.content_frame, width=200)  # Keep reference using self.
            self.url_entry.grid(row=1, column=1, padx=10, pady=(30,20), sticky="w")
            cookie_label = ctk.CTkLabel(self.content_frame,text="Enter Cookie : ",font=('arial',16,"bold"))
            cookie_label.grid(row=2,column=0,padx=10,pady=(30,20),sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.cookie_entry.grid(row=2,column=1,padx=10,pady=(30,20),sticky="w")
            th_label =ctk.CTkLabel(self.content_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=3,column=0,padx=10,pady=(30,20),sticky="e")
            self.th_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.th_entry.grid(row=3,column=1,padx=10,pady=(30,20),sticky="w")
            u_agent = ctk.CTkLabel(self.content_frame,text="User agent :",font=("arial",16,"bold"))
            u_agent.grid(row=4,column=0,padx=10,pady=(30,20),sticky="e")
            self.agent_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.agent_entry.grid(row=4,column=1,padx=10,pady=(30,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=5,column=0,padx=10,pady=(30,20),sticky="e")
            self.word_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.word_entry.grid(row=5,column=1,padx=10,pady=(30,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan")  #command=self.start_banner_grabber)
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
            domain_entry = ctk.CTkEntry(self.content_frame,width=200)
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            th_label =ctk.CTkLabel(self.content_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=3,column=0,padx=10,pady=(30,20),sticky="e")
            self.th_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.th_entry.grid(row=3,column=1,padx=10,pady=(30,20),sticky="w")
            word_label = ctk.CTkLabel(self.content_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=4,column=0,padx=10,pady=(30,20),sticky="e")
            self.word_entry = ctk.CTkEntry(self.content_frame,width=200)
            self.word_entry.grid(row=4,column=1,padx=10,pady=(30,20),sticky="w")
            submit_button = ctk.CTkButton(self.content_frame, text="Start Scan")  #command=self.start_banner_grabber)
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
        if n.lower() in ["header grabber"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Header Grabber",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["js file analyzer"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="JS File Analyzer",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["shodan recon"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Shodan Reconnaissance",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["subdomain enumeration"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Sub Domain Enumeration",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["web scrapper"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Web Scapper",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["web status"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="Web Status",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   
        if n.lower() in ["whois"]: 
            self.framefortool()
            url_label = ctk.CTkLabel(self.content_frame,text="WHO IS",font=("arial",40,"bold"))
            url_label.grid(row=1,columnspan=2,padx=25, pady=10)   


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