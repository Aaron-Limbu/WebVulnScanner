import customtkinter as ctk
from tkinter import messagebox
from dotenv import load_dotenv
import requests
import os
import json
import secrets

load_dotenv()
# Initialize main app
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

APP_URL = os.getenv("APP_URL")
# SESSION_FILE = "session.json"


# class AuthApp(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         self.geometry("800x600")
#         self.resizable(False,False)
#         self.main_frame = ctk.CTkFrame(self,corner_radius=0)
#         self.main_frame.pack(expand=True)  
#         self.frame_login = None
#         self.frame_register = None   
#         self.show_login()  
#         self.headers={"Content-Type":"application/json"}
        

#     def show_login(self):
#         self.title("Login ")
#         if self.frame_register:
#             self.frame_register.destroy()
#         self.frame_login = ctk.CTkFrame(self.main_frame)
#         self.frame_login.pack(pady=40, padx=40)
#         ctk.CTkLabel(self.frame_login, text="Login", font=("Arial", 20)).pack(pady=20)
#         self.login_email = ctk.CTkEntry(self.frame_login, placeholder_text="Email", width=300, height=40)
#         self.login_email.pack(pady=10)
#         self.login_password = ctk.CTkEntry(self.frame_login, placeholder_text="Password", show="*", width=300, height=40)
#         self.login_password.pack(pady=10)
#         login_btn = ctk.CTkButton(self.frame_login, text="Login", width=300, height=40, command=self.login_action)
#         login_btn.pack(pady=10)
#         switch_to_register = ctk.CTkButton(self.frame_login, text="Register", fg_color="transparent",command=self.show_register,width=300, height=40)
#         switch_to_register.pack(pady=5)

#     def show_register(self):
#         self.title("Register")
#         self.frame_login.destroy()
#         self.frame_register = ctk.CTkFrame(self.main_frame)
#         self.frame_register.pack(pady=20, padx=40)
#         ctk.CTkLabel(self.frame_register, text="Register", font=("Arial", 20)).pack(pady=20)
#         self.reg_username = ctk.CTkEntry(self.frame_register, placeholder_text="Username", width=300, height=40)
#         self.reg_username.pack(pady=10)
#         self.reg_email = ctk.CTkEntry(self.frame_register, placeholder_text="Email", width=300, height=40)
#         self.reg_email.pack(pady=10)
#         self.reg_password = ctk.CTkEntry(self.frame_register, placeholder_text="Password", show="*", width=300, height=40)
#         self.reg_password.pack(pady=10)
#         self.reg_password2 = ctk.CTkEntry(self.frame_register, placeholder_text="Re-type password", show="*", width=300, height=40)
#         self.reg_password2.pack(pady=10)
#         register_btn = ctk.CTkButton(self.frame_register, text="Register", width=300, height=40, command=self.register_action)
#         register_btn.pack(pady=10)
#         switch_to_login = ctk.CTkButton(self.frame_register, text="Back to Login", fg_color="transparent",width=300, height=40, command=self.show_login)
#         switch_to_login.pack(pady=5)

#     @staticmethod
#     def load_session():
#         """Load session token from JSON file."""
#         if os.path.exists(SESSION_FILE):
#             with open(SESSION_FILE, "r") as f:
#                 return json.load(f).get("token")
#         return None

#     @staticmethod
#     def save_session(token, role):
#         """Save session token and role to a JSON file."""
#         session_data = {"token": token, "role": role}
#         with open(SESSION_FILE, "w") as f:
#             json.dump(session_data, f)


#     def verify_session(self):
#         """Send request to server to verify session token."""
#         token = self.load_session()
#         if not token:
#             return False  # No stored token found, require login

#         headers = {"Authorization": token}
#         response = requests.get(f"{APP_URL}/verify", headers=headers)

#         if response.status_code == 200:
#             print("[+] Session verified successfully.")
#             return True
#         else:
#             print("[-] Invalid session, requiring new login.")
#             return False

#     def login_action(self):
#         try:
#             # Check if a valid session already exists
#             existing_token = self.load_session()
#             if existing_token:
#                 print("[+] Using existing session token.")
#                 messagebox.showinfo("Already Logged In", "Session is still active.")
#                 return  # Skip login process if session is valid

#             email = self.login_email.get()
#             password = self.login_password.get()

#             response = requests.post(f"{APP_URL}/login", json={"email": email, "password": password}, headers=self.headers)

#             if response.status_code == 200:
#                 data = response.json()
#                 token = data.get("token")
#                 role = data.get("role")  # <- Make sure the server returns role

#                 if not token:
#                     print("[!] No token from server, generating a new one.")
#                     token = secrets.token_hex(32)

#                 self.save_session(token, role)  # Save both token and role

#                 messagebox.showinfo("Login Successful", f"Welcome back! Role: {role}")
#                 self.frame_login.destroy()
#                 self.withdraw()
#                 dash_win = Dash()
#                 dash_win.mainloop()
#             else:
#                 messagebox.showerror("Login Failed", "Invalid email or password")

#         except requests.RequestException as re:
#             messagebox.showerror("Error", str(re))
#         except Exception as e:
#             print("[!] Error:", e)

#     def register_action(self):
#         try:
#             username = self.reg_username.get().strip()
#             email = self.reg_email.get().strip()
#             password = self.reg_password.get()
#             password2 = self.reg_password2.get()
#             if not username or not email or not password or not password2:
#                 messagebox.showerror("Registration Failed", "All fields are required!")
#                 return

#             if password != password2:
#                 messagebox.showerror("Registration Failed", "Passwords do not match!")
#                 return
#             payload = {
#                 "username": username,
#                 "email": email,
#                 "password": password,
#                 "password-confirmation": password2
#             }
#             response = requests.post(f"{APP_URL}/register", json=payload, headers=self.headers)
#             if response.status_code == 201:
#                 messagebox.showinfo("Registration Successful", "You can now log in!")
#                 self.show_login()
#             else:
#                 try:
#                     error_msg = response.json().get("error", "Registration failed, please try again.")
#                 except json.JSONDecodeError:
#                     error_msg = "Registration failed, please check your input."

#                 messagebox.showerror("Registration Failed", error_msg)

#         except requests.RequestException as re: 
#             messagebox.showerror("Error", str(re))
#         except Exception as e:
#             print("[!] Error:", e)
#UI for Pentesters 
class Dash(ctk.CTk): 
    def __init__(self):
        super().__init__()
        self.geometry("800x650")
        self.title("Spiderscan")
        self.resizable(False,False)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1,weight=1)
        self.grid_rowconfigure(0,weight=1)
        self.content_frame=None
        self.box_frame = None
        self.show_sidebar()
        self.log_label = None
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
        # UH_btn = ctk.CTkButton(self.sidebar,text="Programmes",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_programmes,height=30,width=200)
        # UH_btn.grid(row=2,column=0,padx=10,pady=10)
        tools_btn = ctk.CTkButton(self.sidebar,text="Tools",font=("Arial",14),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_tools,height=30,width=200 )
        tools_btn.grid(row=3,column=0,padx=10,pady=10)
        label2 = ctk.CTkLabel(self.sidebar,text="Logging",font=("Arial",18))
        label2.grid(row=4,column=0,padx=10,pady=10,sticky="ew")
        log_btn = ctk.CTkButton(self.sidebar,text="URL Log",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200,command=self.tool_logs)
        log_btn.grid(row=5,column=0,padx=10,pady=10)
        # log_btn2 = ctk.CTkButton(self.sidebar,text="Export Log",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200)
        # log_btn2.grid(row=6,column=0,padx=10,pady=10)
        label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",18))
        label3.grid(row=7,column=0,padx=10,pady=10,sticky="ew")
        toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200,command=self.logout_action)
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
    
    # def show_programmes(self):
    #     if self.content_frame:
    #         self.content_frame.destroy()

    #     self.content_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="#1e1e1e", height=550, width=550)
    #     self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 20), pady=20)
    #     self.content_frame.grid_columnconfigure(0, weight=1)
    #     title_label = ctk.CTkLabel(self.content_frame, text="Dashboard", font=("Arial", 32, "bold"), text_color="white")
    #     title_label.grid(row=0, column=0, sticky="w", padx=20, pady=(10, 5))

    #     subheading = ctk.CTkLabel(self.content_frame, text="Pentesting Programmes Overview", font=("Arial", 16), text_color="#cccccc")
    #     subheading.grid(row=1, column=0, sticky="w", padx=20)

    #     programmes_frame = ctk.CTkFrame(self.content_frame, fg_color="#2e2e2e", corner_radius=10)
    #     programmes_frame.grid(row=2, column=0, padx=20, pady=20, sticky="nsew")
    #     programmes_frame.grid_columnconfigure(0, weight=1)  # Expand child cards

    #     token = self.load_session()
    #     programmes = []
    #     if token:
    #         try:
    #             res = requests.get(f"{APP_URL}/programmes", headers={"Authorization": token})
    #             if res.status_code == 200:
    #                 programmes = res.json()
    #             else:
    #                 print("Failed to fetch programmes:", res.json())
    #         except Exception as e:
    #             print("Error while fetching programmes:", e)

    #     if not programmes:
    #         empty_label = ctk.CTkLabel(programmes_frame, text="No programmes added.", font=("Arial", 14), text_color="#cccccc")
    #         empty_label.grid(row=0, column=0, padx=20, pady=20)
    #     else:
    #         for i, prog in enumerate(programmes):
    #             card = ctk.CTkFrame(programmes_frame, fg_color="#242424", corner_radius=16)
    #             card.grid(row=i, column=0, padx=10, pady=12, sticky="ew")
    #             card.grid_columnconfigure(0, weight=1)
    #             ctk.CTkLabel(
    #                 card, text=prog['programme_name'], font=("Segoe UI", 20, "bold"),
    #                 text_color="white"
    #             ).grid(row=0, column=0, sticky="w", padx=20, pady=(12, 4))
    #             ctk.CTkLabel(
    #                 card,text=f"Publisher: {prog['username']}",font=("Segoe UI",13),text_color="white"
    #             ).grid(row=0,column=1,sticky="w",padx=10,pady=(12,4))
    #             ctk.CTkLabel(
    #                 card, text=f"Domain Name: {prog['domain_name']}", font=("Segoe UI", 14),
    #                 text_color="#cccccc"
    #             ).grid(row=1, column=0, sticky="w", padx=20, pady=2)
    #             ctk.CTkLabel(
    #                 card, text=f"Scopes:", font=("Segoe UI", 13),
    #                 text_color="#aaaaaa"
    #             ).grid(row=2, column=0, sticky="w", padx=20, pady=2)
    #             ctk.CTkLabel(
    #                 card, text=f"{prog['scope']}", font=("Segoe UI", 13),
    #                 text_color="#aaaaaa"
    #             ).grid(row=3, columnspan=2, sticky="w", padx=50, pady=2)
    #             out_scope = prog.get('outofscope', '').strip()
    #             if out_scope:
    #                 ctk.CTkLabel(
    #                     card, text=f"Out of Scope: ", font=("Segoe UI", 13),
    #                     text_color="#999999"
    #                 ).grid(row=4, column=0, sticky="w", padx=20, pady=2)
    #                 ctk.CTkLabel(
    #                     card, text=f"{out_scope}", font=("Segoe UI", 13),
    #                     text_color="#999999"
    #                 ).grid(row=5, columnspan=2, sticky="w", padx=50, pady=2)
    #             ctk.CTkLabel(
    #                 card, text=f"{prog['start_date']} → {prog['end_date']}", font=("Segoe UI", 12),
    #                 text_color="#888888"
    #             ).grid(row=6, column=0, sticky="w", padx=20, pady=2)
    #             status_color = "#44cc66" if prog['status'] == "Completed" else "#ffaa00" if prog['status'] == "Pending" else "#00bfff"
    #             ctk.CTkLabel(
    #                 card, text=f"Status: {prog['status']}", font=("Segoe UI", 12, "bold"),
    #                 text_color=status_color
    #             ).grid(row=7, column=0, sticky="w", padx=20, pady=(4, 2))
    #             ctk.CTkLabel(
    #                 card, text=f"Created: {prog['created_at']}", font=("Segoe UI", 11),
    #                 text_color="#777777"
    #             ).grid(row=8, column=0, sticky="w", padx=20, pady=(0, 12))
    #             # Join Button
    #             join_button = ctk.CTkButton(
    #                 card, text="Join", font=("Segoe UI", 12, "bold"),
    #                 command=lambda prog_id=prog['id']: self.join_programme(prog_id),
    #                 fg_color="#007acc", hover_color="#005f99", text_color="white",
    #                 corner_radius=8, width=80
    #             )
    #             join_button.grid(row=9, column=1, sticky="e", padx=20, pady=(0, 12))
    #             joined_programme_id = self.get_joined_programme_id()

    #             if joined_programme_id == prog['id']:
    #                 feedback_button = ctk.CTkButton(
    #                     card, text="Report Feedback", font=("Segoe UI", 12, "bold"),
    #                     command=self.open_feedback_form,
    #                     fg_color="#66bb6a", hover_color="#4caf50", text_color="white",
    #                     corner_radius=8, width=140
    #                 )
    #                 feedback_button.grid(row=10, column=1, sticky="e", padx=20, pady=(0, 12))

    # def get_joined_programme_id(self):
    #     try:
    #         with open("session.json", "r") as f:
    #             data = json.load(f)
    #             return data.get("joined_programme_id")
    #     except:
    #         return None

    # def join_programme(self, programme_id):
    #     try:
    #         with open("session.json", "r") as f:
    #             session_data = json.load(f)
    #     except FileNotFoundError:
    #         session_data = {}

    #     session_data['joined_programme_id'] = programme_id

    #     with open("session.json", "w") as f:
    #         json.dump(session_data, f)

    #     ctk.CTkMessagebox.show_info("Joined", "Successfully joined the programme.")
    #     self.show_programmes()  # Refresh UI to show feedback button

    # def open_feedback_form(self):
    #     feedback_window = ctk.CTkToplevel(self)
    #     feedback_window.title("Submit Feedback")
    #     feedback_window.geometry("400x300")

    #     ctk.CTkLabel(feedback_window, text="Your Feedback:", font=("Segoe UI", 14)).pack(pady=10)
    #     feedback_entry = ctk.CTkTextbox(feedback_window, height=100)
    #     feedback_entry.pack(padx=20, pady=10, fill="both", expand=True)

    #     def submit_feedback():
    #         comment = feedback_entry.get("1.0", "end").strip()
    #         programme_id = self.get_joined_programme_id()
    #         token = self.load_session()

    #         if comment and programme_id:
    #             try:
    #                 res = requests.post(
    #                     f"{APP_URL}/feedback",
    #                     json={"programme_id": programme_id, "comment": comment},
    #                     headers={"Authorization": token}
    #                 )
    #                 if res.status_code == 201:
    #                     ctk.CTkMessagebox.show_info("Success", "Feedback submitted.")
    #                     feedback_window.destroy()
    #                 else:
    #                     ctk.CTkMessagebox.show_error("Error", f"Submission failed: {res.text}")
    #             except Exception as e:
    #                 ctk.CTkMessagebox.show_error("Error", str(e))
    #         else:
    #             ctk.CTkMessagebox.show_warning("Missing", "Feedback cannot be empty.")

    #     ctk.CTkButton(feedback_window, text="Submit", command=submit_feedback).pack(pady=10)

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
            t_l = ctk.CTkLabel(scrollable_frame2,text=t,font=("arial",18,"bold"),wraplength=300,justify="left")
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
    
    def get_files(self, directory):
        """Fetches the list of files from the given directory."""
        if not os.path.exists(directory):
            return ["No files found"]  # If directory doesn't exist
        return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

    def stop_scan():
        if app:  # Check if the scan is running
            app.stop()
    # tools pages 
    def form(self,n):       
        if n.lower() in ["banner grabber"]:
            self.framefortool("Banner Grabber")
            ip_label = ctk.CTkLabel(self.box_frame, text="Enter IP Address :", font=("Arial", 16))
            ip_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
            self.ip_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("Arial",16))
            self.ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")
            port_label = ctk.CTkLabel(self.box_frame, text="Enter Port :", font=("Arial", 16))
            port_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
            self.port_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("Arial",16))
            self.port_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
            submit_button = ctk.CTkButton(self.box_frame, text="Start Scan",
                                          font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=self.ip_entry.get(), port=self.port_entry.get(),wordlists=None,useragent=None,cookies=None,threads=None,n_result=None,output=None,input_list=None,tool="banner_grabber")) 
            submit_button.grid(row=2, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500, height=10)  # Set height
            log_frame.grid(row=3, columnspan=2, pady=10)
            log_frame.columnconfigure(0, weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["directory enumeration"]: 
            self.framefortool("Directory Enumeration")
            url_label1 = ctk.CTkLabel(self.box_frame, text="Enter URL:", font=("Arial", 16))
            url_label1.grid(row=2, column=0, padx=10, pady=10, sticky="e")
            self.url_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("Arial",16))  # Keep reference using self.
            self.url_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame,text="Enter Cookie : ",font=('arial',16,"bold"))
            cookie_label.grid(row=3,column=0,padx=10,pady=10,sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("arial",16))
            self.cookie_entry.grid(row=3,column=1,padx=10,pady=10,sticky="w")
            th_label =ctk.CTkLabel(self.box_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=4,column=0,padx=10,pady=10,sticky="e")
            self.th_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("arial",16))
            self.th_entry.grid(row=4,column=1,padx=10,pady=10,sticky="w")
            u_agent = ctk.CTkLabel(self.box_frame,text="User agent :",font=("arial",16,"bold"))
            u_agent.grid(row=5,column=0,padx=10,pady=10,sticky="e")
            self.agent_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("arial",16))
            self.agent_entry.grid(row=5,column=1,padx=10,pady=10,sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=6,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/directory_enumeration")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            # self.word_entry = ctk.CTkEntry(self.box_frame,width=300,height=40,font=("arial",16))
            self.word_entry.grid(row=6,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame, text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.recon_scan(url=self.url_entry.get(),cookies=self.cookie_entry.get(),
                                                                 wordlists= os.path.join("directory_enumeration", self.word_entry.get()),useragent=self.agent_entry.get(),threads=self.th_entry.get(),port="80",n_result=10  ,output=None,input_list=None,tool="dir_enum"))  
            submit_button.grid(row=7, columnspan=2, pady=15)
            # stop_button = ctk.CTkButton(self.box_frame,text="Stop Scan",font=("arial",20,"bold"),width=400,height=40,
            #                             command=)
            # stop_button.grid(row=7,column=1,pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500, height=10)  # Set height
            log_frame.grid(row=4, columnspan=2, pady=10)
            log_frame.columnconfigure(0, weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["dns enumeration"]: 
            self.framefortool("DNS Enumeration")  
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            th_label =ctk.CTkLabel(self.box_frame,text="Number of Threads : ",font=("arail",16,"bold"))
            th_label.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            self.th_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            self.th_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/dns_enum")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            self.word_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame, text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=domain_entry.get(),port="88",useragent=None,cookies=None,threads=th_entry.get(),wordlists=word_entry.get(),n_result=10,output=None,input_list=None,tool="dns_enum"))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")


        if n.lower() in ["google dork"]: 
            self.framefortool("Google Dork")
            query_label = ctk.CTkLabel(self.box_frame,text="Enter Query : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            query_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            query_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            num_label = ctk.CTkLabel(self.box_frame,text="Number of results : ",font=("arial",16,"bold"))
            num_label.grid(row=3,column=0,padx=10,pady=10,sticky="e")
            num_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            num_entry.grid(row=3,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame, text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=query_entry.get(),port=None,tool="google_dork",wordlists=None,useragent=None,cookies=None,threads=None,n_result=num_entry.get(),input_list=None,output=None))  
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=7,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["header grabber"]: 
            self.framefortool("Header Grabber")
            query_label = ctk.CTkLabel(self.box_frame,text="Enter URL : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            query_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            query_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=query_entry.get(), port=None,useragent=None,cookies=None,threads=None,wordlists=None,n_result=None,input_list=None,output=None ,tool="header_grabber"))  
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=6,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["js file analyzer"]: 
            self.framefortool("JS File Analyzer")
            query_label = ctk.CTkLabel(self.box_frame,text="Enter URL : ",font=("arial",16,"bold"))
            query_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            query_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            query_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,command=lambda: self.recon_scan(url=query_entry.get(),port=None,wordlists=None,useragent=None,cookies=None,threads=None,n_result=None,output=None,input_list=None,tool="js_file_analyzer"))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")


        if n.lower() in ["shodan recon"]: 
            self.framefortool("Shodan Recon")
            # ip_label = ctk.CTkLabel(self.box_frame, text="IP Address:", font=("arial", 16, "bold"))
            # ip_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
            # ip_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16), height=40)
            # ip_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
            # domain_label = ctk.CTkLabel(self.box_frame, text="Domain:", font=("arial", 16, "bold"))
            # domain_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")
            # domain_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16), height=40)
            # domain_entry.grid(row=3, column=1, padx=10, pady=5, sticky="w")
            # query_label = ctk.CTkLabel(self.box_frame, text="Search Query:", font=("arial", 16, "bold"))
            # query_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")
            # query_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16), height=40)
            # query_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")
            # device_label = ctk.CTkLabel(self.box_frame, text="Device Query:", font=("arial", 16, "bold"))
            # device_label.grid(row=5, column=0, padx=10, pady=5, sticky="e")
            # device_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16), height=40)
            # device_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")
            # submit_button = ctk.CTkButton(
            #     self.box_frame,
            #     text="Start Recon",
            #     font=("arial", 20, "bold"),
            #     width=400,
            #     height=40,
            #     command=lambda: self.recon_scan(
            #         url=domain_entry.get(),
            #         port=None,
            #         wordlists=None,
            #         useragent=None,
            #         cookies=None,
            #         threads=None,
            #         n_result=None,
            #         output=None,
            #         input_list=None,
            #         tool="shodan_recon",
            #         ip_addr=ip_entry.get(),
            #         domain=domain_entry.get(),
            #         query=query_entry.get(),
            #         device_query=device_entry.get(),
            #         status=None
            #     )
            # )
            # submit_button.grid(row=7, columnspan=2, pady=15)
            # log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            # log_frame.grid(row=8, columnspan=2, pady=(20, 5))
            # log_frame.columnconfigure(0, weight=1)
            # self.log_label = ctk.CTkLabel(log_frame, text="Script Log", font=("arial", 20, "bold"), justify="left", anchor="w")
            # self.log_label.grid(row=0, columnspan=2, padx=20, pady=(20, 5), sticky="w")


        if n.lower() in ["subdomain enumeration"]: 
            self.framefortool("Subdomain Enumeration")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            th_label = ctk.CTkLabel(self.box_frame,text="Enter threads : ",font=("arial",16,"bold"))
            th_label.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            th_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            th_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=domain_entry.get(),port=None,wordlists=None,useragent=None,cookies=None,threads=th_entry.get(),n_result=None,output=None,input_list=None,tool="subdomain_enum"))  
            submit_button.grid(row=2, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=5,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["web scraper"]: 
            self.framefortool("Web Scraper")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=url_entry.get(),port=None,wordlists=None,useragent=None,cookies=None,threads=None,n_result=None,output=None,input_list=None,tool="web_scraper"))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["web status"]: 
            self.framefortool("Web Status")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter Domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky=("w"))
            input_list = ctk.CTkLabel(self.box_frame,text="Enter File path : ",font=("arial",16,"bold"))
            input_list.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            input_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            input_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            output = ctk.CTkLabel(self.box_frame,text="Output filename : ",font=("arial",16,"bold"))
            output.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            output_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            output_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command= lambda: self.recon_scan(url=domain_entry.get(),port=None,wordlists=word_entry.get(),useragent=None,cookies=None,threads=None,n_result=None,output=output_entry.get(),input_list=input_entry.get(),tool="web_status"))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=6,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")


        if n.lower() in ["whois"]: 
            self.framefortool("Whois")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter domain : ",font=("arial",16,"bold"))
            domain_label.grid(row=2,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=2,column=1,padx=10,pady=(40,20),sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.recon_scan(url=domain_entry.get(),port=None,wordlists=None,useragent=None,cookies=None,threads=None,n_result=None,output=None,input_list=None,tool="who_is"))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=4,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
        if n.lower() in ["api authentication scanning"]:
            self.framefortool("API Authentication Scanning")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            user_name = ctk.CTkLabel(self.box_frame,text="Enter Username : ",font=("arial",16))
            user_name.grid(row=1,column=0,padx=10,pady=10,sticky="e" )
            u_entery = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            u_entery.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            pas_label = ctk.CTkLabel(self.box_frame,text="Enter password : ",font=("arial",16))
            pas_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            pas_entry  = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            pas_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=3,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/Api_auth_scan")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            self.word_entry.grid(row=3,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.vuln_scan(
                                              url=domain_entry.get(),
                                              username=u_entery.get(),
                                              password=pas_entry.get(),
                                              wordlists=self.word_entry.get(),
                                              threads=None,
                                              token=None,
                                              cookie=None,
                                              useragent=None,
                                              http_method=None,
                                              headers=None,
                                              delay=None,
                                              keyword_filter=None,
                                              encoding=None,
                                              id1=None,
                                              id2=None,
                                              parameter=None,
                                              ip_addr=None,
                                              port=None,
                                              scan_argument=None,
                                              script=None,
                                              dns_rebinding=None,
                                              time_based=None,
                                              attack_type=None,
                                              target_file=None,
                                              tool="Api_Auth_scan"))  
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
        
        if n.lower() in ["api testing"]:
            self.framefortool("API testing")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            token_label = ctk.CTkLabel(self.box_frame,text="Enter Token : ",font=("arial",16,"bold"))
            token_label.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            token_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            token_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            thread_label = ctk.CTkLabel(self.box_frame,text="Enter Threads : ",font=("arial",16,"bold"))
            thread_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            thread_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            thread_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=3,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/Api_testing")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            self.word_entry.grid(row=3,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command=lambda: self.vuln_scan(
                                              url=domain_entry.get(),
                                              username=None,
                                              password=None,
                                              wordlists=self.word_entry.get(),
                                              threads=thread_entry.get(),
                                              token=token_entry.get(),
                                              cookie=None,
                                              useragent=None,
                                              http_method=None,
                                              headers=None,
                                              delay=None,
                                              keyword_filter=None,
                                              encoding=None,
                                              id1=None,
                                              id2=None,
                                              parameter=None,
                                              ip_addr=None,
                                              port=None,
                                              scan_argument=None,
                                              script=None,
                                              dns_rebinding=None,
                                              time_based=None,
                                              attack_type=None,
                                              target_file=None,
                                              tool="API_test"))  
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
        
        if n.lower() in ["bruteforce"]: 
            self.framefortool("Bruteforce")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter URL : ",font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            user_name = ctk.CTkLabel(self.box_frame,text="Enter Username : ",font=("arial",16,"bold"))
            user_name.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            user_entry= ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            user_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/Bruteforce")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            self.word_entry.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            pu_label = ctk.CTkLabel(self.box_frame,text="Param username : ",font=("arial",16,"bold"))
            pu_label.grid(row=3,column=0,padx=10,pady=10,sticky="e")
            pu_entry =ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            pu_entry.grid(row=3,column=1,padx=10,pady=10,sticky="w")
            pp_label = ctk.CTkLabel(self.box_frame,text="Param password : ",font=("arial",16,"bold"))
            pp_label.grid(row=4,column=0,padx=10,pady=10,sticky="e")
            pp_entry =ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            pp_entry.grid(row=4,column=1,padx=10,pady=10,sticky="w")
            m_label =ctk.CTkLabel(self.box_frame,text="Method : ",font=("arial",16,"bold"))
            m_label.grid(row=5,column=0,padx=10,pady=10,sticky="e")
            m_entry=ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            m_entry.grid(row=5,column=1,padx=10,pady=10,sticky="w")
            thread_label= ctk.CTkLabel(self.box_frame,text="Enter thread : ",font=("arial",16,"bold"))
            thread_label.grid(row=6,column=0,padx=10,pady=10,stick="e")
            thread_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            thread_entry.grid(row=6,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                          command= lambda: self.vuln_scan(url=domain_entry.get(),
                                                                          username=user_entry.get(),
                                                                          password=pas_entry.get(),
                                                                          wordlists=self.word_entry.get(),
                                                                          threads=thread_entry.get(),
                                                                          token=None,
                                                                          cookie=None,useragent=None,
                                                                          http_method=m_entry.get(),
                                                                          headers=None,
                                                                          delay=None,
                                                                          keyword_filter=None,
                                                                          encoding=None,
                                                                          id1=pu_entry.get(),id2=pp_entry.get(),
                                                                          parameter=None,
                                                                          ip_addr=None,
                                                                          port=None,
                                                                          scan_argument=None,
                                                                          script=None,
                                                                          dns_rebinding=None,
                                                                          time_based=None,
                                                                          attack_type=None,
                                                                          target_file=None,
                                                                          tool="Bruteforce"))  
            submit_button.grid(row=7, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
        
        if n.lower() in ["command injection"]:
            self.framefortool("Command Injection")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter Domain : ", font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=(40,20),sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16))
            domain_entry.grid(row=0,column=1,padx=10,pady=(40,20),sticky="w")
            param_label = ctk.CTkLabel(self.box_frame, text="Specific parameter:", font=("arial", 16, "bold"))
            param_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            self.param_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.param_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.box_frame, text="HTTP method:", font=("arial", 16, "bold"))
            method_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            self.method_var = ctk.StringVar(self.box_frame)  
            self.method_var.set("GET") 
            methods = ["GET", "POST"]
            self.method_dropdown = ctk.CTkOptionMenu(self.box_frame, variable=self.method_var, values=methods,height=40,width=300)
            self.method_dropdown.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            header_label = ctk.CTkLabel(self.box_frame, text="Custom headers:", font=("arial", 16, "bold"))
            header_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            self.header_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.header_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame, text="Session cookies:", font=("arial", 16, "bold"))
            cookie_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            self.cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.cookie_entry.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            delay_label = ctk.CTkLabel(self.box_frame, text="Delay (seconds):", font=("arial", 16, "bold"))
            delay_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            self.delay_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.delay_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            word_label = ctk.CTkLabel(self.box_frame,text="Wordlist path",font=("arial",16,"bold"))
            word_label.grid(row=6,column=0,padx=10,pady=10,sticky="e")
            self.file_list = self.get_files("data/wordlists/CommandInjection")
            self.word_var = ctk.StringVar(value=self.file_list[0] if self.file_list else "No wordlists found")
            self.word_entry = ctk.CTkOptionMenu(self.box_frame,values=self.file_list,variable=self.word_var,width=300,height=40)
            self.word_entry.grid(row=6,column=1,padx=10,pady=10,sticky="w")
            threads_label = ctk.CTkLabel(self.box_frame, text="Number of threads:", font=("arial", 16, "bold"))
            threads_label.grid(row=7, column=0, padx=10, pady=(10, 10), sticky="e")
            self.threads_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.threads_entry.grid(row=7, column=1, padx=10, pady=(10, 10), sticky="w")
            filter_label = ctk.CTkLabel(self.box_frame, text="Keyword filter:", font=("arial", 16, "bold"))
            filter_label.grid(row=8, column=0, padx=10, pady=(10, 10), sticky="e")
            self.filter_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            self.filter_entry.grid(row=8, column=1, padx=10, pady=(10, 10), sticky="w")
            encoding_label = ctk.CTkLabel(self.box_frame, text="Encoding:", font=("arial", 16, "bold"))
            encoding_label.grid(row=9, column=0, padx=10, pady=(10, 40), sticky="e")
            encodings = ["base64", "hex", "url", "double-url", "none"]
            self.encoding_dropdown = ctk.CTkOptionMenu(self.box_frame,values=encodings)
            self.encoding_dropdown.grid(row=9, column=1, padx=10, pady=(10, 40), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,                              command=lambda: self.vuln_scan(
                                  url=domain_entry.get(),
                                  username=user_entry.get(),
                                  password=pas_entry.get(),
                                  wordlists=self.word_entry.get(),
                                  threads=self.threads_entry.get(),
                                  token=None,
                                  cookie=self.cookie_entry.get(),
                                  useragent=None,
                                  http_method=self.method_var.get(),
                                  headers=self.header_entry.get(),
                                  delay=self.delay_entry.get(),
                                  keyword_filter=self.filter_entry.get(),
                                  encoding=self.encoding_dropdown.get(),
                                  id1=pu_entry.get(),
                                  id2=pp_entry.get(),
                                  parameter=self.param_entry.get(),
                                  ip_addr=None,
                                  port=None,
                                  scan_argument=None,
                                  script=None,
                                  dns_rebinding=None,
                                  time_based=None,
                                  attack_type=None,
                                  target_file=None,
                                  tool="Command_Injection"
                              ))  
            submit_button.grid(row=10, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
        
        if n.lower() in ["csrf scanning"]:
            self.framefortool("CSRF scanning")
            domain_label = ctk.CTkLabel(self.box_frame,text="Enter Domain : ", font=("arial",16,"bold"))
            domain_label.grid(row=0,column=0,padx=10,pady=10,sticky="e")
            domain_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            domain_entry.grid(row=0,column=1,padx=10,pady=10,sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame,text="Enter Cookie : ",font=("arial",16,"bold"))
            cookie_label.grid(row=1,column=0,padx=10,pady=10,sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            cookie_entry.grid(row=1,column=1,padx=10,pady=10,sticky="w")
            u_agent = ctk.CTkLabel(self.box_frame,text="Enter user agent : ",font=("arial",16,"bold"))
            u_agent.grid(row=2,column=0,padx=10,pady=10,sticky="e")
            u_entery = ctk.CTkEntry(self.box_frame,width=300,font=("arial",16),height=40)
            u_entery.grid(row=2,column=1,padx=10,pady=10,sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=domain_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=None,
                                        token=None,
                                        cookie=cookie_entry.get(),
                                        useragent=u_entery.get(),
                                        http_method=None,
                                        headers=None,
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=None,
                                        id1=None,
                                        id2=None,
                                        parameter=None,
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=None,
                                        target_file=None,
                                        tool="CSRF"
                                    ))  
            submit_button.grid(row=3, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["idor scan"]:
            self.framefortool("IDOR scan")
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL:", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            param_label = ctk.CTkLabel(self.box_frame, text="Parameter:", font=("arial", 16, "bold"))
            param_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            param_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            param_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            start_label = ctk.CTkLabel(self.box_frame, text="Start ID:", font=("arial", 16, "bold"))
            start_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            start_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            start_entry.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            end_label = ctk.CTkLabel(self.box_frame, text="End ID:", font=("arial", 16, "bold"))
            end_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            end_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            end_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.box_frame, text="HTTP Method:", font=("arial", 16, "bold"))
            method_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            method_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["GET", "POST"],height=40,width=300)
            method_dropdown.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            method_dropdown.set("GET") 
            header_label = ctk.CTkLabel(self.box_frame, text="Header:", font=("arial", 16, "bold"))
            header_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            header_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            header_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame, text="Cookie:", font=("arial", 16, "bold"))
            cookie_label.grid(row=6, column=0, padx=10, pady=(10, 10), sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookie_entry.grid(row=6, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=url_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=None,
                                        token=None,
                                        cookie=cookie_entry.get(),
                                        useragent=None,
                                        http_method=method_dropdown.get(),
                                        headers=header_entry.get(),
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=None,
                                        id1=start_entry.get(),
                                        id2=end_entry.get(),
                                        parameter=param_entry.get(),
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=None,
                                        target_file=None,
                                        tool="IDOR"
                                    ))  
            submit_button.grid(row=7, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["lfi scan"]:
            self.framefortool("LFI scan")
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL:", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            param_label = ctk.CTkLabel(self.box_frame, text="Vulnerable Parameter:", font=("arial", 16, "bold"))
            param_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            param_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            param_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            encoding_label = ctk.CTkLabel(self.box_frame, text="Encoding Technique:", font=("arial", 16, "bold"))
            encoding_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            encoding_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["base64", "double_url", "single_url"],height=40,width=300)
            encoding_dropdown.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            encoding_dropdown.set("base64") 
            cookies_label = ctk.CTkLabel(self.box_frame, text="Session Cookies:", font=("arial", 16, "bold"))
            cookies_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            cookies_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookies_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            headers_label = ctk.CTkLabel(self.box_frame, text="Custom Headers:", font=("arial", 16, "bold"))
            headers_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            headers_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            headers_entry.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            threads_label = ctk.CTkLabel(self.box_frame, text="Number of Threads:", font=("arial", 16, "bold"))
            threads_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            threads_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            threads_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=url_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=threads_entry.get(),
                                        token=None,
                                        cookie=cookies_entry.get(),
                                        useragent=None,
                                        http_method=None,
                                        headers=headers_entry.get(),
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=encoding_dropdown.get(),
                                        id1=None,
                                        id2=None,
                                        parameter=param_entry.get(),
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=None,
                                        target_file=None,
                                        tool="LFI"
                                    ))  
            submit_button.grid(row=6, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")


        if n.lower() in ["nmap scan"]:
            self.framefortool("NMAP scan")
            ip_label = ctk.CTkLabel(self.box_frame, text="IP Address :", font=("arial", 16, "bold"))
            ip_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            ip_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            ip_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            ports_label = ctk.CTkLabel(self.box_frame, text="Ports (e.g., 20-80) :", font=("arial", 16, "bold"))
            ports_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            ports_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            ports_entry.insert(0, "20-80") 
            ports_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            args_label = ctk.CTkLabel(self.box_frame, text="Scan Arguments :", font=("arial", 16, "bold"))
            args_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            args_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            args_entry.insert(0, "-sS -sV") 
            args_entry.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            script_label = ctk.CTkLabel(self.box_frame, text="Script (Optional) :", font=("arial", 16, "bold"))
            script_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            script_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            script_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=None,
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=None,
                                        token=None,
                                        cookie=None,
                                        useragent=None,
                                        http_method=None,
                                        headers=None,
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=None,
                                        id1=None,
                                        id2=None,
                                        parameter=None,
                                        ip_addr=ip_entry.get(),
                                        port=ports_entry.get(),
                                        scan_argument=args_entry.get(),
                                        script=script_entry.get(),
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=None,
                                        target_file=None,
                                        tool="Nmap Scan"
                                    ))  
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
       
        if n.lower() in ["sql injection(error based)"]:
            self.framefortool("SQL Injection(Error based)")
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL :", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.box_frame, text="Method :", font=("arial", 16, "bold"))
            method_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            method_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["f (Form)", "q (Query Parameter)"],height=40,width=300)
            method_dropdown.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            method_dropdown.set("f (Form)") 
            cookie_label = ctk.CTkLabel(self.box_frame, text="Cookie :", font=("arial", 16, "bold"))
            cookie_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookie_entry.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            user_agent_label = ctk.CTkLabel(self.box_frame, text="User-Agent :", font=("arial", 16, "bold"))
            user_agent_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            user_agent_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            user_agent_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=url_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=None,
                                        token=None,
                                        cookie=cookie_entry.get(),
                                        useragent=user_agent_entry.get(),
                                        http_method=method_dropdown.get(),
                                        headers=None,
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=None,
                                        id1=None,
                                        id2=None,
                                        parameter=None,
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=None,
                                        target_file=None,
                                        tool="sql_injection"
                                    ))  
            submit_button.grid(row=4, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["ssrf scan"]:
            self.framefortool("SSRF scan")
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL :", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            param_label = ctk.CTkLabel(self.box_frame, text="Parameter :", font=("arial", 16, "bold"))
            param_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            param_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            param_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.box_frame, text="HTTP Method :", font=("arial", 16, "bold"))
            method_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            method_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["GET", "POST"],height=40,width=300)
            method_dropdown.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            method_dropdown.set("GET") 
            header_label = ctk.CTkLabel(self.box_frame, text="Custom Headers :", font=("arial", 16, "bold"))
            header_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            header_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            header_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame, text="Session Cookie :", font=("arial", 16, "bold"))
            cookie_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookie_entry.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            delay_label = ctk.CTkLabel(self.box_frame, text="Delay (seconds):", font=("arial", 16, "bold"))
            delay_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            delay_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            delay_entry.insert(0, "0")  # Default value
            delay_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            dns_var = ctk.BooleanVar()
            dns_checkbox = ctk.CTkCheckBox(self.box_frame, text="Test for DNS Rebinding", variable=dns_var)
            dns_checkbox.grid(row=6, column=1, padx=10, pady=(10, 10), sticky="w")
            time_var = ctk.BooleanVar()
            time_checkbox = ctk.CTkCheckBox(self.box_frame, text="Test for Time-based SSRF", variable=time_var)
            time_checkbox.grid(row=7, column=1, padx=10, pady=(10, 10), sticky="w")
            wordlist_label = ctk.CTkLabel(self.box_frame, text="Payload Wordlist :", font=("arial", 16, "bold"))
            wordlist_label.grid(row=8, column=0, padx=10, pady=(10, 10), sticky="e")
            wordlist_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            wordlist_entry.grid(row=8, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=url_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=wordlist_entry.get(),
                                        threads=None,
                                        token=None,
                                        cookie=cookie_entry.get(),
                                        useragent=None,
                                        http_method=method_dropdown.get(),
                                        headers=header_entry.get(),
                                        delay=delay_entry.get(),
                                        keyword_filter=None,
                                        encoding=None,
                                        id1=None,
                                        id2=None,
                                        parameter=param_entry.get(),
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=dns_var.get(),
                                        time_based=time_var.get(),
                                        attack_type=None,
                                        target_file=None,
                                        tool="SSRF"
                                    ))  
            submit_button.grid(row=9, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["xee scan"]:
            self.framefortool("XEE scan")
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL :", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            method_label = ctk.CTkLabel(self.box_frame, text="HTTP Method :", font=("arial", 16, "bold"))
            method_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            method_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["GET", "POST"],height=40,width=300)
            method_dropdown.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            method_dropdown.set("POST")  
            header_label = ctk.CTkLabel(self.box_frame, text="Custom Headers :", font=("arial", 16, "bold"))
            header_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            header_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            header_entry.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame, text="Session Cookies :", font=("arial", 16, "bold"))
            cookie_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookie_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            attack_label = ctk.CTkLabel(self.box_frame, text="Attack Type :", font=("arial", 16, "bold"))
            attack_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            attack_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["file_read", "ssrf", "blind_oob", "xml_bomb"],height=40,width=300)
            attack_dropdown.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            target_label = ctk.CTkLabel(self.box_frame, text="Target file :", font=("arial", 16, "bold"))
            target_label.grid(row=5, column=0, padx=10, pady=(10, 10), sticky="e")
            target_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16))
            target_entry.grid(row=5, column=1, padx=10, pady=(10, 10), sticky="w")
            encoding_label = ctk.CTkLabel(self.box_frame, text="Encoding :", font=("arial", 16, "bold"))
            encoding_label.grid(row=6, column=0, padx=10, pady=(10, 10), sticky="e")
            encoding_dropdown = ctk.CTkOptionMenu(self.box_frame, values=["base64", "hex"],height=40,width=300)
            encoding_dropdown.grid(row=6, column=1, padx=10, pady=(10, 10), sticky="w")
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                        command=lambda: self.vuln_scan(
                                        url=url_entry.get(),
                                        username=None,
                                        password=None,
                                        wordlists=None,
                                        threads=None,
                                        token=None,
                                        cookie=cookie_entry.get(),
                                        useragent=None,
                                        http_method=method_dropdown.get(),
                                        headers=header_entry.get(),
                                        delay=None,
                                        keyword_filter=None,
                                        encoding=encoding_dropdown.get(),
                                        id1=None,
                                        id2=None,
                                        parameter=None,
                                        ip_addr=None,
                                        port=None,
                                        scan_argument=None,
                                        script=None,
                                        dns_rebinding=None,
                                        time_based=None,
                                        attack_type=attack_dropdown.get(),
                                        target_file=target_entry.get(),
                                        tool="XEE"
                                    ))  
            submit_button.grid(row=7, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")

        if n.lower() in ["xss scan"]:
            self.framefortool("XSS scan")
            # URL Label and Entry
            url_label = ctk.CTkLabel(self.box_frame, text="Target URL :", font=("arial", 16, "bold"))
            url_label.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="e")
            url_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            url_entry.grid(row=0, column=1, padx=10, pady=(10, 10), sticky="w")
            cookie_label = ctk.CTkLabel(self.box_frame, text="Session Cookie :", font=("arial", 16, "bold"))
            cookie_label.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="e")
            cookie_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            cookie_entry.grid(row=1, column=1, padx=10, pady=(10, 10), sticky="w")
            user_agent_label = ctk.CTkLabel(self.box_frame, text="User-Agent :", font=("arial", 16, "bold"))
            user_agent_label.grid(row=2, column=0, padx=10, pady=(10, 10), sticky="e")
            user_agent_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            user_agent_entry.grid(row=2, column=1, padx=10, pady=(10, 10), sticky="w")
            payloads_label = ctk.CTkLabel(self.box_frame, text="Payload File :", font=("arial", 16, "bold"))
            payloads_label.grid(row=3, column=0, padx=10, pady=(10, 10), sticky="e")
            payloads_entry = ctk.CTkEntry(self.box_frame, width=300, font=("arial", 16),height=40)
            payloads_entry.grid(row=3, column=1, padx=10, pady=(10, 10), sticky="w")
            threads_label = ctk.CTkLabel(self.box_frame, text="Threads :", font=("arial", 16, "bold"))
            threads_label.grid(row=4, column=0, padx=10, pady=(10, 10), sticky="e")
            threads_entry = ctk.CTkEntry(self.box_frame, width=100, font=("arial", 16),height=40)
            threads_entry.grid(row=4, column=1, padx=10, pady=(10, 10), sticky="w")
            threads_entry.insert(0, "5") 
            submit_button = ctk.CTkButton(self.box_frame,text="Start Scan",font=("arial",20,"bold"),width=400, height=40,
                                           command=lambda: self.vuln_scan(
                                            url=url_entry.get(),
                                            cookie=cookie_entry.get(),
                                            useragent=user_agent_entry.get(),
                                            wordlists=payloads_entry.get(),  
                                            threads=int(threads_entry.get()) if threads_entry.get().isdigit() else 5,
                                            username=None,
                                            password=None,
                                            token=None,
                                            http_method=None,
                                            headers=None,
                                            delay=None,
                                            keyword_filter=None,
                                            encoding=None,
                                            id1=None,
                                            id2=None,
                                            parameter=None,
                                            ip_addr=None,
                                            port=None,
                                            scan_argument=None,
                                            script=None,
                                            dns_rebinding=None,
                                            time_based=None,
                                            attack_type=None,
                                            target_file=None,
                                            tool="XSS" 
                                        ))  
            submit_button.grid(row=5, columnspan=2, pady=15)
            log_frame = ctk.CTkScrollableFrame(self.content_frame, width=500)
            log_frame.grid(row=3,columnspan=2,pady=(20,5))
            log_frame.columnconfigure(0,weight=1)
            self.log_label = ctk.CTkLabel(log_frame,text="Script Log",font=("arial",20,"bold"),justify="left",anchor="w")
            self.log_label.grid(row=0,columnspan=2,padx=20,pady=(20,5),sticky="w")
  
    def tool_logs(self): 
        if self.content_frame: 
            self.content_frame.destroy()
        log_dir = os.path.join(os.getcwd(), "logs")  # Use os.path.join for cross-platform support
        if not os.path.exists(log_dir):
            print(f"[!] Log directory does not exist: {log_dir}")
            return  # Exit if the directory is missing

        files = [file for file in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, file))]

        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e", height=500)
        self.content_frame.grid(row=0,column=1,padx=(5,20),pady=20,sticky="nsew")
        self.content_frame.grid_columnconfigure(0,weight=1)
        label = ctk.CTkLabel(self.content_frame,text="Log files",font=("arial",30,"bold"))
        label.grid(row=1,columnspan=2,padx=10,pady=10,sticky="nsew")
        for i, file in enumerate(files,2):
            file_button = ctk.CTkButton(self.content_frame, text=file, command=lambda f=file: self.open_log(f))
            file_button.grid(row=i,columnspan=2,padx=10,pady=10,sticky="nsew") # Display buttons for each log file

    def open_log(self, filename):
        log_path = os.path.join(os.getcwd(), "logs", filename)
        try:
            if self.content_frame: 
                self.content_frame.destroy()
            
            with open(log_path, "r") as file:
                content = file.read()
            
            self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e")
            self.content_frame.grid(row=0, column=1, padx=(5,20), pady=20, sticky="nsew")  # Add this line
            self.content_frame.grid_columnconfigure(0,weight=1)
            self.back = ctk.CTkButton(self.content_frame, text="Back", font=("arial", 20, "bold"),
                                    height=40, width=300, command=self.tool_logs)
            self.back.grid(row=0, columnspan=2, padx=10, pady=10)
            
            frame_log = ctk.CTkScrollableFrame(self.content_frame,width=300,height=500)
            frame_log.grid(row=1,columnspan=2,padx=10,pady=10,sticky="nsew")
            self.file_content = ctk.CTkLabel(frame_log, corner_radius=10, text=content,
                                            font=("arial", 20, "bold"), wraplength=500, justify="left",height=40)
            self.file_content.grid(row=0, columnspan=2, padx=10, pady=10)
            
        except Exception as e:
            messagebox.showerror("Error",e)


    def framefortool(self,title):
        if hasattr(self, "content_frame") and self.content_frame:  
            self.content_frame.destroy()
        self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e",height=500)
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
        self.box_frame =ctk.CTkScrollableFrame(self.content_frame,corner_radius=10,width=500)
        self.box_frame.grid(row=2,columnspan=2,padx=10,pady=10)
        self.box_frame.columnconfigure([0,1],weight=1)
   
    def log_update_callback(self, message):
        if self.log_label: 
            new_text = self.log_label.cget("text") + "\n" + message  
            self.log_label.configure(text=new_text, font=("Arial", 14), wraplength=480)  
            self.log_label.grid_configure(sticky="w") 
            self.log_label.update_idletasks()

    #sending GUI input to the processor
    def recon_scan(self,url,port,tool,wordlists,useragent,cookies,threads,n_result,output,input_list):
        try: 
            from src.GUI.process.recon_process import ReconProcess
            recon_process = ReconProcess(url=url,port=port,useragent=useragent,cookie=cookies,thread=threads if threads is not None else "10",wordlists=wordlists,n=n_result,output_file=output,input_list=input_list,log_update_callback=self.log_update_callback,filename=tool)
            if tool=="banner_grabber": 
                recon_process.BannerGrabber()
            elif tool == "dir_enum": 
                recon_process.DirEnum()
            elif tool == "header_grabber":
                recon_process.HeaderGrabber()

            elif tool == "dns_enum":
                recon_process.DNSenum()

            elif tool == "google_dork":
                recon_process.Gdork()
            elif tool == "js_file_analyzer": 
                recon_process.JSfAnalyz()

            elif tool == "shodan_enum":
                recon_process.ShodanEnum()

            elif tool == "subdomain_enum":
                recon_process.SubDomEnum()

            elif tool == "web_scraper": 
                recon_process.WebScrap()

            elif tool == "web_status": 
                recon_process.WebStatus()

            elif tool == "who_is":
                recon_process.Wis()
        except Exception as e: 
            messagebox.showerror("Error",e)
            print(e)

    def vuln_scan(self,url,username,password,wordlists,threads,token,cookie,useragent,http_method,headers,delay,keyword_filter,encoding,id1,id2,parameter,ip_addr,port,scan_argument,script,dns_rebinding,time_based,attack_type,target_file,tool):
        try:
            from src.GUI.process.vuln_process import VulnScanProcess
            vuln_scan = VulnScanProcess(url =url ,
                                        username =username,
                                        password = password,
                                        wordlist_path =wordlists,
                                        thread=threads,
                                        tokens = token,
                                        cookies =cookie,
                                        useragent = useragent,
                                        http_method = http_method,
                                        headers = headers,
                                        delay = delay,
                                        keyword_filter = keyword_filter,
                                        encoding = encoding,
                                        param_id1 = id1,
                                        param_id2= id2,
                                        parameter= parameter,
                                        ip = ip_addr,
                                        ports =port,
                                        scan_argument = scan_argument,
                                        script = script,
                                        dns_rebinding = dns_rebinding,
                                        time_based = time_based,
                                        attack_type = attack_type,
                                        target_file = target_file,
                                        log_update_callback=self.log_update_callback,
                                        filename=tool)
            if tool == "Api_Auth_scan":
                vuln_scan.ApiAuthTest()
            elif tool == "API_test": 
                vuln_scan.ApiTest()
            elif tool == "Bruteforce": 
                vuln_scan.Bruteforce()
            elif tool == "Command_Injection": 
                vuln_scan.CommandInjection()
            elif tool == "CSRF": 
                vuln_scan.CSRF()
            elif tool == "IDOR": 
                vuln_scan.IDOR()
            elif tool == "LFI": 
                vuln_scan.LFI()
            elif tool == "nmap_scan": 
                vuln_scan.nmapscan()
            elif tool == "sql_injection": 
                vuln_scan.SQL_Injection()
            elif tool == "SSRF":
                vuln_scan.SSRF()
            elif tool == "XEE": 
                vuln_scan.XEE()
            elif tool == "XSS": 
                vuln_scan.XEE()

        except Exception as e :
            messagebox.showerror("Error",e)
    def logout_action(self):
        try:
            token = self.load_session()  # Load token from local session file

            if not token:
                messagebox.showinfo("Logout", "No active session found.")
                return

            headers = {"Authorization": token}

            response = requests.get(f"{APP_URL}/logout", headers=headers)

            if response.status_code == 200:
                # Successfully logged out
                self.clear_session()
                messagebox.showinfo("Logout Successful", "You have been logged out.")
                self.destroy()  # Close the app or redirect to login window
            else:
                messagebox.showerror("Logout Failed", "Could not log out. Please try again.")

        except requests.RequestException as e:
            messagebox.showerror("Network Error", str(e))
        except Exception as e:
            print("[!] Logout Error:", e)
    
    # @staticmethod
    # def load_session():
    #     """Load session token from JSON file."""
    #     if os.path.exists(SESSION_FILE):
    #         with open(SESSION_FILE, "r") as f:
    #             return json.load(f).get("token")
    #     return None

    # def clear_session(self):
    #     """Clear the session token stored locally."""
    #     if os.path.exists(SESSION_FILE):
    #         os.remove(SESSION_FILE)


# #UI for Blue Teamer and Developer
# class BlueT(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         self.geometry("800x650")
#         self.title("Blue Teamer/developer Panel")
#         self.resizable(False,False)
#         self.content_frame = None 
#         self.box_frame = None 
#         self.show_sidebar()
#         self.show_content()

        
#     @staticmethod
#     def load_session():
#         """Load session token from JSON file."""
#         if os.path.exists(SESSION_FILE):
#             with open(SESSION_FILE, "r") as f:
#                 return json.load(f).get("token")
#         return None

#     def show_sidebar(self): 
#         self.sidebar = ctk.CTkFrame(self,corner_radius=10,width=150,fg_color="transparent")
#         self.sidebar.grid(row=0,column=0,sticky="ns",padx=20,pady=20)
#         self.sidebar.grid_propagate(False)
#         self.sidebar.grid_columnconfigure(0,weight=1)
#         # label1 = ctk.CTkLabel(self.sidebar,text="Overview",font=("Arial",18))
#         # label1.grid(row=0,column=0,padx=10,pady=10,sticky="ew")
#         # home_btn = ctk.CTkButton(self.sidebar,text="Home",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_content,height=30,width=200)
#         # home_btn.grid(row=1,column=0,padx=10,pady=10)
#         # UH_btn = ctk.CTkButton(self.sidebar,text="Programmes",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_programmes,height=30,width=200)
#         # UH_btn.grid(row=2,column=0,padx=10,pady=10)
#         # tools_btn = ctk.CTkButton(self.sidebar,text="Tools",font=("Arial",14),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",command=self.show_tools,height=30,width=200 )
#         # tools_btn.grid(row=3,column=0,padx=10,pady=10)
#         label2 = ctk.CTkLabel(self.sidebar,text="Review",font=("Arial",18))
#         label2.grid(row=4,column=0,padx=10,pady=10,sticky="ew")
#         log_btn = ctk.CTkButton(self.sidebar,text="Security Review",font=("Arial",13),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=250,command=self.security_review)
#         log_btn.grid(row=5,column=0,padx=10,pady=10)
#         # log_btn2 = ctk.CTkButton(self.sidebar,text="Export Log",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200)
#         # log_btn2.grid(row=6,column=0,padx=10,pady=10)
#         label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",18))
#         label3.grid(row=7,column=0,padx=10,pady=10,sticky="ew")
#         toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",font=("Arial",15),fg_color="transparent",corner_radius=30,hover_color="#1e1e1e",height=30,width=200,command=self.logout_action)
#         toggl_btn.grid(row=8,column=0,padx=10,pady=10)

#         clabel = ctk.CTkLabel(self.sidebar,text="Created by:\n Aaron Limbu",font=("Arial",10))
#         clabel.grid(row=9,column=0,padx=10,pady=(80,10))
#         # label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",20))
#         # label3.grid(row=6,column=0,padx=10,pady=10,sticky="ew")
#         # toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",font=("Arial",15))
#         # toggl_btn.grid(row=7,column=0,padx=10,pady=10)
#     def show_content(self):
#         if self.content_frame:
#             self.content_frame.destroy()

#         self.content_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="#1e1e1e", height=550, width=550)
#         self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 20), pady=20)
#         self.content_frame.grid_columnconfigure(0, weight=1)

#         title_label = ctk.CTkLabel(self.content_frame, text="Dashboard", font=("Arial", 32, "bold"), text_color="white")
#         title_label.grid(row=0, column=0, sticky="w", padx=20, pady=(10, 5))

#         subheading = ctk.CTkLabel(self.content_frame, text="Pentesting Programmes Overview", font=("Arial", 16), text_color="#cccccc")
#         subheading.grid(row=1, column=0, sticky="w", padx=20)

#         programmes_frame = ctk.CTkFrame(self.content_frame, fg_color="#2e2e2e", corner_radius=10)
#         programmes_frame.grid(row=2, column=0, padx=20, pady=20, sticky="nsew")
#         programmes_frame.grid_columnconfigure(0, weight=1)  # Expand child cards

#         token = self.load_session()
#         programmes = []
#         if token:
#             try:
#                 res = requests.get(f"{APP_URL}/programmes", headers={"Authorization": token})
#                 if res.status_code == 200:
#                     programmes = res.json()
#                 else:
#                     print("Failed to fetch programmes:", res.json())
#             except Exception as e:
#                 print("Error while fetching programmes:", e)

#         if not programmes:
#             empty_label = ctk.CTkLabel(programmes_frame, text="No programmes added.", font=("Arial", 14), text_color="#cccccc")
#             empty_label.grid(row=0, column=0, padx=20, pady=20)
#         else:
#             for i, prog in enumerate(programmes):
#                 card = ctk.CTkFrame(programmes_frame, fg_color="#242424", corner_radius=16)
#                 card.grid(row=i, column=0, padx=10, pady=12, sticky="ew")
#                 card.grid_columnconfigure(0, weight=1)
#                 ctk.CTkLabel(
#                     card, text=prog['programme_name'], font=("Segoe UI", 20, "bold"),
#                     text_color="white"
#                 ).grid(row=0, column=0, sticky="w", padx=20, pady=(12, 4))
#                 ctk.CTkLabel(
#                     card,text=f"Publisher: {prog['username']}",font=("Segoe UI",13),text_color="white"
#                 ).grid(row=0,column=1,sticky="w",padx=10,pady=(12,4))
#                 ctk.CTkLabel(
#                     card, text=f"Domain Name: {prog['domain_name']}", font=("Segoe UI", 14),
#                     text_color="#cccccc"
#                 ).grid(row=1, column=0, sticky="w", padx=20, pady=2)
#                 ctk.CTkLabel(
#                     card, text=f"Scopes:", font=("Segoe UI", 13),
#                     text_color="#aaaaaa"
#                 ).grid(row=2, column=0, sticky="w", padx=20, pady=2)
#                 ctk.CTkLabel(
#                     card, text=f"{prog['scope']}", font=("Segoe UI", 13),
#                     text_color="#aaaaaa"
#                 ).grid(row=3, columnspan=2, sticky="w", padx=50, pady=2)
#                 out_scope = prog.get('outofscope', '').strip()
#                 if out_scope:
#                     ctk.CTkLabel(
#                         card, text=f"Out of Scope: ", font=("Segoe UI", 13),
#                         text_color="#999999"
#                     ).grid(row=4, column=0, sticky="w", padx=20, pady=2)
#                     ctk.CTkLabel(
#                         card, text=f"{out_scope}", font=("Segoe UI", 13),
#                         text_color="#999999"
#                     ).grid(row=5, columnspan=2, sticky="w", padx=50, pady=2)
#                 ctk.CTkLabel(
#                     card, text=f"{prog['start_date']} → {prog['end_date']}", font=("Segoe UI", 12),
#                     text_color="#888888"
#                 ).grid(row=6, column=0, sticky="w", padx=20, pady=2)
#                 status_color = "#44cc66" if prog['status'] == "Completed" else "#ffaa00" if prog['status'] == "Pending" else "#00bfff"
#                 ctk.CTkLabel(
#                     card, text=f"Status: {prog['status']}", font=("Segoe UI", 12, "bold"),
#                     text_color=status_color
#                 ).grid(row=7, column=0, sticky="w", padx=20, pady=(4, 2))
#                 ctk.CTkLabel(
#                     card, text=f"Created: {prog['created_at']}", font=("Segoe UI", 11),
#                     text_color="#777777"
#                 ).grid(row=8, column=0, sticky="w", padx=20, pady=(0, 12))
#         add_programme_button = ctk.CTkButton(self.content_frame, text="Add Programme", command=self.add_programme)
#         add_programme_button.grid(row=3, column=0, sticky="e", padx=20, pady=20)
        
#     def add_programme(self):
#         """Creates a form to add a new programme inside the content_frame"""
#         # Clear the current content
#         for widget in self.content_frame.winfo_children():
#             widget.destroy()
#         self.content_frame.grid_rowconfigure([4, 5, 6, 7], weight=1)  
#         self.content_frame.grid_columnconfigure([0, 1], weight=1)  
#         title_label = ctk.CTkLabel(self.content_frame, text="Add New Programme", font=("Arial", 24, "bold"), text_color="white")
#         title_label.grid(row=0, column=0, sticky="w", padx=20, pady=(10, 5))
#         back_button = ctk.CTkButton(self.content_frame, text="Back", command=self.show_content)
#         back_button.grid(row=1, column=0, sticky="w", padx=20, pady=10)
#         programme_name_label = ctk.CTkLabel(self.content_frame, text="Programme Name:")
#         programme_name_label.grid(row=2, column=0, padx=20, pady=10, sticky="w")
#         programme_name_entry = ctk.CTkEntry(self.content_frame, width=250)
#         programme_name_entry.grid(row=2, column=1, padx=20, pady=10)
#         domain_name_label = ctk.CTkLabel(self.content_frame, text="Domain Name:")
#         domain_name_label.grid(row=3, column=0, padx=20, pady=10, sticky="w")
#         domain_name_entry = ctk.CTkEntry(self.content_frame, width=250)
#         domain_name_entry.grid(row=3, column=1, padx=20, pady=10)
#         scope_label = ctk.CTkLabel(self.content_frame, text="Scope:")
#         scope_label.grid(row=4, column=0, padx=20, pady=10, sticky="w")
#         scope_text = ctk.CTkTextbox(self.content_frame, height=100, width=250,border_width=1)  
#         scope_text.grid(row=4, column=1, padx=20, pady=10)
#         out_of_scope_label = ctk.CTkLabel(self.content_frame, text="Out of Scope:")
#         out_of_scope_label.grid(row=5, column=0, padx=20, pady=10, sticky="w")
#         out_of_scope_text = ctk.CTkTextbox(self.content_frame, height=100, width=250,border_width=1)  
#         out_of_scope_text.grid(row=5, column=1, padx=20, pady=10)
#         start_date_label = ctk.CTkLabel(self.content_frame, text="Start Date:")
#         start_date_label.grid(row=6, column=0, padx=20, pady=10, sticky="w")
#         start_date_entry = ctk.CTkEntry(self.content_frame, width=250)
#         start_date_entry.grid(row=6, column=1, padx=20, pady=10)
#         end_date_label = ctk.CTkLabel(self.content_frame, text="End Date:")
#         end_date_label.grid(row=7, column=0, padx=20, pady=10, sticky="w")
#         end_date_entry = ctk.CTkEntry(self.content_frame, width=250)
#         end_date_entry.grid(row=7, column=1, padx=20, pady=10)
#         submit_button = ctk.CTkButton(self.content_frame, text="Submit", command=lambda: self.submit_programme(
#             programme_name_entry.get(), domain_name_entry.get(), scope_text.get("1.0", "end-1c"), 
#             out_of_scope_text.get("1.0", "end-1c"), start_date_entry.get(), end_date_entry.get()))
#         submit_button.grid(row=8, column=0, columnspan=2, padx=20, pady=20)

#     def submit_programme(self, programme_name, domain_name, scope, out_of_scope, start_date, end_date):
#         """Submit the new programme to the backend"""
#         new_programme = {
#             "programme_name": programme_name,
#             "domain_name": domain_name,
#             "scope": scope,
#             "outofscope": out_of_scope,
#             "start_date": start_date,
#             "end_date": end_date,
#         }
#         token = self.load_session()
#         headers = {"Authorization": token}
#         try:
#             res = requests.post(f"{APP_URL}/addprogrammes", json=new_programme, headers=headers)
#             if res.status_code == 201:
#                 messagebox.showinfo("Success", "Programme added successfully.")
#                 self.show_content()  # Refresh the content to show the new programme
#             else:
#                 messagebox.showerror("Error", f"Failed to add programme: {res.json().get('error')}")
#         except Exception as e:
#             messagebox.showerror("Error", f"Error while adding programme: {str(e)}")
#     def security_review(self):
#         if self.content_frame:
#             self.content_frame.destroy()

#         self.content_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1e1e1e", height=550, width=550)
#         self.content_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 20), pady=20)
#         title = ctk.CTkLabel(self.content_frame, text="Security Review", font=("Arial", 28, "bold"), text_color="white")
#         title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))

#         subtitle = ctk.CTkLabel(self.content_frame, text="Vulnerabilities Identified & Recommendations", font=("Arial", 16), text_color="#bbbbbb")
#         subtitle.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

#             # Main frame for vulns
#         vulns_frame = ctk.CTkScrollableFrame(self.content_frame, fg_color="#2e2e2e", corner_radius=10, height=500,width=500)
#         vulns_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
#         self.grid_rowconfigure(2, weight=1)
#         self.grid_columnconfigure(0, weight=1)

#         vulnerabilities = [
#                 {
#                     "title": "SQL Injection",
#                     "component": "Login Form",
#                     "severity": "High",
#                     "description": "Unsanitized inputs allow attackers to execute arbitrary SQL queries.",
#                     "fix": "Use parameterized queries or ORM methods to avoid direct SQL string concatenation."
#                 },
#                 {
#                     "title": "Cross-Site Scripting (XSS)",
#                     "component": "Search Field",
#                     "severity": "Medium",
#                     "description": "User input is rendered without proper escaping, allowing script injection.",
#                     "fix": "Sanitize user input and use proper encoding when displaying data in HTML."
#                 },
#                 {
#                     "title": "Insecure Direct Object Reference (IDOR)",
#                     "component": "User Profile Access",
#                     "severity": "High",
#                     "description": "User can access resources of other users by manipulating URLs.",
#                     "fix": "Implement access control checks on the server-side based on user roles and ownership."
#                 }
#             ]

#         for i, vuln in enumerate(vulnerabilities):
#             card = ctk.CTkFrame(vulns_frame, fg_color="#1a1a1a", corner_radius=12,width=400)
#             card.grid(row=i, column=0, padx=10, pady=10, sticky="ew")
#             card.grid_columnconfigure(0, weight=1)

#             sev_colors = {"High": "#ff4d4d", "Medium": "#ffaa00", "Low": "#44cc66"}
#             color = sev_colors.get(vuln["severity"], "#999999")

#             ctk.CTkLabel(card, text=f"{vuln['title']} (Severity: {vuln['severity']})",wraplength=450, font=("Arial", 18, "bold"), text_color=color).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
#             ctk.CTkLabel(card, text=f"Affected Component: {vuln['component']}",wraplength=450, font=("Arial", 14), text_color="#cccccc").grid(row=1, column=0, sticky="w", padx=10)

#             ctk.CTkLabel(card, text="Description:", font=("Arial", 13, "bold"),wraplength=450, text_color="white").grid(row=2, column=0, sticky="w", padx=10, pady=(8, 0))
#             ctk.CTkLabel(card, text=vuln["description"], font=("Arial", 13),wraplength=450, text_color="#aaaaaa",  justify="left").grid(row=3, column=0, sticky="w", padx=10)

#             ctk.CTkLabel(card, text="Fix Recommendation:", font=("Arial", 13, "bold"), text_color="white").grid(row=4, column=0, sticky="w", padx=10, pady=(8, 0))
#             ctk.CTkLabel(card, text=vuln["fix"], font=("Arial", 13),wraplength=450, text_color="#88ccff",  justify="left").grid(row=5, column=0, sticky="w", padx=10, pady=(0, 10))


#     def logout_action(self):
#         try:
#             token = self.load_session()  # Load token from local session file

#             if not token:
#                 messagebox.showinfo("Logout", "No active session found.")
#                 return

#             headers = {"Authorization": token}

#             response = requests.get(f"{APP_URL}/logout", headers=headers)

#             if response.status_code == 200:
#                 # Successfully logged out
#                 self.clear_session()
#                 messagebox.showinfo("Logout Successful", "You have been logged out.")
#                 self.destroy()  # Close the app or redirect to login window
#             else:
#                 messagebox.showerror("Logout Failed", "Could not log out. Please try again.")

#         except requests.RequestException as e:
#             messagebox.showerror("Network Error", str(e))
#         except Exception as e:
#             print("[!] Logout Error:", e)

#     def clear_session(self):
#         """Clear the session token stored locally."""
#         if os.path.exists(SESSION_FILE):
#             os.remove(SESSION_FILE)


# class AdminDashboard(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         self.title("Admin Dashboard")
#         self.geometry("1000x600")
#         self.configure(fg_color="#1e1e1e")  # Dark background

#         self.token = self.load_token()

#         ctk.CTkLabel(
#             self,
#             text="Admin Dashboard",
#             font=("Segoe UI", 24, "bold"),
#             text_color="white"
#         ).pack(pady=15)

#         self.tabview = ctk.CTkTabview(self, height=520, fg_color="#1e1e1e")
#         self.tabview.pack(fill="both", expand=True, padx=20)

#         self.users_tab = self.tabview.add("Users")
#         self.programmes_tab = self.tabview.add("Programmes")
#         self.feedback_tab = self.tabview.add("Feedback")
#         self.scanresults_tab = self.tabview.add("Scan Results")

#         self.load_users()
#         self.load_programmes()
#         self.load_feedback()
#         self.load_scan_results()

#     def load_token(self):
#         try:
#             with open("session.json", "r") as f:
#                 return json.load(f).get("token")
#         except:
#             return ""

#     def fetch_data(self, endpoint):
#         try:
#             res = requests.get(f"{APP_URL}/{endpoint}", headers={"Authorization": self.token})
#             if res.status_code == 200:
#                 return res.json()
#             else:
#                 print("Error:", res.text)
#                 return []
#         except Exception as e:
#             print("Request failed:", e)
#             return []

#     def create_scrollable_frame(self, parent):
#         scroll_frame = ctk.CTkScrollableFrame(parent, fg_color="#1e1e1e", corner_radius=10)
#         scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
#         return scroll_frame

#     def load_users(self):
#         frame = self.create_scrollable_frame(self.users_tab)
#         users = self.fetch_data("admin/users")
#         for user in users:
#             self.display_card(frame, {
#                 "ID": user["id"],
#                 "Username": user["username"],
#                 "Email": user["email"],
#                 "Role": user["role"]
#             })

#     def load_programmes(self):
#         frame = self.create_scrollable_frame(self.programmes_tab)

#         ctk.CTkLabel(frame, text="Add New Programme", font=("Segoe UI", 18, "bold"), text_color="white").pack(pady=10)

#         fields = {
#             "programme_name": "Programme Name",
#             "domain_name": "Domain Name",
#             "scope": "Scope",
#             "outofscope": "Out of Scope (optional)",
#             "start_date": "Start Date (YYYY-MM-DD)",
#             "end_date": "End Date (YYYY-MM-DD)"
#         }
#         entries = {}
#         for key, label_text in fields.items():
#             ctk.CTkLabel(frame, text=label_text, text_color="white").pack(anchor="w", padx=20, pady=(10, 0))
#             entry = ctk.CTkEntry(frame, width=700)
#             entry.pack(padx=20, pady=5)
#             entries[key] = entry

#         status_label = ctk.CTkLabel(frame, text="", text_color="white")
#         status_label.pack()

#         def submit_programme():
#             data = {
#                 "programme_name": entries["programme_name"].get(),
#                 "domain_name": entries["domain_name"].get(),
#                 "scope": entries["scope"].get(),
#                 "outofscope": entries["outofscope"].get(),
#                 "start_date": entries["start_date"].get(),
#                 "end_date": entries["end_date"].get(),
#             }

#             if not all(data[k] for k in ["programme_name", "domain_name", "scope", "start_date", "end_date"]):
#                 status_label.configure(text="Please fill all required fields.", text_color="red")
#                 return

#             try:
#                 res = requests.post(
#                     f"{APP_URL}/addprogrammes",
#                     json=data,
#                     headers={"Authorization": self.token}
#                 )
#                 if res.status_code == 201:
#                     status_label.configure(text="Programme added successfully!", text_color="green")
#                     for entry in entries.values():
#                         entry.delete(0, "end")
#                     self.refresh_programmes_display(frame)
#                 else:
#                     status_label.configure(text=f"Error: {res.json().get('error', 'Unknown')}", text_color="red")
#             except Exception as e:
#                 status_label.configure(text=f"Request failed: {str(e)}", text_color="red")

#         ctk.CTkButton(frame, text="Submit", command=submit_programme).pack(pady=15)

#         ctk.CTkLabel(frame, text="Existing Programmes", font=("Segoe UI", 16, "bold"), text_color="white").pack(pady=10)

#         self.refresh_programmes_display(frame)
#     def refresh_programmes_display(self, parent_frame):
#         progs = self.fetch_data("admin/programmes")

#         for p in progs:
#             self.display_card(parent_frame, {
#                 "ID": p["id"],
#                 "Programme": p["programme_name"],
#                 "Domain": p["domain_name"],
#                 "Status": p["status"],
#                 "Start Date": p["start_date"],
#                 "End Date": p["end_date"]
#             })

#     def load_feedback(self):
#         frame = self.create_scrollable_frame(self.feedback_tab)
#         feedbacks = self.fetch_data("admin/feedback")
#         for f in feedbacks:
#             self.display_card(frame, {
#                 "User ID": f["user_id"],
#                 "Programme ID": f["programme_id"],
#                 "Comment": f["comment"],
#                 "Created At": f["created_at"]
#             })

#     def load_scan_results(self):
#         frame = self.create_scrollable_frame(self.scanresults_tab)
#         scans = self.fetch_data("admin/scanresults")
#         for s in scans:
#             self.display_card(frame, {
#                 "Programme ID": s["programme_id"],
#                 "Type": s["result_type"],
#                 "Details": s["details"],
#                 "Created At": s["created_at"]
#             })

#     def display_card(self, parent, data: dict):
#         card = ctk.CTkFrame(parent, fg_color="#2a2a2a", corner_radius=12)
#         card.pack(padx=10, pady=10, fill="x")

#         for key, val in data.items():
#             label = ctk.CTkLabel(
#                 card,
#                 text=f"{key}: {val}",
#                 font=("Segoe UI", 13),
#                 text_color="white"
#             )
#             label.pack(anchor="w", padx=15, pady=2)


if __name__ == "__main__":      
    try:
        # if not os.path.exists("session.json"):
        #     with open("session.json", "w") as f:
        #         json.dump({"token": None, "role": None}, f)

        # with open("session.json", "r") as f:
        #     session_data = json.load(f)
        #     token = session_data.get("token")
        #     role = session_data.get("role")
        # if not token or not role:
        #     print("[!] No valid session found. Redirecting to Login.")
        #     app = AuthApp()
        #     app.mainloop()
        #     exit()

        # headers = {"Authorization": token}
        # response = requests.get(f"{APP_URL}/verify", headers=headers)

        # if response.status_code == 200:
        #     print(f"[+] Session verified. Role: {role}")
        #     if role == "blue_teamer" or role == "developer":
        #         app = BlueT()
        #     elif role == "pentester":
        #         app = Dash()
        #     elif role == "admin":
        #         app = AdminDashboard()
        #     else:
        #         print("[!] Unrecognized role. Redirecting to Login.")
        #         app = AuthApp()
        # else:
        #     print("[-] Invalid session. Redirecting to Login.")
        #     app = AuthApp()
        app = Dash()
        app.mainloop()

    except KeyboardInterrupt:
        print("[!] Keyboard Interrupt")
    except Exception as e:
        print(f"[!] Error: {e}")
