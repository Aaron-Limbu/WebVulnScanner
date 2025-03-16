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
        recon_btn = ctk.CTkButton(self.content_frame,text="Reconnaissance",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40)
        recon_btn.grid(row=1,column=0,padx=30,pady=0,sticky="n")
        scan_btn = ctk.CTkButton(self.content_frame,text="Scanning",border_width=2,hover_color="#1e1e1e",corner_radius=50,fg_color="transparent",font=("Arial",15,"bold"),height=40)
        scan_btn.grid(row=1,column=1,padx=30,pady=0,sticky="n")
        programmes = [
            ('Tool 1'), ('Tool 2'), ('Tool 3'), ('Tool 4'), ('Tool 5'), ('Tool 6'),
            ('Tool 7'), ('Tool 8'), ('Tool 9'), ('Tool 10'), ('Tool 11')
        ]
        self.tool_lists = ctk.CTkScrollableFrame(self.content_frame, width=300)
        self.tool_lists.grid(row=2, column=0, columnspan=2, padx=25, pady=10, sticky="nsew")
        self.content_frame.rowconfigure(2, weight=1)
        self.tool_lists.grid_columnconfigure(0, weight=1)
        self.tool_lists.grid_columnconfigure(1, weight=1)
        for i, (name) in enumerate(programmes):
            row = i % 6 if i < 6 else (i - 6) % 5 
            col = 0 if i < 6 else 1 
            programme_label = ctk.CTkLabel(self.tool_lists, text=name, font=("Arial", 15, "bold"))
            programme_label.grid(row=row * 2, column=col, padx=10, pady=(10, 0), sticky="n")
            btn = ctk.CTkButton(self.tool_lists, text="Start", command=lambda n=name: print(f"Button {n} clicked"),fg_color="#3C3D37")
            btn.grid(row=row * 2 + 1, column=col, padx=10, pady=(0, 10), sticky="n")

if __name__ == "__main__": 
    try: 
        app = Dash()
        app.mainloop()
    except KeyboardInterrupt as ke : 
        print(f"[!] Keyboard Interrupt")
    except Exception as e : 
        print(f"[!] Error: {e}")