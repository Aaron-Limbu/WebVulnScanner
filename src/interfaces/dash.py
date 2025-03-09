import customtkinter as ctk
from tkinter import messagebox

class Dash(ctk.CTk): 
    def __init__(self):
        super().__init__()
        self.geometry("800x600")
        self.title("Spiderscan")
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1,weight=1)
        self.grid_rowconfigure(0,weight=1)
        self.show_sidebar()
        self.show_content()
    
    def show_sidebar(self): 
        self.sidebar = ctk.CTkFrame(self,corner_radius=10,width=180)
        self.sidebar.grid(row=0,column=0,sticky="ns",padx=20,pady=20)
        self.sidebar.grid_propagate(False)
        label1 = ctk.CTkLabel(self.sidebar,text="Overview",font=("Arial",20),anchor="w",compound="left")
        label1.grid(row=0,column=0,padx=10,pady=10,sticky="ew")
        home_btn = ctk.CTkButton(self.sidebar,text="Home",fg_color="transparent",anchor="w",compound="left",font=("Arial",15))
        home_btn.grid(row=1,column=0,padx=10,pady=10)
        UH_btn = ctk.CTkButton(self.sidebar,text="Programmes",fg_color="transparent",anchor="w",compound="left",font=("Arial",15))
        UH_btn.grid(row=2,column=0,padx=10,pady=10)
        label2 = ctk.CTkLabel(self.sidebar,text="Logging",font=("Arial",20),anchor="w",compound="left")
        label2.grid(row=3,column=0,padx=10,pady=10,sticky="ew")
        log_btn = ctk.CTkButton(self.sidebar,text="URL Log",fg_color="transparent",anchor="w",compound="left",font=("Arial",15))
        log_btn.grid(row=4,column=0,padx=10,pady=10)
        log_btn2 = ctk.CTkButton(self.sidebar,text="Export Log",fg_color="transparent",anchor="w",compound="left",font=("Arial",15))
        log_btn2.grid(row=5,column=0,padx=10,pady=10)
        # label3 = ctk.CTkLabel(self.sidebar,text="Settings",font=("Arial",20),anchor="w",compound="left")
        # label3.grid(row=6,column=0,padx=10,pady=10,sticky="ew")
        # toggl_btn = ctk.CTkButton(self.sidebar,text="Log out",fg_color="transparent",anchor="w",compound="left",font=("Arial",15))
        # toggl_btn.grid(row=7,column=0,padx=10,pady=10)

    def show_content(self): 
        self.content_frame = ctk.CTkFrame(self,corner_radius=10,fg_color="#1e1e1e")
        self.content_frame.grid(row=0,column=1,sticky="nsew",padx=20,pady=20)
        self.content_label = ctk.CTkLabel(self.content_frame,text="hello",font=("Arial",20))
        self.content_label.grid(row=0,column=0,padx=10,pady=10)
        




if __name__ == "__main__": 
    try: 
        app = Dash()
        app.mainloop()
    except KeyboardInterrupt as ke : 
        print(f"[!] Keyboard Interrupt")
    except Exception as e : 
        print(f"[!] Error: {e}")