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
            else:
                messagebox.showerror("Login Failed", "Invalid email or password")

        except requests.RequestException as re: 
            messagebox.showerror("Error",re)

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

if __name__ == "__main__":
    app = AuthApp()
    app.mainloop()
