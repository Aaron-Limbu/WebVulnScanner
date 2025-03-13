import src.interfaces.login as LoginUI 

if __name__ == "__main__": 
    try: 
        app = LoginUI.AuthApp()
        app.mainloop()
    except KeyboardInterrupt as ke : 
        print("[i] Keyboard Interrupted")
        exit(0)
    except Exception as e: 
        print("[!] ",e)