import customtkinter as ctk
from tkinter import messagebox, Menu
import re
from PIL import Image, ImageTk  # Import Image and ImageTk from PIL
from Database import Database  # Import the Database class
from Admin import AdminPage, DatabaseContentsPage  # Import the AdminPage and DatabaseContentsPage classes
from registration import SimpleRegistrationScreen, evaluate_password_strength, get_strength_text  # Import the necessary functions and registration screen

class LoginScreen(ctk.CTk):
    def __init__(self, on_login_success):
        super().__init__()
        self.title("Advanced Image Encryption System - Login")
        self.geometry("700x500")
        self.configure(bg="#2b2b2b")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.on_login_success = on_login_success
        self.appearance_mode = ctk.StringVar(value="Dark")
        
        self.db = Database()  # Initialize the database

        self.show_password = False  # Track password visibility
        self.create_widgets()

    def create_widgets(self):
        # Main frame
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Use grid layout
        self.frame.grid_rowconfigure(0, weight=0)
        self.frame.grid_rowconfigure(1, weight=0)
        self.frame.grid_rowconfigure(2, weight=1)  # Give weight to this row to take remaining space
        self.frame.grid_rowconfigure(3, weight=0)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=0)
        self.frame.grid_columnconfigure(2, weight=1)

        # Admin button
        self.admin_button = ctk.CTkButton(self.frame, text="Admin Login", command=self.open_admin_login, width=100)
        self.admin_button.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

        # Switch Theme button
        self.toggle_button = ctk.CTkButton(self.frame, text="Switch Theme", command=self.toggle_appearance_mode, width=100)
        self.toggle_button.grid(row=0, column=2, padx=10, pady=10, sticky="ne")

        # Logo or title
        self.title_label = ctk.CTkLabel(self.frame, text="Advanced Image Encryption System", font=("Roboto", 24, "bold"))
        self.title_label.grid(row=1, column=0, columnspan=3, pady=20)

        # Transparent frame around login section
        self.login_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        self.login_frame.grid(row=2, column=0, columnspan=3, pady=20, sticky="n")

        # Username entry
        self.username_entry = ctk.CTkEntry(self.login_frame, width=300, height=35, placeholder_text="Username")
        self.username_entry.pack(pady=(0, 10))
        self.username_entry.bind("<Return>", self.focus_password_entry)
        self.create_context_menu(self.username_entry)

        # Custom password entry with integrated visibility toggle
        self.password_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        self.password_frame.pack(pady=(0, 10))

        self.password_entry = ctk.CTkEntry(self.password_frame, show="*", width=300, height=35, placeholder_text="Password")
        self.password_entry.pack(side="left")
        self.password_entry.bind("<Return>", self.trigger_login)
        self.create_context_menu(self.password_entry)

        # Load and resize icons
        self.eye_icon = ImageTk.PhotoImage(Image.open("assets/eye.png").resize((20, 20), Image.LANCZOS))
        self.hide_icon = ImageTk.PhotoImage(Image.open("assets/hide.png").resize((20, 20), Image.LANCZOS))

        # Login button
        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login, width=300, height=35)
        self.login_button.pack(pady=(0, 10))

        # Register button
        self.register_button = ctk.CTkButton(self.login_frame, text="Register", command=self.open_register_screen, 
                                             width=300, height=35, fg_color="#3b3b3b", hover_color="#4b4b4b")
        self.register_button.pack(pady=(0, 10))
        
        # Status label
        self.status_label = ctk.CTkLabel(self.frame, text="", font=("Roboto", 12))
        self.status_label.grid(row=3, column=0, columnspan=3, pady=10)

    def create_context_menu(self, widget):
        context_menu = Menu(widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: self.copy(widget))
        context_menu.add_command(label="Paste", command=lambda: self.paste(widget))
        
        def show_context_menu(event):
            try:
                widget.selection_get()
                context_menu.entryconfig("Copy", state="normal")
            except:
                context_menu.entryconfig("Copy", state="disabled")
            context_menu.tk_popup(event.x_root, event.y_root)
        
        widget.bind("<Button-3>", show_context_menu)  # Bind right-click to show context menu

    def copy(self, widget):
        widget.clipboard_clear()
        widget.clipboard_append(widget.selection_get())

    def paste(self, widget):
        widget.insert('insert', widget.clipboard_get())

    def focus_password_entry(self, event):
        self.password_entry.focus_set()

    def trigger_login(self, event):
        self.login()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        user = self.db.get_user(username)
        if user and self.db.verify_password(user[3], user[2], password):  # user[3] is the salt, user[2] is the hashed password
            self.destroy()
            self.on_login_success()
        else:
            self.status_label.configure(text="Invalid username or password", text_color="red")
    
    def open_register_screen(self):
        self.register_screen = SimpleRegistrationScreen(self)
        self.register_screen.grab_set()

    def open_admin_login(self):
        self.admin_login_screen = AdminLoginScreen(self)
        self.admin_login_screen.grab_set()

    def open_db_contents_page(self):
        self.db_contents_page = DatabaseContentsPage(self)
        self.db_contents_page.grab_set()

    def toggle_appearance_mode(self):
        new_mode = "Light" if self.appearance_mode.get() == "Dark" else "Dark"
        self.appearance_mode.set(new_mode)
        ctk.set_appearance_mode(new_mode.lower())
        self.update_colors()

    def update_colors(self):
        bg_color = "white" if self.appearance_mode.get() == "Light" else "#2b2b2b"
        self.configure(bg=bg_color)
        self.frame.configure(bg=bg_color)
        # Update other widgets' colors as needed

    def clean_up(self):
        self.db.close()

    def toggle_password_visibility(self, event=None):
        self.show_password = not self.show_password
        if self.show_password:
            self.password_entry.configure(show="")
            self.toggle_button.configure(image=self.hide_icon)
        else:
            self.password_entry.configure(show="*")
            self.toggle_button.configure(image=self.eye_icon)


class AdminLoginScreen(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Admin Login")
        self.geometry("300x300")
        self.master = master

        self.label = ctk.CTkLabel(self, text="Admin Login", font=("Roboto", 20, "bold"))
        self.label.pack(pady=20)

        self.username_entry = ctk.CTkEntry(self, width=200, placeholder_text="Username")
        self.username_entry.pack(pady=5)
        self.username_entry.bind("<Return>", self.focus_password_entry)  # Bind Enter key to focus password entry

        self.password_entry = ctk.CTkEntry(self, show="*", width=200, placeholder_text="Password")
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<Return>", self.trigger_login)  # Bind Enter key to login

        self.login_button = ctk.CTkButton(self, text="Login", command=self.login, width=200)
        self.login_button.pack(pady=20)

    def focus_password_entry(self, event):
        self.password_entry.focus_set()

    def trigger_login(self, event):
        self.login()

    def login(self):
        admin_username = "admin"
        admin_password = "admin123"
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == admin_username and password == admin_password:
            self.open_admin_page()
            self.destroy()
        else:
            messagebox.showerror("Error", "Invalid admin credentials.")

    def open_admin_page(self):
        self.admin_page = AdminPage(self.master)
        self.admin_page.grab_set()

if __name__ == "__main__":
    app = LoginScreen(on_login_success=lambda: print("Logged in successfully"))
    app.mainloop()
