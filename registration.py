import customtkinter as ctk
from tkinter import messagebox, Menu
import re

# Function to evaluate password strength
def evaluate_password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search("[a-z]", password):
        strength += 1
    if re.search("[A-Z]", password):
        strength += 1
    if re.search("[0-9]", password):
        strength += 1
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    return strength

# Function to get textual representation of password strength
def get_strength_text(strength):
    if strength <= 1:
        return "Very Weak"
    elif strength == 2:
        return "Weak"
    elif strength == 3:
        return "Medium"
    elif strength == 4:
        return "Strong"
    elif strength == 5:
        return "Very Strong"

class SimpleRegistrationScreen(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Register New User")
        self.geometry("500x450")
        self.db = master.db
        self.master = master  # Store reference to the master window

        self.label = ctk.CTkLabel(self, text="Register New User", font=("Roboto", 20, "bold"))
        self.label.pack(pady=20)
        
        self.username_entry = ctk.CTkEntry(self, width=200, placeholder_text="Username")
        self.username_entry.pack(pady=5)
        self.username_entry.bind("<Return>", self.focus_password_entry)
        self.create_context_menu(self.username_entry)
        
        self.password_entry = ctk.CTkEntry(self, show="*", width=200, placeholder_text="Password")
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)
        self.password_entry.bind("<Return>", self.focus_confirm_password_entry)
        self.create_context_menu(self.password_entry)
        
        self.confirm_password_entry = ctk.CTkEntry(self, show="*", width=200, placeholder_text="Confirm Password")
        self.confirm_password_entry.pack(pady=5)
        self.confirm_password_entry.bind("<Return>", self.submit_registration)
        self.create_context_menu(self.confirm_password_entry)

        # Add password strength meter components
        self.strength_progress = ctk.CTkProgressBar(self, width=200)
        self.strength_progress.pack(pady=5)
        self.strength_progress.set(0)
        
        self.strength_label = ctk.CTkLabel(self, text="Password Strength: ")
        self.strength_label.pack(pady=5)
        
        
        self.register_button = ctk.CTkButton(self, text="Register", command=self.register)
        self.register_button.pack(pady=20)
        
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

    def check_password_strength(self, event):
        password = self.password_entry.get()
        strength = evaluate_password_strength(password)
        strength_text = get_strength_text(strength)
        self.strength_label.configure(text=f"Password Strength: {strength_text}")
        self.strength_progress.set(strength / 5)
    
    def focus_password_entry(self, event):
        self.password_entry.focus_set()

    def focus_confirm_password_entry(self, event):
        self.confirm_password_entry.focus_set()

    def submit_registration(self, event):
        self.register()
        
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return
        
        strength = evaluate_password_strength(password)
        if strength < 4:
            messagebox.showerror("Error", "Password must be Strong or Very Strong.")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        if self.db.add_user(username, password):
            messagebox.showinfo("Success", f"User {username} registered successfully!")
            self.master.refresh_user_data()  # Refresh user data on the AdminPage
            self.destroy()
        else:
            messagebox.showerror("Error", "Username already exists.")
