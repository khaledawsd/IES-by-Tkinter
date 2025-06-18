import datetime
import re
import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image, ImageTk
import os
import logging
import tkinterdnd2
from login import LoginScreen
from encryption import EncryptionManager

class ImageEncryptionApp(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)
        self.withdraw()  # Hide the main window initially
        self.login_screen = LoginScreen(self.on_login_success)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)  # Set up closing handler

        self.encryption_manager = EncryptionManager()

        self.login_screen.mainloop()

    def on_closing(self):
        self.login_screen.clean_up()  # Clean up database connection
        self.destroy() 

    def on_login_success(self):
        self.deiconify()  # Show the main window
        self.title("Advanced Image Encryption System")
        self.geometry("800x900")
        self.configure(bg="#2b2b2b")

        self.file_path = ""
        self.key = None
        self.encryption_method = ctk.StringVar(value="AES-GCM")
        self.appearance_mode = ctk.StringVar(value="Dark")
        self.image_preview_object = None  # Store the image object to avoid garbage collection
        self.settings_window = None  # Initialize settings_window attribute

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.setup_logging()
        self.create_widgets()

        # Setup drag and drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)

        self.update_background_color()

    def setup_logging(self):
        logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

    def create_widgets(self):
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Clear button
        clear_icon = self.load_icon("clear.png")
        self.clear_button = ctk.CTkButton(self.frame, text="", image=clear_icon, width=30, height=30, 
                                          corner_radius=15, command=self.clear_image)
        self.clear_button.place(x=40, y=22)

        # Settings button (Top right corner)
        settings_icon = self.load_icon("settings.png")
        self.settings_button = ctk.CTkButton(self.frame, text="", image=settings_icon, width=30, height=30, 
                                             corner_radius=15, command=self.open_settings)
        self.settings_button.place(relx=1.0, x=-40, y=22, anchor="ne")

        self.label = ctk.CTkLabel(self.frame, text="Advanced Image Encryption System", font=("Roboto", 28, "bold"))
        self.label.pack(pady=20, padx=10)

        # Image selection section
        select_icon = self.load_icon("folder.png")
        self.select_button = ctk.CTkButton(self.frame, text="Select Image", image=select_icon, compound="left", command=self.select_image)
        self.select_button.pack(pady=12, padx=10)

        self.file_label = ctk.CTkLabel(self.frame, text="No file selected", height=30)
        self.file_label.pack(pady=(0, 12), padx=10)

        # Image preview section
        self.preview_frame = ctk.CTkFrame(self.frame, width=320, height=320)
        self.preview_frame.pack(pady=2, padx=2)
        self.preview_frame.pack_propagate(False)  # Prevent the frame from shrinking
        self.preview_label = ctk.CTkLabel(self.preview_frame, text="Image Preview")
        self.preview_label.pack(pady=2)
        self.image_preview = ctk.CTkLabel(self.preview_frame, text="Select or drop your image here", width=50, height=50)
        self.image_preview.pack(expand=True)

        # Encryption method section
        self.method_label = ctk.CTkLabel(self.frame, text="Encryption Method:", font=("Roboto", 16))
        self.method_label.pack(pady=(20, 5), padx=10)

        self.method_menu = ctk.CTkOptionMenu(self.frame, variable=self.encryption_method, values=["AES-GCM", "RSA", "DES", "ChaCha20"])
        self.method_menu.pack(pady=(0, 20), padx=10)

        # Key display section
        key_frame = ctk.CTkFrame(self.frame)
        key_frame.pack(pady=(20, 5), padx=10, fill='x')

        self.key_label = ctk.CTkLabel(key_frame, text="Encryption Key:", font=("Roboto", 16))
        self.key_label.pack(side='left', pady=(20, 20), padx=(10, 5))

        key_display_frame = ctk.CTkFrame(key_frame)
        key_display_frame.pack(side='left', expand=True, fill='x', pady=(20, 20), padx=5)

        self.key_display = ctk.CTkEntry(key_display_frame, state='readonly')
        self.key_display.pack(expand=True, fill='x')

        # Download button
        download_icon = self.load_icon("download.png")
        self.download_button = ctk.CTkButton(key_frame, text="", image=download_icon, width=30, height=30, 
                                            corner_radius=10, command=self.download_key)
        self.download_button.pack(side='left', pady=(20, 20), padx=(5, 10))

        # Action buttons section
        button_frame = ctk.CTkFrame(self.frame)
        button_frame.pack(pady=20, padx=10)

        encrypt_icon = self.load_icon("lock.png")
        self.encrypt_button = ctk.CTkButton(button_frame, text="Encrypt", image=encrypt_icon, compound="left", command=self.encrypt_image)
        self.encrypt_button.pack(side="left", padx=10)

        decrypt_icon = self.load_icon("unlock.png")
        self.decrypt_button = ctk.CTkButton(button_frame, text="Decrypt", image=decrypt_icon, compound="left", command=self.decrypt_image)
        self.decrypt_button.pack(side="left", padx=10)

        self.status_label = ctk.CTkLabel(self.frame, text="", height=50)
        self.status_label.pack(pady=20, padx=10)
        
    def load_icon(self, filename):
        return ImageTk.PhotoImage(Image.open(f"assets/{filename}").resize((20, 20)))

    def open_settings(self):
        if self.settings_window is None or not self.settings_window.winfo_exists():
            self.settings_window = SettingsWindow(self)
            self.settings_window.grab_set()
        else:
            self.settings_window.deiconify()
            self.settings_window.lift()

    def toggle_appearance_mode(self):
        new_mode = "Light" if self.appearance_mode.get() == "Dark" else "Dark"
        self.appearance_mode.set(new_mode)
        ctk.set_appearance_mode(new_mode.lower())
        self.update_menu_colors()
        self.update_background_color()
        
    def setup_drag_and_drop(self):
        self.drop_label.drop_target_register(tkinterdnd2.DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        file_path = event.data
        if file_path.startswith('{') and file_path.endswith('}'): 
            file_path = file_path[1:-1]  # Remove curly braces if present
        
        if os.path.isfile(file_path):
            _, file_extension = os.path.splitext(file_path)
            if file_extension.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                self.file_path = file_path
                self.file_label.configure(text=f"Selected: {os.path.basename(self.file_path)}")
                self.status_label.configure(text="Image selected")
                self.update_image_preview()
            else:
                messagebox.showerror("Error", "Please drop a valid image file.")
        else:
            messagebox.showerror("Error", "The dropped item is not a valid file.")


    def select_image(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp")])
        if self.file_path:
            self.file_label.configure(text=f"Selected: {os.path.basename(self.file_path)}")
            self.status_label.configure(text="Image selected")
            self.update_image_preview()

    def clear_image(self):
        self.file_path = ""
        self.file_label.configure(text="No file selected\nDrag and drop an image here")
        self.image_preview.configure(image=None, text="No image selected")
        self.image_preview.image = None  # Clear the image reference
        self.image_preview_object = None  # Clear the image object reference
        self.status_label.configure(text="Image cleared")

    def update_image_preview(self):
        if self.file_path:
            image = Image.open(self.file_path)
            image.thumbnail((250, 250))  # Resize image to fit in preview
            self.image_preview_object = ImageTk.PhotoImage(image)
            self.image_preview.configure(image=self.image_preview_object, text="")
            self.image_preview.image = self.image_preview_object  # Prevent garbage collection
        else:
            self.image_preview.configure(image=None, text="No image selected")
            self.image_preview.image = None  # Clear the image reference

    def encrypt_image(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        try:
            method = self.encryption_method.get()
            output_path, key = self.encryption_manager.encrypt_image(method, self.file_path)

            if output_path:
                self.key_display.configure(state='normal')
                self.key_display.delete(0, ctk.END)
                self.key_display.insert(0, key)
                self.key_display.configure(state='readonly')

                self.status_label.configure(text=f"Image encrypted successfully with {method}!")
                messagebox.showinfo("Success", f"Image encrypted and saved as {os.path.basename(output_path)}")
            else:
                self.status_label.configure(text="Encryption cancelled.")
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def download_key(self):
        if self.key_display.get():
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(self.key_display.get())
                messagebox.showinfo("Success", f"Encryption key saved to {file_path}")
        else:
            messagebox.showerror("Error", "No encryption key to save.")

    def decrypt_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
        if not file_path:
            return

        try:
            method = self.encryption_manager.detect_encryption_method(file_path)
            key_input = ctk.CTkInputDialog(text=f"Enter the {method} decryption key (hex):", title=f"{method} Decryption Key").get_input()
            if not key_input:
                return

            output_path = self.encryption_manager.decrypt_image(method, file_path, key_input)

            self.status_label.configure(text=f"Image decrypted successfully with {method}!")
            messagebox.showinfo("Success", f"Image decrypted and saved as {os.path.basename(output_path)}")
        except ValueError:
            messagebox.showerror("Error", "Invalid key format or decryption failed.")
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed. Please ensure you entered the correct key.")

class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Settings")
        self.geometry("800x500")
        self.master = master

        # Configure grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Create sidebar frame
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        # Create main content frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # Sidebar elements
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Settings", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.change_password_button = ctk.CTkButton(self.sidebar_frame, text="Change Password",
                                                    command=lambda: self.show_tab("change_password"))
        self.change_password_button.grid(row=1, column=0, padx=20, pady=10)

        # Create frames for each tab's content
        self.change_password_frame = ctk.CTkFrame(self.main_frame)

        # Change Password Content
        self.change_password_label = ctk.CTkLabel(self.change_password_frame,
                                                  text="Change Password", font=ctk.CTkFont(size=24, weight="bold"))
        self.change_password_label.pack(pady=(20, 30))

        self.username_entry = ctk.CTkEntry(self.change_password_frame, width=300, placeholder_text="Username")
        self.username_entry.pack(pady=10)
        self.username_entry.bind("<Return>", self.focus_current_password_entry)

        self.current_password_entry = ctk.CTkEntry(self.change_password_frame, show="*", width=300, placeholder_text="Current Password")
        self.current_password_entry.pack(pady=10)
        self.current_password_entry.bind("<Return>", self.focus_new_password_entry)

        self.new_password_entry = ctk.CTkEntry(self.change_password_frame, show="*", width=300, placeholder_text="New Password")
        self.new_password_entry.pack(pady=10)
        self.new_password_entry.bind("<KeyRelease>", self.check_password_strength)
        self.new_password_entry.bind("<Return>", self.focus_confirm_password_entry)

        self.confirm_password_entry = ctk.CTkEntry(self.change_password_frame, show="*", width=300, placeholder_text="Confirm New Password")
        self.confirm_password_entry.pack(pady=10)
        self.confirm_password_entry.bind("<Return>", self.trigger_change_password)

        self.strength_progress = ctk.CTkProgressBar(self.change_password_frame, width=250)
        self.strength_progress.pack(pady=5)
        self.strength_progress.set(0)

        self.strength_label = ctk.CTkLabel(self.change_password_frame, text="Password Strength: ")
        self.strength_label.pack(pady=5)

        self.show_password_var = ctk.BooleanVar()
        self.show_password_checkbox = ctk.CTkCheckBox(self.change_password_frame, text="Show Password",
                                                      variable=self.show_password_var, command=self.toggle_password_visibility)
        self.show_password_checkbox.pack(pady=10)

        self.change_password_button = ctk.CTkButton(self.change_password_frame, text="Change Password",
                                                    command=self.change_password)
        self.change_password_button.pack(pady=20)

        # Show the default tab
        self.show_tab("change_password")

    def show_tab(self, tab_name):
        self.change_password_frame.pack_forget()

        if tab_name == "change_password":
            self.change_password_frame.pack(expand=True, fill="both")

        self.change_password_button.configure(fg_color=("gray75", "gray25") if tab_name == "change_password" else ("gray70", "gray30"))

    def check_password_strength(self, event):
        password = self.new_password_entry.get()
        strength = self.evaluate_password_strength(password)
        strength_text = self.get_strength_text(strength)
        self.strength_label.configure(text=f"Password Strength: {strength_text}")
        self.strength_progress.set(strength / 5)

    def change_password(self):
        username = self.username_entry.get()
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match.")
            return

        strength = self.evaluate_password_strength(new_password)
        if strength < 3:
            messagebox.showerror("Error", "Password must be Strong or Very Strong.")
            return

        user = self.master.login_screen.db.get_user(username)

        if not user or not self.master.login_screen.db.verify_password(user[3], user[2], current_password):
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        if self.master.login_screen.db.change_password(username, new_password):
            messagebox.showinfo("Success", "Password changed successfully!")
            self.username_entry.delete(0, 'end')
            self.current_password_entry.delete(0, 'end')
            self.new_password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
        else:
            messagebox.showerror("Error", "Failed to change password.")

    def focus_current_password_entry(self, event):
        self.current_password_entry.focus_set()

    def focus_new_password_entry(self, event):
        self.new_password_entry.focus_set()

    def focus_confirm_password_entry(self, event):
        self.confirm_password_entry.focus_set()

    def trigger_change_password(self, event):
        self.change_password()

    @staticmethod
    def evaluate_password_strength(password):
        strength = 0
        if len(password) >= 8:
            strength += 1
        if re.search(r"[A-Z]", password):
            strength += 1
        if re.search(r"[a-z]", password):
            strength += 1
        if re.search(r"[0-9]", password):
            strength += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            strength += 1
        return strength

    @staticmethod
    def get_strength_text(strength):
        if strength < 2:
            return "Weak"
        elif strength < 3:
            return "Medium"
        elif strength < 4:
            return "Strong"
        else:
            return "Very Strong"

    def toggle_password_visibility(self):
        show = '' if self.show_password_var.get() else '*'
        self.current_password_entry.configure(show=show)
        self.new_password_entry.configure(show=show)
        self.confirm_password_entry.configure(show=show)

if __name__ == "__main__":
    app = ImageEncryptionApp()
    app.mainloop()
