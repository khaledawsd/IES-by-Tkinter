import customtkinter as ctk
from tkinter import messagebox
from registration import SimpleRegistrationScreen  # Ensure this import is present

class AdminPage(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Admin Page")
        self.geometry("800x600")
        self.db = master.db
        self.master = master  # Store reference to the master window

        self.appearance_mode = ctk.StringVar(value=ctk.get_appearance_mode())
        self.configure_colors()

        self.create_widgets()
        self.update_widget_colors()  # Ensure all widgets are updated with the correct colors

    def configure_colors(self):
        if self.appearance_mode.get() == "Dark":
            self.configure(fg_color="#2b2b2b")
            self.text_color = "white"
            self.card_color = "#3b3b3b"
            self.canvas_color = "#2b2b2b"
        else:
            self.configure(fg_color="#f0f0f0")
            self.text_color = "black"
            self.card_color = "#ffffff"
            self.canvas_color = "#f0f0f0"

    def create_widgets(self):
        # Title
        self.title_label = ctk.CTkLabel(self, text="User Data Management", font=("Roboto", 24, "bold"), text_color=self.text_color)
        self.title_label.pack(pady=20)

        # Add User button
        self.add_user_button = ctk.CTkButton(self, text="Add User", command=self.open_register_user_page, fg_color="#4CAF50")
        self.add_user_button.pack(pady=10)

        # Search functionality
        self.search_frame = ctk.CTkFrame(self)
        self.search_frame.pack(pady=10, padx=20, fill="x")

        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Search by username")
        self.search_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        self.search_entry.bind("<Return>", self.trigger_search)  # Bind Enter key to trigger search

        self.search_button = ctk.CTkButton(self.search_frame, text="Search", command=self.search_users)
        self.search_button.pack(side="right")

        # Create a frame for the canvas and scrollbar
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True, padx=20, pady=10)

        # Create a canvas
        self.canvas = ctk.CTkCanvas(self.container, highlightthickness=0, bg=self.canvas_color)
        self.canvas.pack(side="left", fill="both", expand=True)

        # Add a scrollbar to the canvas
        self.scrollbar = ctk.CTkScrollbar(self.container, command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")

        # Configure the canvas
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', self.on_configure)

        # Create a frame inside the canvas
        self.scrollable_frame = ctk.CTkFrame(self.canvas, fg_color="transparent")

        # Add the new frame to a window in the canvas
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # Bind the canvas resizing to the scrollable frame
        self.scrollable_frame.bind("<Configure>", self.on_frame_configure)

        # Bind mouse wheel event to the canvas
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)

        self.user_cards = []  # Store references to user cards
        self.display_user_data()

    def trigger_search(self, event):
        self.search_users()

    def on_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        # Update the size of the canvas window to match the frame
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def display_user_data(self):
        users = self.db.get_all_users()
        for user in users:
            self.create_user_card(user)

    def create_user_card(self, user):
        card = ctk.CTkFrame(self.scrollable_frame, corner_radius=10, fg_color=self.card_color)
        card.pack(pady=10, padx=10, fill="x")

        user_id_label = ctk.CTkLabel(card, text=f"UserID: {user[0]}", text_color=self.text_color)
        user_id_label.pack(anchor="w", padx=10, pady=5)

        username_label = ctk.CTkLabel(card, text=f"Username: {user[1]}", text_color=self.text_color)
        username_label.pack(anchor="w", padx=10, pady=5)

        
        # Delete User button
        delete_button = ctk.CTkButton(card, text="Delete", command=lambda u=user: self.delete_user(u), fg_color="#F44336")
        delete_button.pack(pady=5, padx=10)

        self.user_cards.append((card, user[1]))  # Store the card and username

    def delete_user(self, user):
        response = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user {user[1]}?")
        if response:
            self.db.conn.execute("DELETE FROM User WHERE UserID = ?", (user[0],))
            self.db.conn.commit()
            self.refresh_user_data()

    def refresh_user_data(self):
        for card, _ in self.user_cards:
            card.destroy()
        self.user_cards.clear()
        self.display_user_data()

    def search_users(self):
        query = self.search_entry.get().lower()
        for card, username in self.user_cards:
            if query in username.lower():
                card.pack(pady=10, padx=10, fill="x")
            else:
                card.pack_forget()

        self.on_configure(None)  # Update scrollregion

    def open_db_contents_page(self):
        self.db_contents_page = DatabaseContentsPage(self)
        self.db_contents_page.grab_set()

    def open_register_user_page(self):
        self.register_user_page = SimpleRegistrationScreen(self)
        self.register_user_page.grab_set()

    def update_widget_colors(self):
        self.configure(fg_color=self.cget("fg_color"))
        self.title_label.configure(text_color=self.text_color)
        self.canvas.configure(bg=self.canvas_color)
        self.scrollable_frame.configure(fg_color="transparent")
        for card, _ in self.user_cards:
            card.configure(fg_color=self.card_color)
            for child in card.winfo_children():
                if isinstance(child, ctk.CTkLabel):
                    child.configure(text_color=self.text_color)
        self.canvas.configure(bg=self.cget("fg_color"))

# The DatabaseContentsPage class remains unchanged
class DatabaseContentsPage(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Database Contents")
        self.geometry("600x400")
        self.db = master.db

        self.label = ctk.CTkLabel(self, text="Database Contents", font=("Roboto", 20, "bold"))
        self.label.pack(pady=20)

        self.text = ctk.CTkTextbox(self, width=500, height=300)
        self.text.pack(pady=20)

        self.display_contents()

    def display_contents(self):
        users = self.db.conn.execute("SELECT * FROM User").fetchall()
        self.text.insert("1.0", "UserID\tUsername\tPassword\tPasswordHash\tSalt\n")
        self.text.insert("2.0", "--------------------------------------------------------\n")
        for user in users:
            self.text.insert("end", f"{user[0]}\t{user[1]}\t{user[2]}\t{user[3]}\t{user[4]}\n")
