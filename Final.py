import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib
import sqlite3
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Initialize the SQLite database
conn = sqlite3.connect('local_database.db')
cursor = conn.cursor()

# Database setup
def initialize_database():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT,
            name TEXT,
            birthday TEXT,
            phone_number TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT,
            receiver_email TEXT,
            subject TEXT,
            content TEXT,
            mac TEXT,
            position INTEGER
        )
    ''')
    conn.commit()

initialize_database()

# Utility Functions
def calculate_shared_key(sender, receiver):
    key_material = (sender + receiver).encode()
    return hashlib.sha256(key_material).digest()

def pad_message(message, block_size):
    pad_len = block_size - (len(message) % block_size)
    return message + bytes([pad_len] * pad_len)

def cbc_mac(key, message, iv):
    block_size = 16  # AES block size
    padded_message = pad_message(message, block_size)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext[-block_size:]

# MessagingApp Class
class MessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Messaging App")
        self.current_user = None
        self.setup_login_screen()

    def setup_login_screen(self):
        # Clear screen
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Login", font=("Arial", 20)).pack(pady=10)

        tk.Label(self.root, text="Email").pack()
        self.email_entry = tk.Entry(self.root)
        self.email_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.authenticate_user).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.setup_register_screen).pack()

    def setup_register_screen(self):
        # Clear screen
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Register", font=("Arial", 20)).pack(pady=10)

        tk.Label(self.root, text="Name").pack()
        self.name_entry = tk.Entry(self.root)
        self.name_entry.pack()

        tk.Label(self.root, text="Birthday (YYYY-MM-DD)").pack()
        self.birthday_entry = tk.Entry(self.root)
        self.birthday_entry.pack()

        tk.Label(self.root, text="Phone Number").pack()
        self.phone_entry = tk.Entry(self.root)
        self.phone_entry.pack()

        tk.Label(self.root, text="Email").pack()
        self.reg_email_entry = tk.Entry(self.root)
        self.reg_email_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.reg_password_entry = tk.Entry(self.root, show="*")
        self.reg_password_entry.pack()

        tk.Button(self.root, text="Register", command=self.register_user).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.setup_login_screen).pack()

    def authenticate_user(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        if not email or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?', (email, password_hash))
        user = cursor.fetchone()

        if user:
            self.current_user = email
            messagebox.showinfo("Success", f"Welcome, {email}!")
            self.setup_dashboard()
        else:
            messagebox.showerror("Error", "Invalid email or password.")

    def register_user(self):
        name = self.name_entry.get()
        birthday = self.birthday_entry.get()
        phone = self.phone_entry.get()
        email = self.reg_email_entry.get()
        password = self.reg_password_entry.get()

        if not all([name, birthday, phone, email, password]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if not email.endswith(("@gmail.com", "@yahoo.com", "@hotmail.com")):
            messagebox.showerror("Error", "Please enter a valid email.")
            return

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        try:
            cursor.execute('INSERT INTO users (email, password_hash, name, birthday, phone_number) VALUES (?, ?, ?, ?, ?)',
                           (email, password_hash, name, birthday, phone))
            conn.commit()
            messagebox.showinfo("Success", "Account created successfully!")
            self.setup_login_screen()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Email already registered.")

    def setup_dashboard(self):
        # Clear screen
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Welcome, {self.current_user}", font=("Arial", 20)).pack(pady=10)

        tk.Button(self.root, text="Send Message", command=self.send_message_screen).pack(pady=5)
        tk.Button(self.root, text="View Messages", command=self.view_messages).pack(pady=5)
        tk.Button(self.root, text="Logout", command=self.setup_login_screen).pack(pady=5)

    def send_message_screen(self):
        # Clear screen
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Send Message", font=("Arial", 20)).pack(pady=10)

        tk.Label(self.root, text="Receiver Email").pack()
        self.receiver_entry = tk.Entry(self.root)
        self.receiver_entry.pack()

        tk.Label(self.root, text="Subject").pack()
        self.subject_entry = tk.Entry(self.root)
        self.subject_entry.pack()

        tk.Label(self.root, text="Message").pack()
        self.message_entry = tk.Text(self.root, height=5, width=40)
        self.message_entry.pack()

        tk.Button(self.root, text="Send", command=self.send_message).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.setup_dashboard).pack()

    def send_message(self):
        receiver_email = self.receiver_entry.get()
        subject = self.subject_entry.get()
        content = self.message_entry.get("1.0", tk.END).strip()

        cursor.execute('SELECT * FROM users WHERE email = ?', (receiver_email,))
        recipient = cursor.fetchone()

        if not recipient:
            messagebox.showerror("Error", "Recipient not found.")
            return

        if not content:
            messagebox.showerror("Error", "Message cannot be empty.")
            return

        shared_key = calculate_shared_key(self.current_user, receiver_email)
        position = cursor.execute('SELECT COUNT(*) FROM messages WHERE receiver_email = ?', (receiver_email,)).fetchone()[0] + 1
        iv = secrets.token_bytes(16)
        mac = cbc_mac(shared_key, content.encode(), iv)

        cursor.execute('INSERT INTO messages (sender_email, receiver_email, subject, content, mac, position) VALUES (?, ?, ?, ?, ?, ?)',
                       (self.current_user, receiver_email, subject, content, mac.hex(), position))
        conn.commit()

        messagebox.showinfo("Success", "Message sent successfully!")
        self.setup_dashboard()

    def view_messages(self):
        messages = self.load_messages(self.current_user)
        if not messages:
            messagebox.showinfo("Info", "No messages to display.")
            return

        for message in messages:
            content = f"From: {message['sender_email']}\nSubject: {message['subject']}\n\n{message['content']}"
            messagebox.showinfo("Message", content)

    def load_messages(self, receiver_email):
        cursor.execute('SELECT * FROM messages WHERE receiver_email = ? ORDER BY position', (receiver_email,))
        messages = cursor.fetchall()
        return [
            {
                'id': row[0],
                'sender_email': row[1],
                'receiver_email': row[2],
                'subject': row[3],
                'content': row[4],
                'mac': row[5],
                'position': row[6],
            }
            for row in messages
        ]

# Run the App
if __name__ == "__main__":
    root = tk.Tk()
    app = MessagingApp(root)
    root.mainloop()
