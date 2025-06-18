import sqlite3
import hashlib
import os
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode

class Database:
    def __init__(self, db_name='users.db', encryption_key='my_secret_key'):
        self.conn = sqlite3.connect(db_name)
        self.encryption_key = self.derive_key(encryption_key)
        self.create_table()

    def create_table(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS User (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    UserName TEXT NOT NULL UNIQUE,
                    Password TEXT NOT NULL,
                    PasswordHash TEXT NOT NULL,
                    Salt TEXT NOT NULL
                )
            """)

    def derive_key(self, password):
        salt = b'secret_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return urlsafe_b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted):
        encrypted = urlsafe_b64decode(encrypted.encode())
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def hash_password(self, password, salt=None):
        if not salt:
            salt = os.urandom(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return binascii.hexlify(salt).decode('utf-8'), binascii.hexlify(hashed).decode('utf-8')

    def add_user(self, username, password):
        salt, hashed_password = self.hash_password(password)
        encrypted_password = self.encrypt(password)
        try:
            with self.conn:
                self.conn.execute("INSERT INTO User (UserName, Password, PasswordHash, Salt) VALUES (?, ?, ?, ?)", 
                                  (username, encrypted_password, hashed_password, salt))
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_password(self, stored_salt, stored_hash, provided_password):
        salt = binascii.unhexlify(stored_salt.encode('utf-8'))
        provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return stored_hash == binascii.hexlify(provided_hash).decode('utf-8')

    def get_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute("SELECT UserName, Password, PasswordHash, Salt FROM User WHERE UserName = ?", (username,))
        return cursor.fetchone()
    
    def change_password(self, username, new_password):
        try:
            salt, hashed_password = self.hash_password(new_password)
            encrypted_password = self.encrypt(new_password)
            with self.conn:
                self.conn.execute("""
                    UPDATE User 
                    SET Password = ?, PasswordHash = ?, Salt = ? 
                    WHERE UserName = ?
                """, (encrypted_password, hashed_password, salt, username))
            return True
        except sqlite3.Error:
            return False

    def get_all_users(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT UserID, UserName, Password FROM User")
        return cursor.fetchall()

    def close(self):
        self.conn.close()
