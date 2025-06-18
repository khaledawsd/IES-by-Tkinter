import os
import secrets
from Crypto.Cipher import AES, DES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from tkinter import filedialog
import logging

class EncryptionManager:
    def __init__(self):
        self.key = None

    def generate_key(self, method):
        if method == "AES-GCM":
            key = secrets.token_bytes(32)  # 256-bit key
            return key.hex()
        elif method == "RSA":
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            return private_key.decode(), public_key.decode()
        elif method == "DES":
            key = secrets.token_bytes(8)  # 64-bit key
            return key.hex()
        elif method == "ChaCha20":
            key = secrets.token_bytes(32)  # 256-bit key
            return key.hex()

    def encrypt_image(self, method, file_path):
        if method == "AES-GCM":
            self.key = self.generate_key(method)
            return self.encrypt_aes_gcm(file_path), self.key
        elif method == "RSA":
            private_key, public_key = self.generate_key(method)
            self.key = public_key
            return self.encrypt_rsa(file_path, public_key), private_key
        elif method == "DES":
            self.key = self.generate_key(method)
            return self.encrypt_des(file_path), self.key
        elif method == "ChaCha20":
            self.key = self.generate_key(method)
            return self.encrypt_chacha20(file_path), self.key

    def encrypt_aes_gcm(self, file_path):
        key_bytes = bytes.fromhex(self.key)

        with open(file_path, 'rb') as file:
            image_data = file.read()

        cipher = AES.new(key_bytes, AES.MODE_GCM)
        encrypted_data, tag = cipher.encrypt_and_digest(image_data)

        default_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}_aes_gcm.encrypted"
        output_path = self.get_save_location(default_filename)

        if output_path:
            with open(output_path, 'wb') as file:
                file.write(cipher.nonce + tag + encrypted_data)

            return output_path
        return None

    def encrypt_rsa(self, file_path, public_key):
        recipient_key = RSA.import_key(public_key)

        with open(file_path, 'rb') as file:
            image_data = file.read()

        cipher_rsa = PKCS1_OAEP.new(recipient_key)

        default_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}_rsa.encrypted"
        output_path = self.get_save_location(default_filename)

        if output_path:
            with open(output_path, 'wb') as file:
                for i in range(0, len(image_data), 190):
                    chunk = image_data[i:i+190]
                    encrypted_chunk = cipher_rsa.encrypt(chunk)
                    file.write(encrypted_chunk)

            return output_path
        return None

    def encrypt_des(self, file_path):
        key_bytes = bytes.fromhex(self.key)

        with open(file_path, 'rb') as file:
            image_data = file.read()

        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(image_data, DES.block_size))

        default_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}_des.encrypted"
        output_path = self.get_save_location(default_filename)

        if output_path:
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)

            return output_path
        return None

    def encrypt_chacha20(self, file_path):
        key_bytes = bytes.fromhex(self.key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce

        with open(file_path, 'rb') as file:
            image_data = file.read()

        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        encrypted_data = cipher.encrypt(image_data)

        default_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}_chacha20.encrypted"
        output_path = self.get_save_location(default_filename)

        if output_path:
            with open(output_path, 'wb') as file:
                file.write(nonce + encrypted_data)

            return output_path
        return None

    def decrypt_image(self, method, file_path, key_input):
        if method == "AES-GCM":
            return self.decrypt_aes_gcm(file_path, key_input)
        elif method == "RSA":
            return self.decrypt_rsa(file_path, key_input)
        elif method == "DES":
            return self.decrypt_des(file_path, key_input)
        elif method == "ChaCha20":
            return self.decrypt_chacha20(file_path, key_input)

    def decrypt_aes_gcm(self, file_path, key_input):
        key = bytes.fromhex(key_input)
        with open(file_path, 'rb') as file:
            nonce = file.read(16)
            tag = file.read(16)
            encrypted_data = file.read()

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

        output_path = file_path.replace('_aes_gcm.encrypted', '_decrypted.png')
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)
        return output_path

    def decrypt_rsa(self, file_path, private_key_input):
        private_key = RSA.import_key(private_key_input)

        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        output_path = file_path.replace('_rsa.encrypted', '_decrypted.png')
        with open(output_path, 'wb') as file:
            for i in range(0, len(encrypted_data), 256):
                chunk = encrypted_data[i:i+256]
                decrypted_chunk = cipher_rsa.decrypt(chunk)
                file.write(decrypted_chunk)

        os.remove(file_path)
        return output_path

    def decrypt_des(self, file_path, key_input):
        key = bytes.fromhex(key_input)
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)

        output_path = file_path.replace('_des.encrypted', '_decrypted.png')
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)
        return output_path

    def decrypt_chacha20(self, file_path, key_input):
        key = bytes.fromhex(key_input)
        with open(file_path, 'rb') as file:
            nonce = file.read(12)
            encrypted_data = file.read()

        cipher = ChaCha20.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_data)

        output_path = file_path.replace('_chacha20.encrypted', '_decrypted.png')
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)
        return output_path

    def get_save_location(self, default_filename):
        return filedialog.asksaveasfilename(
            defaultextension=".encrypted",
            filetypes=[("Encrypted files", "*.encrypted")],
            initialfile=default_filename
        )

    def detect_encryption_method(self, file_path):
        if '_aes_gcm.encrypted' in file_path:
            return "AES-GCM"
        elif '_rsa.encrypted' in file_path:
            return "RSA"
        elif '_des.encrypted' in file_path:
            return "DES"
        elif '_chacha20.encrypted' in file_path:
            return "ChaCha20"
        else:
            raise ValueError("Unknown encryption method.")
