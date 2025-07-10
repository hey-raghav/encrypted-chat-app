import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from encryption import set_fernet_key, encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime

class SecureChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', height=20)
        self.text_area.pack(padx=10, pady=5)

        self.entry = tk.Entry(master, width=60)
        self.entry.pack(padx=10, pady=5, side=tk.LEFT)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(padx=10, pady=5, side=tk.RIGHT)

        self.client_socket = socket.socket()
        try:
            self.client_socket.connect(("localhost", 9999))
            self.display_message("[+] Connected to the server.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect: {e}")
            master.destroy()
            return

        with open("rsa_keys/public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        self.fernet_key = Fernet.generate_key()
        set_fernet_key(self.fernet_key)

        encrypted_key = public_key.encrypt(
            self.fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.client_socket.sendall(encrypted_key)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def timestamp(self):
        return datetime.now().strftime("[%H:%M:%S]")

    def display_message(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, f"{self.timestamp()} {msg}\n")
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg:
            encrypted = encrypt_message(msg)
            try:
                self.client_socket.sendall(encrypted)
                self.display_message(f"You: {msg}")
                self.display_message(f"[Encrypted]: {encrypted.decode()}")
                self.entry.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Failed to send message.")

    def receive_messages(self):
        while True:
            try:
                encrypted_reply = self.client_socket.recv(4096)
                if not encrypted_reply:
                    self.display_message("[!] Server disconnected.")
                    break
                msg = decrypt_message(encrypted_reply)
                self.display_message(f"[Encrypted]: {encrypted_reply.decode()}")
                self.display_message(f"Server: {msg}")
            except Exception as e:
                break


if __name__ == '__main__':
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()

