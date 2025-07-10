import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from encryption import set_fernet_key, encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

class SecureChatServer:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Server")

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', height=20)
        self.text_area.pack(padx=10, pady=5)

        self.entry = tk.Entry(master, width=60)
        self.entry.pack(padx=10, pady=5, side=tk.LEFT)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(padx=10, pady=5, side=tk.RIGHT)

        self.server_socket = socket.socket()
        self.server_socket.bind(("0.0.0.0", 9999))
        self.server_socket.listen(1)

        self.display_message("[+] Waiting for connection on port 9999...")

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def timestamp(self):
        return datetime.now().strftime("[%H:%M:%S]")

    def display_message(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, f"{self.timestamp()} {msg}\n")
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def accept_connection(self):
        with open("rsa_keys/private_key.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

        self.conn, self.addr = self.server_socket.accept()
        self.display_message(f"[+] Connected by {self.addr}")

        encrypted_key = self.conn.recv(1024)
        fernet_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        set_fernet_key(fernet_key)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg:
            encrypted = encrypt_message(msg)
            try:
                self.conn.sendall(encrypted)
                self.display_message(f"You: {msg}")
                self.display_message(f"[Encrypted]: {encrypted.decode()}")
                self.entry.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Failed to send message.")

    def receive_messages(self):
        while True:
            try:
                encrypted_msg = self.conn.recv(4096)
                if not encrypted_msg:
                    self.display_message("[!] Client disconnected.")
                    break
                msg = decrypt_message(encrypted_msg)
                self.display_message(f"[Encrypted]: {encrypted_msg.decode()}")
                self.display_message(f"Client: {msg}")
            except:
                break


if __name__ == '__main__':
    root = tk.Tk()
    app = SecureChatServer(root)
    root.mainloop()
