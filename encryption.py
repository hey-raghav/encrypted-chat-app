from cryptography.fernet import Fernet

cipher = None

def set_fernet_key(key):
    global cipher
    cipher = Fernet(key)

def encrypt_message(msg):
    return cipher.encrypt(msg.encode())

def decrypt_message(token):
    return cipher.decrypt(token).decode()

