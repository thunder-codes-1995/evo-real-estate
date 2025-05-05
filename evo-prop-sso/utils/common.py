from cryptography.fernet import Fernet


KEY = Fernet.generate_key()
fernet = Fernet(KEY)

# Function to encrypt the password
def encrypt_password(password: str) -> str:
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password.decode()

# Function to decrypt the password
def decrypt_password(encrypted_password: str) -> str:
    decrypted_password = fernet.decrypt(encrypted_password.encode())
    return decrypted_password.decode()