from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open('fernet.key', 'wb') as f:
    f.write(key)

print("Fernet key generated and saved to fernet.key")