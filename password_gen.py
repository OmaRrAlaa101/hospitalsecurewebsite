from werkzeug.security import generate_password_hash
import pyotp

print("NUMBER=",generate_password_hash('admin123'))
print("NUMBER=",pyotp.random_base32())