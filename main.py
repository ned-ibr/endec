from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64

def generate_key(password, salt):
    return scrypt(password, salt, 42, N=2**14, r=8, p=1)

def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = generate_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    cipher_text = base64.b64encode(cipher_text).decode('utf-8')
    return salt, iv, cipher_text

def decrypt_message(cipher_text, salt, iv, password):
    cipher_text = base64.b64decode(cipher_text)
    iv = base64.b64decode(iv)
    key = generate_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_message.decode('utf-8')

password = "super_secure_password"
message_to_encrypt = "This is a highly confidential message."
print("Original Message:", message_to_encrypt)
salt, iv, encrypted_message = encrypt_message(message_to_encrypt, password)
print("\nEncrypted Message:", encrypted_message)
decrypted_message = decrypt_message(encrypted_message, salt, iv, password)
print("\nDecrypted Message:", decrypted_message)
