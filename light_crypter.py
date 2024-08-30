from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import bson
import os


def password_to_key(password):
    h = SHA256.new()
    h.update(password.encode())
    key = h.digest()
    return key


def decrypt(ciphertext, key):
    nonce, tag = ciphertext[:12], ciphertext[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext[12:-16], tag)
    decoded_data = bson.BSON(plaintext).decode()
    return decoded_data


def encrypt(data, key):
    encoded_data = bson.BSON.encode(data)
    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(encoded_data)
    return nonce + ciphertext + tag
