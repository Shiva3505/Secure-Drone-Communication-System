"""
encryption.py
Hybrid encryption:
  - RSA-2048 with OAEP padding to wrap/unwrap the AES session key
  - AES-128-CBC with PKCS7 padding to encrypt/decrypt the drone payload
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


def generate_rsa_keys():
    """
    Generate a 2048-bit RSA key pair.
    Returns (private_key, public_key).
    """
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


def encrypt_aes(data: str, key: bytes):
    """
    Encrypt a UTF-8 string with AES-128-CBC.
    A random 16-byte IV is generated per message.
    Returns (iv, ciphertext) as raw bytes.
    """
    cipher = AES.new(key, AES.MODE_CBC)          # IV auto-generated
    ciphertext = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    return cipher.iv, ciphertext


def decrypt_aes(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt AES-128-CBC ciphertext.
    Returns the original plaintext string.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")


def encrypt_session_key(session_key: bytes, public_key) -> bytes:
    """
    Encrypt a session key with RSA-OAEP (public key).
    Used by the Drone to securely send the AES key to the Ground Station.
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(session_key)


def decrypt_session_key(enc_key: bytes, private_key) -> bytes:
    """
    Decrypt a session key with RSA-OAEP (private key).
    Used by the Ground Station to recover the AES session key.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(enc_key)