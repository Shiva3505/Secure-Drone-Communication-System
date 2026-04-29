"""
signature.py
Digital signatures using RSA with PKCS#1 v1.5 and SHA-256.

  - Drone signs the plaintext message with its RSA private key
  - Ground Station verifies the signature using the Drone's RSA public key
  - This provides authenticity (message came from the Drone) and
    non-repudiation (Drone cannot deny sending it)
"""

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def sign_message(message: str, private_key) -> bytes:
    """
    Sign a UTF-8 message string with the given RSA private key.
    Returns the raw signature bytes.
    """
    digest = SHA256.new(message.encode("utf-8"))
    signature = pkcs1_15.new(private_key).sign(digest)
    return signature


def verify_signature(message: str, signature: bytes, public_key) -> bool:
    """
    Verify an RSA signature against the message using the given public key.
    Returns True if valid, False if tampered or wrong key.

    Only catches ValueError (bad signature) and TypeError (wrong input type).
    Other exceptions (e.g., programming errors) are intentionally NOT suppressed.
    """
    digest = SHA256.new(message.encode("utf-8"))
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False