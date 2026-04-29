"""
integrity.py
Message Authentication Code (MAC) using HMAC-SHA256.

The MAC is computed over (iv || ciphertext) so that:
  - Any tampering with the ciphertext is detected
  - Any tampering with the IV (which affects decryption output) is also detected
  - The key is the shared AES session key (bytes)
"""

import hmac
import hashlib


def generate_hmac(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Compute HMAC-SHA256 over the concatenation of IV and ciphertext.
    Returns a hex-encoded digest string.
    """
    mac = hmac.new(key, iv + ciphertext, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(iv: bytes, ciphertext: bytes, key: bytes, received_hmac: str) -> bool:
    """
    Recompute the MAC and compare with the received value using
    hmac.compare_digest to prevent timing attacks.
    Returns True if MACs match, False otherwise.
    """
    expected = generate_hmac(iv, ciphertext, key)
    return hmac.compare_digest(expected, received_hmac)