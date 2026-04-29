"""
authentication.py
Password-based authentication using PBKDF2-HMAC-SHA256.

Why PBKDF2 instead of plain SHA-256?
  - Deliberately slow (100 000 iterations) → brute-force is expensive
  - Each password gets a unique random salt → prevents rainbow-table attacks
  - Passwords are NEVER stored in plaintext
"""

import hashlib
import hmac
import os


def hash_password(password: str) -> tuple[bytes, bytes]:
    """
    Hash a password with a fresh random 16-byte salt using PBKDF2-HMAC-SHA256.
    Returns (salt, hashed_password) — both as raw bytes.
    Store both; you need the salt to verify later.
    """
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=100_000
    )
    return salt, hashed


def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    """
    Re-derive the hash and compare using a constant-time comparison
    (hmac.compare_digest) to prevent timing-based attacks.
    Returns True if the password matches, False otherwise.
    """
    candidate = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=100_000
    )
    return hmac.compare_digest(candidate, stored_hash)


def generate_challenge() -> bytes:
    """
    Generate a 32-byte random challenge for challenge-response authentication.
    The Drone must sign this challenge with its RSA private key so the Ground
    Station can verify identity without transmitting the password.
    """
    return os.urandom(32)