"""
key_exchange.py
Diffie-Hellman key exchange using the cryptography library.
A 512-bit DH group is used here for demo speed; use 2048-bit in production.
The raw shared secret is passed through HKDF-SHA256 to derive a 16-byte AES key.
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate DH parameters once and share between both parties
# key_size=512 is used here only for fast demo; use 2048 in production
_parameters = dh.generate_parameters(
    generator=2,
    key_size=512,
    backend=default_backend()
)


def generate_private_key():
    """Generate a DH private key."""
    return _parameters.generate_private_key()


def generate_public_key(private_key):
    """Derive the DH public key from a private key."""
    return private_key.public_key()


def generate_shared_key(private_key, peer_public_key):
    """
    Perform DH exchange and derive a 16-byte AES session key via HKDF-SHA256.
    Both parties must call this with their own private key and the other's public key.
    """
    raw_shared = private_key.exchange(peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"drone-gcs-session",
        backend=default_backend()
    ).derive(raw_shared)

    return derived_key