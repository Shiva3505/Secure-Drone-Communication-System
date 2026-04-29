"""
main.py
Secure Drone ↔ Ground Control Station (GCS) Communication Protocol

Workflow:
  1. Drone authenticates with GCS (PBKDF2 password hashing)
  2. Diffie-Hellman key exchange → shared secret → AES session key (HKDF)
  3. AES session key additionally wrapped with RSA-OAEP for hybrid encryption
  4. Drone builds telemetry payload with timestamp + random nonce
  5. Drone encrypts payload (AES-CBC), signs plaintext (RSA), computes MAC (HMAC-SHA256)
  6. GCS verifies: replay protection → signature → MAC → decryption

Libraries required:
  pip install pycryptodome cryptography
"""

import json
import os
import time

from authentication import hash_password, verify_password, generate_challenge
from encryption import (
    generate_rsa_keys,
    encrypt_aes, decrypt_aes,
    encrypt_session_key, decrypt_session_key,
)
from integrity import generate_hmac, verify_hmac
from key_exchange import generate_private_key, generate_public_key, generate_shared_key
from signature import sign_message, verify_signature

# ---------------------------------------------------------------------------
# In-memory nonce store (simulates GCS persistent store)
# In production this would be a database / Redis set with a TTL
# ---------------------------------------------------------------------------
used_nonces: set[str] = set()

# ---------------------------------------------------------------------------
# STEP 1 — Authentication
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 1: Authentication")
print("=" * 60)

DRONE_PASSWORD = "SecureDrone@2024"

# GCS stores only (salt, hash) — never the plaintext password
salt, stored_hash = hash_password(DRONE_PASSWORD)
print(f"[GCS]   Password hash stored (PBKDF2-HMAC-SHA256, 100k iterations)")
print(f"[GCS]   Salt (hex): {salt.hex()}")

# Drone sends password → GCS verifies
if not verify_password(DRONE_PASSWORD, salt, stored_hash):
    print("[GCS]   Authentication FAILED — aborting.")
    exit(1)

print("[GCS]   Authentication SUCCESS\n")

# Optional: challenge-response step (demonstrates the helper)
challenge = generate_challenge()
print(f"[GCS]   Challenge issued (hex): {challenge.hex()}")

# ---------------------------------------------------------------------------
# STEP 2 — Diffie-Hellman Key Exchange
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 2: Diffie-Hellman Key Exchange")
print("=" * 60)

drone_dh_private  = generate_private_key()
server_dh_private = generate_private_key()

drone_dh_public  = generate_public_key(drone_dh_private)
server_dh_public = generate_public_key(server_dh_private)

# Each side independently computes the same shared key
session_key_drone  = generate_shared_key(drone_dh_private,  server_dh_public)
session_key_server = generate_shared_key(server_dh_private, drone_dh_public)

assert session_key_drone == session_key_server, "DH shared keys do not match!"

print(f"[Drone] DH shared key derived (hex): {session_key_drone.hex()}")
print(f"[GCS]   DH shared key derived (hex): {session_key_server.hex()}")
print(f"[✓]    Keys match: {session_key_drone == session_key_server}\n")

# ---------------------------------------------------------------------------
# STEP 3 — Hybrid Encryption: RSA wraps the AES session key
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 3: Hybrid Encryption — RSA wraps AES session key")
print("=" * 60)

# GCS generates an RSA key pair; Drone encrypts the DH-derived AES key with it
gcs_rsa_private, gcs_rsa_public = generate_rsa_keys()

encrypted_session_key = encrypt_session_key(session_key_drone, gcs_rsa_public)
print(f"[Drone] Session key encrypted with GCS RSA public key")
print(f"[Drone] Encrypted key (hex, first 32 bytes): {encrypted_session_key.hex()[:64]}...")

recovered_session_key = decrypt_session_key(encrypted_session_key, gcs_rsa_private)
print(f"[GCS]   Session key decrypted (hex): {recovered_session_key.hex()}")
print(f"[✓]    Session keys match: {session_key_drone == recovered_session_key}\n")

# Use recovered_session_key on the GCS side from here on
aes_key = session_key_drone          # Drone uses this
aes_key_gcs = recovered_session_key  # GCS uses this

# ---------------------------------------------------------------------------
# STEP 4 — Drone: Build payload, encrypt, sign, add MAC + nonce + timestamp
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 4: Drone prepares secure message")
print("=" * 60)

# Drone RSA keys for signing
drone_rsa_private, drone_rsa_public = generate_rsa_keys()

# Telemetry payload
nonce = os.urandom(16).hex()          # Cryptographically random, not time-based
timestamp = time.time()

payload = {
    "drone_id":  "DR001",
    "latitude":  12.9716,
    "longitude": 77.5946,
    "speed":     45,
    "altitude":  120,
    "timestamp": timestamp,
    "nonce":     nonce,
}

payload_str = json.dumps(payload, separators=(",", ":"))
print(f"[Drone] Plaintext payload:\n        {payload_str}\n")

# 4a. Encrypt with AES-CBC
iv, ciphertext = encrypt_aes(payload_str, aes_key)
print(f"[Drone] AES-CBC ciphertext (hex, first 32 bytes): {ciphertext.hex()[:64]}...")
print(f"[Drone] IV (hex): {iv.hex()}")

# 4b. Sign the PLAINTEXT (so GCS can verify before decrypting)
signature = sign_message(payload_str, drone_rsa_private)
print(f"[Drone] RSA signature generated (hex, first 32 bytes): {signature.hex()[:64]}...")

# 4c. HMAC over iv || ciphertext (protects both IV and encrypted data)
mac = generate_hmac(iv, ciphertext, aes_key)
print(f"[Drone] HMAC-SHA256 (hex): {mac}\n")

# ---------------------------------------------------------------------------
# STEP 5 — Ground Station: Verify everything, then decrypt
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 5: GCS verifies and decrypts")
print("=" * 60)

# 5a. Replay protection — FIRST check before any heavy crypto
print("[GCS]   Checking replay protection...")

received_nonce     = payload["nonce"]
received_timestamp = payload["timestamp"]
MAX_AGE_SECONDS    = 30          # Reject messages older than 30 s

if received_nonce in used_nonces:
    print("[GCS]   REPLAY ATTACK DETECTED — duplicate nonce. Message rejected.")
    exit(1)

if (time.time() - received_timestamp) > MAX_AGE_SECONDS:
    print("[GCS]   REPLAY ATTACK DETECTED — message too old. Message rejected.")
    exit(1)

used_nonces.add(received_nonce)
print(f"[GCS]   Nonce accepted: {received_nonce}")
print(f"[GCS]   Message age: {time.time() - received_timestamp:.4f}s (within {MAX_AGE_SECONDS}s window)")

# 5b. Verify HMAC
print("\n[GCS]   Verifying HMAC...")
if not verify_hmac(iv, ciphertext, aes_key_gcs, mac):
    print("[GCS]   MAC VERIFICATION FAILED — message tampered. Rejected.")
    exit(1)
print("[GCS]   HMAC verified ✓")

# 5c. Decrypt to recover plaintext (needed for signature verification)
print("\n[GCS]   Decrypting payload...")
decrypted_str = decrypt_aes(iv, ciphertext, aes_key_gcs)
print(f"[GCS]   Decrypted payload: {decrypted_str}")

# 5d. Verify digital signature
print("\n[GCS]   Verifying digital signature...")
if not verify_signature(decrypted_str, signature, drone_rsa_public):
    print("[GCS]   SIGNATURE VERIFICATION FAILED — authenticity not confirmed. Rejected.")
    exit(1)
print("[GCS]   Signature verified ✓")

# ---------------------------------------------------------------------------
# STEP 6 — Success summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("SECURE TRANSMISSION COMPLETE")
print("=" * 60)
received = json.loads(decrypted_str)
print(f"  Drone ID   : {received['drone_id']}")
print(f"  Latitude   : {received['latitude']}")
print(f"  Longitude  : {received['longitude']}")
print(f"  Speed      : {received['speed']} km/h")
print(f"  Altitude   : {received['altitude']} m")
print(f"  Timestamp  : {received['timestamp']}")
print(f"  Nonce      : {received['nonce']}")
print("\nAll security checks passed:")
print("  [✓] Password-based authentication (PBKDF2)")
print("  [✓] Diffie-Hellman key exchange + HKDF")
print("  [✓] Hybrid encryption (RSA-OAEP + AES-CBC)")
print("  [✓] Digital signature (RSA + SHA-256)")
print("  [✓] Message integrity (HMAC-SHA256 over IV+ciphertext)")
print("  [✓] Replay attack protection (random nonce + timestamp)")

# ---------------------------------------------------------------------------
# BONUS — Simulate a replay attack
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("BONUS: Replay Attack Simulation")
print("=" * 60)

print("[Attacker] Re-sending the exact same message (same nonce)...")
if received_nonce in used_nonces:
    print("[GCS]      REPLAY ATTACK DETECTED — nonce already seen. Message rejected. ✓")
else:
    print("[GCS]      Message accepted (replay not detected — BUG!)")