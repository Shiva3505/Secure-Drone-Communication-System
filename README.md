# 🛡️ Secure Drone Communication System

A Python implementation of a cryptographically secure communication protocol between a **Drone (Client)** and a **Ground Control Station / GCS (Server)**. Built as part of a Cryptography & Network Security course assignment, the system chains six independent security mechanisms to ensure confidentiality, authentication, integrity, and replay protection.

---

## 📁 Project Structure

```
secure-drone-comms/
├── main.py                   # Entry point — orchestrates the full protocol
├── key_exchange.py           # Diffie-Hellman key exchange + HKDF derivation
├── encryption.py             # RSA-OAEP key wrapping + AES-128-CBC encryption
├── authentication.py         # PBKDF2-HMAC-SHA256 password authentication
├── integrity.py              # HMAC-SHA256 message authentication code
├── signature.py              # RSA digital signature (sign + verify)
├── output_roll_number.pdf    # PDF-1: Execution output screenshots
├── code_roll_number.pdf      # PDF-2: Code listing + technical report
└── README.md
```

---

## 🔐 Security Architecture

| Layer | Mechanism | Algorithm |
|---|---|---|
| Identity | Password-based authentication | PBKDF2-HMAC-SHA256 (100k iterations) |
| Key Exchange | Diffie-Hellman + key derivation | DH + HKDF-SHA256 → 16-byte AES key |
| Key Transport | Session key wrapping | RSA-2048 OAEP |
| Encryption | Payload encryption | AES-128-CBC + PKCS7 padding |
| Signature | Message authenticity + non-repudiation | RSA-2048 + SHA-256 (PKCS#1 v1.5) |
| Integrity | Tamper detection | HMAC-SHA256 over IV \|\| ciphertext |
| Anti-Replay | Duplicate / stale message rejection | Random nonce (os.urandom) + timestamp |

---

## 🔄 Protocol Workflow

```
Drone                                          GCS
  │                                             │
  │──── 1. Authenticate (PBKDF2 hash) ────────▶│
  │                                             │
  │◀──── 2. DH public key exchange ────────────▶│
  │       (both derive same AES session key)    │
  │                                             │
  │──── 3. RSA-OAEP encrypted session key ────▶│
  │                                             │
  │    [Drone builds payload]                   │
  │     • Encrypt payload with AES-CBC          │
  │     • Sign plaintext with RSA               │
  │     • Compute HMAC over IV+ciphertext       │
  │     • Attach nonce + timestamp              │
  │                                             │
  │──── 4. { ciphertext, IV, sig,          ───▶│
  │          MAC, nonce, timestamp }            │
  │                                             │
  │                          [GCS verifies]     │
  │                      ① Replay protection    │
  │                      ② HMAC integrity check │
  │                      ③ AES decryption       │
  │                      ④ RSA signature verify │
  │                                             │
  │◀──── 5. Secure data accepted ──────────────│
```

---

## ⚙️ Installation

### Prerequisites

- Python 3.10 or higher
- pip

### Install dependencies

```bash
pip install pycryptodome cryptography
```

Or using a requirements file:

```bash
pip install -r requirements.txt
```

**requirements.txt**
```
pycryptodome>=3.18.0
cryptography>=41.0.0
```

---

## 🚀 Running the Project

```bash
python main.py
```

### Expected Output

```
============================================================
STEP 1: Authentication
============================================================
[GCS]   Password hash stored (PBKDF2-HMAC-SHA256, 100k iterations)
[GCS]   Salt (hex): <random_hex>
[GCS]   Authentication SUCCESS

[GCS]   Challenge issued (hex): <random_hex>
============================================================
STEP 2: Diffie-Hellman Key Exchange
============================================================
[Drone] DH shared key derived (hex): <hex>
[GCS]   DH shared key derived (hex): <hex>
[✓]    Keys match: True

============================================================
STEP 3: Hybrid Encryption — RSA wraps AES session key
============================================================
[Drone] Session key encrypted with GCS RSA public key
[GCS]   Session key decrypted (hex): <hex>
[✓]    Session keys match: True

============================================================
STEP 4: Drone prepares secure message
============================================================
[Drone] Plaintext payload:
        {"drone_id":"DR001","latitude":12.9716,...}
[Drone] AES-CBC ciphertext (hex, first 32 bytes): <hex>...
[Drone] RSA signature generated (hex, first 32 bytes): <hex>...
[Drone] HMAC-SHA256 (hex): <hex>

============================================================
STEP 5: GCS verifies and decrypts
============================================================
[GCS]   Nonce accepted: <random_hex>
[GCS]   Message age: 0.00XXs (within 30s window)
[GCS]   HMAC verified ✓
[GCS]   Decrypted payload: {"drone_id":"DR001",...}
[GCS]   Signature verified ✓

============================================================
SECURE TRANSMISSION COMPLETE
============================================================
  Drone ID   : DR001
  Latitude   : 12.9716
  Longitude  : 77.5946
  Speed      : 45 km/h
  Altitude   : 120 m

All security checks passed:
  [✓] Password-based authentication (PBKDF2)
  [✓] Diffie-Hellman key exchange + HKDF
  [✓] Hybrid encryption (RSA-OAEP + AES-CBC)
  [✓] Digital signature (RSA + SHA-256)
  [✓] Message integrity (HMAC-SHA256 over IV+ciphertext)
  [✓] Replay attack protection (random nonce + timestamp)

============================================================
BONUS: Replay Attack Simulation
============================================================
[Attacker] Re-sending the exact same message (same nonce)...
[GCS]      REPLAY ATTACK DETECTED — nonce already seen. Message rejected. ✓
```

> **Note:** Hex values (keys, IVs, nonces, salts, signatures) will differ on every run. This is expected — cryptographically secure randomness (`os.urandom`) is used throughout.

---

## 📂 Module Reference

### `key_exchange.py`
Generates Diffie-Hellman key pairs using the `cryptography` library. After the DH exchange, the raw shared secret is passed through **HKDF-SHA256** to produce a uniform 16-byte AES session key.

```python
from key_exchange import generate_private_key, generate_public_key, generate_shared_key

priv    = generate_private_key()
pub     = generate_public_key(priv)
aes_key = generate_shared_key(my_private, peer_public)  # returns 16 bytes
```

---

### `authentication.py`
Password hashing using **PBKDF2-HMAC-SHA256** with a fresh 16-byte random salt and 100,000 iterations. Verification uses `hmac.compare_digest` to prevent timing attacks.

```python
from authentication import hash_password, verify_password

salt, hashed = hash_password("mypassword")
ok = verify_password("mypassword", salt, hashed)  # True
```

---

### `encryption.py`
**Hybrid encryption** — RSA-2048 OAEP wraps the AES session key; AES-128-CBC encrypts the payload. A new random IV is generated per message.

```python
from encryption import (generate_rsa_keys, encrypt_aes,
                        decrypt_aes, encrypt_session_key, decrypt_session_key)

priv, pub      = generate_rsa_keys()
enc_key        = encrypt_session_key(session_key, pub)
dec_key        = decrypt_session_key(enc_key, priv)
iv, ciphertext = encrypt_aes("hello", session_key)
plaintext      = decrypt_aes(iv, ciphertext, session_key)
```

---

### `integrity.py`
Computes **HMAC-SHA256** over `IV || ciphertext` (raw bytes), protecting both the encrypted data and the IV from tampering.

```python
from integrity import generate_hmac, verify_hmac

mac = generate_hmac(iv, ciphertext, key)
ok  = verify_hmac(iv, ciphertext, key, mac)  # True
```

---

### `signature.py`
RSA digital signature using **PKCS#1 v1.5 + SHA-256**. The Drone signs the plaintext; the GCS verifies before trusting the decrypted content.

```python
from signature import sign_message, verify_signature

sig = sign_message("data", private_key)
ok  = verify_signature("data", sig, public_key)  # True
```

---

## 🛡️ Security Analysis

### Attacks Prevented

| Attack | How it is prevented |
|---|---|
| **Eavesdropping** | AES-128-CBC encryption — ciphertext is meaningless without the session key |
| **Brute-force / dictionary attack** | PBKDF2 with 100k iterations + unique salt makes offline cracking expensive |
| **Rainbow table attack** | Per-password random salt ensures identical passwords hash differently |
| **Message tampering** | HMAC-SHA256 over IV+ciphertext detects any bit-level modification |
| **Impersonation / spoofing** | RSA signature ties each message to the Drone's private key |
| **Replay attack** | Random nonce tracked in a seen-set; timestamp enforces a 30-second freshness window |
| **Key-transport attack** | DH-derived AES key is RSA-OAEP wrapped — never transmitted in plaintext |
| **Timing attack on password** | `hmac.compare_digest` used for constant-time comparison |

### Limitations

| Limitation | Detail |
|---|---|
| **DH group size** | 512-bit group used for demo speed. Production requires ≥ 2048-bit (RFC 3526 Group 14) |
| **In-memory nonce store** | Seen-nonce set is lost on restart — replay within the timestamp window becomes possible. Production needs a persistent TTL store (e.g., Redis) |
| **No certificate authority** | Public keys assumed authentic (out-of-band). Real deployment needs PKI to prevent MITM during initial handshake |
| **Single-factor authentication** | Password-only. Production drones should use device certificates or HSMs |
| **No network layer** | Simulation runs in one process. Real deployment needs DTLS/TLS sockets |
| **Static RSA keys** | No per-session ephemeral RSA keys. Full PFS would require ECDHE |

---

## 🎯 Bonus — Replay Attack Demonstration

The final section of `main.py` simulates an attacker re-sending a previously captured valid message:

```python
# Attacker replays the same message (same nonce)
if received_nonce in used_nonces:
    print("[GCS] REPLAY ATTACK DETECTED — nonce already seen. Message rejected.")
```

The GCS immediately rejects it because the nonce is already in the `used_nonces` set.

---

## 📋 Assignment Marks

| Component | Max Marks | Status |
|---|---|---|
| Key Exchange (DH + HKDF) | 2 | ✅ |
| Hybrid Encryption (RSA + AES) | 2 | ✅ |
| Authentication (PBKDF2) | 2 | ✅ |
| Digital Signature (RSA) | 1.5 | ✅ |
| Message Integrity (HMAC) | 1.5 | ✅ |
| Replay Protection (nonce + timestamp) | 1 | ✅ |
| **Total** | **10** | ✅ |
| Bonus (Replay attack demo) | +1 | ✅ |

---

## 🧪 Dependencies

| Library | Purpose |
|---|---|
| `pycryptodome` | AES, RSA, HMAC, PKCS#1 signing |
| `cryptography` | DH parameter generation, HKDF |

---

## 📄 License

This project was created for academic purposes as part of a Cyber Security course assignment.

---

## 👤 Author

**Roll No:** CS23B1025 
**Course:** Cyber Security  
**Institution:** Indian Institute of Information Technology
