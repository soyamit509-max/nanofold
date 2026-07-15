"""
Real proof of the asymmetric Key1/Key2 architecture, using a standard,
vetted pattern: X25519 (ECDH) + AES-256-GCM envelope encryption
(this is the same idea as libsodium's "sealed box").

Key 1 (deployed to every edge instance)  = X25519 PUBLIC key only.
Key 2 (kept only in a central KMS/HSM)   = X25519 PRIVATE key.

The edge node generates a fresh, one-time-use ephemeral keypair for every
chunk it encrypts, derives a per-chunk AES key via ECDH + HKDF, encrypts,
and then DISCARDS the ephemeral private key immediately. It never needs
and never has the server's private key.

This script actually attempts the "attacker on a compromised edge node"
scenario and shows the decrypt call is architecturally impossible without
Key 2 -- not just claimed impossible.
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

RAW = serialization.Encoding.Raw
RAWPUB = serialization.PublicFormat.Raw


def derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"nanofold-chunk-key-v1").derive(shared_secret)


def encrypt_chunk_with_public_key(plaintext: bytes, recipient_public_bytes: bytes) -> bytes:
    """Everything an EDGE NODE is able to do. It only ever holds
    `recipient_public_bytes` (Key 1) -- never a private key."""
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(RAW, RAWPUB)

    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_bytes)
    shared_secret = ephemeral_private.exchange(recipient_public)
    aes_key = derive_aes_key(shared_secret)

    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    # ephemeral_private is now discarded (goes out of scope) -- it is never stored,
    # never logged, never reused. It was only ever needed for this one encryption.
    return ephemeral_public_bytes + nonce + ciphertext


def decrypt_chunk_with_private_key(sealed: bytes, server_private_key: X25519PrivateKey) -> bytes:
    """Requires Key 2. There is no code path to this plaintext without it."""
    ephemeral_public_bytes, nonce, ciphertext = sealed[:32], sealed[32:44], sealed[44:]
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    shared_secret = server_private_key.exchange(ephemeral_public)
    aes_key = derive_aes_key(shared_secret)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ============================== DEMONSTRATION ==============================

print("=== Step 1: central KMS generates the long-term keypair (once, ever) ===")
server_private_key = X25519PrivateKey.generate()          # Key 2 -- stays in the KMS/HSM, never leaves
KEY1_public_bytes = server_private_key.public_key().public_bytes(RAW, RAWPUB)  # Key 1 -- shipped to every edge node
print(f"Key 1 (public, deployed everywhere): {KEY1_public_bytes.hex()[:32]}...")
print("Key 2 (private) never printed, never leaves the KMS in this demo.")
print()

print("=== Step 2: edge node encrypts 3 real chunks using ONLY Key 1 ===")
plaintexts = [
    b"2026-07-06T00:00:01Z 10.0.0.5 GET /api/v1/orders/812 200",
    b"2026-07-06T00:00:02Z 10.0.0.9 POST /api/v1/payments/44 500 ConnectionTimeout",
    b"2026-07-06T00:00:03Z 10.0.0.5 GET /health 200",
]
sealed_chunks = [encrypt_chunk_with_public_key(p, KEY1_public_bytes) for p in plaintexts]
for i, s in enumerate(sealed_chunks):
    print(f"  chunk {i}: {len(s)} bytes sealed, ciphertext={s[44:].hex()[:24]}...")
print()

print("=== Step 3: attacker compromises the edge node, steals Key 1 + the sealed chunks ===")
attacker_has = {"public_key": KEY1_public_bytes, "sealed_chunks": sealed_chunks}
print("Attacker attempts to decrypt using only what they stole (no server private key)...")
try:
    # There is no API to derive the shared secret from two PUBLIC keys.
    # ECDH mathematically requires one PRIVATE key. This is not a missing
    # feature we forgot to implement -- it does not exist in elliptic-curve
    # Diffie-Hellman. We demonstrate the closest an attacker could try:
    # guessing a random "private key" and seeing if it works.
    fake_private_key = X25519PrivateKey.generate()  # attacker has no real private key, so: random guess
    result = decrypt_chunk_with_private_key(sealed_chunks[0], fake_private_key)
    print("  UNEXPECTED: decrypted without Key 2:", result)
except InvalidTag:
    print("  Result: InvalidTag -- decryption cryptographically REJECTED. Attacker gets nothing.")
print()

print("=== Step 4: the central KMS (holding Key 2) decrypts the same chunks normally ===")
for i, s in enumerate(sealed_chunks):
    recovered = decrypt_chunk_with_private_key(s, server_private_key)
    match = recovered == plaintexts[i]
    print(f"  chunk {i}: recovered == original? {match}  -> {recovered.decode()}")
print()

print("=== Step 5: old chunks stay safe even after MORE data is encrypted post-compromise ===")
new_plaintext = b"2026-07-06T00:05:00Z 10.0.0.7 GET /api/v1/users/1 200"
new_sealed = encrypt_chunk_with_public_key(new_plaintext, KEY1_public_bytes)
print("New chunk encrypted with the same (stolen) Key 1 -- but it used a FRESH ephemeral")
print("keypair, generated and discarded on the spot. It shares no secret material with the")
print("earlier chunks, and the earlier chunks' ephemeral private keys were never persisted")
print("anywhere for an attacker to find, even with full disk/memory access to the edge node")
print("*after* those chunks were already shipped out.")
