from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from shared.crypto.tools import x25519_derive_shared_key, NONCE_SIZE
import os

# ----------------
# RSA
# ----------------

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

def rsa_encrypt(packet_bytes, public_key):
    blocks = []

    for i in range(0, len(packet_bytes), MAX_RSA_PLAINTEXT):
        chunk = packet_bytes[i:i + MAX_RSA_PLAINTEXT]

        if len(chunk) < MAX_RSA_PLAINTEXT:
            # If the length of the chunk isn't correct, pad it with zeros
            chunk += b'\x00' * (MAX_RSA_PLAINTEXT - len(chunk))
        
        encrypted = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        blocks.append(encrypted)

    return b''.join(blocks)

# ----------------
# AES (X25519)
# ----------------

def aes_x25519_encrypt(plaintext, private_key, peer_public_key):
    key = x25519_derive_shared_key(private_key, peer_public_key)
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(
        algorithms.AES(key), # AES-256-GCM
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext

def aes_mlkem_encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(
        algorithms.AES(key), # AES-256-GCM
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext