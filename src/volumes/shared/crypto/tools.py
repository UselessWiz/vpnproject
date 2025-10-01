from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os, base64

# Load specified public key. Returns an RSAPublicKey or X25519PublicKey depending on the type contained in the PEM file.
def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# Load specified private key. Returns an RSAPrivateKey or X25519PrivateKey depending on the type contained in the PEM file.
def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
# ----------------
# AES (X25519)
# ----------------

AES_KEY_SIZE = 32   # AES-256-GCM
NONCE_SIZE = 12     # GCM nonce 12 * 8 = 96 bits

# Derive AES key from shared secret. Used for X25519 encryption/decryption.
def x25519_derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)

# ----------------
# PQC
# ----------------

def derive_shared_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)

def export_mlkem_pem(key: bytes, filename: str, type: str = "PRIVATE"):
    encoded_key = base64.b64encode(key).decode("ascii")
    with open(filename, "w+") as file:
        file.write(f"-----BEGIN {type} KEY-----\n{encoded_key}\n-----END {type} KEY-----")

def import_mlkem_pem(filename: str) -> bytes:
    with open(filename, "r") as file:
        pem_content: list[str] = file.read().split("-----")
        if (pem_content[1] == "BEGIN PUBLIC KEY" or pem_content[1] == "BEGIN PRIVATE KEY") and \
            (pem_content[3] == "END PUBLIC KEY" or pem_content[3] == "END PRIVATE KEY"):
            return base64.b64decode(pem_content[2].encode("ascii"))
        else:
            raise ValueError("File is not in valid PEM format.")