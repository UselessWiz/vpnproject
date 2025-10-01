from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import hashes, serialization
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

def rsa_decrypt(data, private_key):
    decrypted = b''

    for i in range(0, len(data), RSA_CIPHERTEXT_LEN):
        chunk = data[i:i + RSA_CIPHERTEXT_LEN]

        if len(chunk) < RSA_CIPHERTEXT_LEN:
            continue  # skip incomplete block

        decrypted_block = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted += decrypted_block

    return decrypted

# ----------------
# AES (X25519)
# ----------------

# AES-256-GCM
def aes_x25519_decrypt(ciphertext, private_key, peer_public_key):
    key = x25519_derive_shared_key(private_key, peer_public_key)
    nonce = ciphertext[:NONCE_SIZE]
    tag = ciphertext[NONCE_SIZE:NONCE_SIZE+16]
    ct = ciphertext[NONCE_SIZE+16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_mlkem_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    nonce = ciphertext[:NONCE_SIZE]
    tag = ciphertext[NONCE_SIZE:NONCE_SIZE+16]
    ct = ciphertext[NONCE_SIZE+16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ct) + decryptor.finalize_with_tag(tag)
