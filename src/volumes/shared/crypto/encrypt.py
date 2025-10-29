from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from shared.crypto.tools import x25519_derive_shared_key, NONCE_SIZE
import os

# --- RSA ---

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

def rsa_encrypt(packet_bytes: bytes, public_key) -> bytes:
    """Encrypts a piece of RSA encrypted ciphertext.
     
    This is done by first splitting it into blocks, then encrypting each block with 
    the provided RSA public key.

    Parameters
    ----------
    data : bytes
        The ciphertext to decrypt.
    private_key : RSAPublicKey
        The RSA public key of the other party.

    Returns
    -------
    bytes
        The ciphertext corresponding to this plaintext that can only be decrypted 
        with the other party's private key.
    
    """
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

# --- SHARED AES-256-GCM ---

def aes_x25519_encrypt(plaintext: bytes, private_key: bytes, peer_public_key: bytes) -> bytes:
    """Encrypts a piece of plaintext using AES-256.
    
    This varient expects an X25519 public and private key, deriving the symmetric key
    using Elliptic Curve Diffie-Hellman before encrypting the message with that shared key.

    Parameters
    ----------
    plaintext : bytes
        The plaintext to encrypt
    private_key : bytes
        This party's private key in a usable bytes format.
    peer_public_key : bytes
        The other party's public key in a usable bytes format.
    """
    key = x25519_derive_shared_key(private_key, peer_public_key)
    return aes_encrypt(plaintext, key)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts a piece of plaintext using AES-256.
    
    This varient expects a derived secret symmetric key.

    Parameters
    ----------
    plaintext : bytes
        The plaintext to encrypt
    key : bytes
        The shared secret key which should be used to encrypt the message.
    """
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(
        algorithms.AES(key), # AES-256-GCM
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext