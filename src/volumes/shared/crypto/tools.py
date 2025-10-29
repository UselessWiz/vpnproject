from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os, base64

def load_public_key(filename: str):
    """
    Load specified public key from the specified PEM file.

    Parameters
    ----------
    filename : str
        The location of the public key file.
    
    Returns
    -------
    PublicKey
        The public key contained in the specified file. Returns either a RSAPublicKey or X25519PublicKey depending on what's in the PEM file.
    """
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_private_key(filename):
    """
    Loads the private key from the specified PEM file.

    Parameters
    ----------
    filename : str
        The location of the private key file.

    Returns
    -------
    PrivateKey
        The private key contained in the specified file. Returns either a RSAPrivateKey or X25519PrivateKey depending on what's in the PEM file.
    """
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
# --- AES (X25519) ---

AES_KEY_SIZE = 32   # AES-256-GCM
NONCE_SIZE = 12     # GCM nonce 12 * 8 = 96 bits

def x25519_derive_shared_key(private_key, peer_public_key):
    """
    Derives an AES key from the X25519 shared secret.

    Parameters
    ----------
    private_key : X25519PrivateKey
        The private key for this party.
    peer_public_key : X25519PublicKey
        The other party's public key.
    
    Returns
    -------
    bytes
        The key which can be used for AES encryption/decryption.  
    """
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)

# --- ML-KEM ---

def derive_shared_key(shared_secret: bytes) -> bytes:
    """
    Derives an AES key from the exchanged shared secret.

    Parameters
    ----------
    shared_secret
        The secret that was exchanged with ML-KEM.

    Returns
    ------
    bytes
        The key which can be used for AES encryption/decryption.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'vpn tunnel',
        backend=default_backend()
    ).derive(shared_secret)


def export_mlkem_pem(key: bytes, filename: str, type: str = "PRIVATE"):
    """
    Exports a ML-KEM key to a PEM file.

    Parameters
    ----------
    key : bytes
        The key to provide. This could be either an ML-KEM public or private key.
    filename : str
        The file to export the PEM file to.
    type : str
        The key type. This could be either "PUBLIC" or "PRIVATE" and is used to specify which type of key as per the PEM file format.

    Returns
    -------
    None
    """
    encoded_key = base64.b64encode(key).decode("ascii")
    with open(filename, "w+") as file:
        file.write(f"-----BEGIN {type} KEY-----\n{encoded_key}\n-----END {type} KEY-----")

def import_mlkem_pem(filename: str) -> bytes:
    """
    Reads a ML-KEM key from a PEM file.

    Parameters
    ----------
    filename : str
        The location of the PEM file.

    Returns
    -------
    bytes
        The key within the file.
    """
    with open(filename, "r") as file:
        pem_content: list[str] = file.read().split("-----")
        if (pem_content[1] == "BEGIN PUBLIC KEY" or pem_content[1] == "BEGIN PRIVATE KEY") and \
            (pem_content[3] == "END PUBLIC KEY" or pem_content[3] == "END PRIVATE KEY"):
            return base64.b64decode(pem_content[2].encode("ascii"))
        else:
            raise ValueError("File is not in valid PEM format.")