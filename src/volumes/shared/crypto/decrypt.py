from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from shared.crypto.tools import x25519_derive_shared_key, NONCE_SIZE

# --- RSA --- 

MAX_RSA_PLAINTEXT = 190 # 190 byte limit for RSA OEAP https://crypto.stackexchange.com/a/42100
RSA_CIPHERTEXT_LEN = 256

def rsa_decrypt(data: bytes, private_key) -> bytes: #RSAPrivateKey
    """Decrypts a piece of RSA encrypted ciphertext.
     
    This is done by first splitting it into blocks, then decrypting each block with 
    the provided RSA private key.

    Parameters
    ----------
    data : bytes
        The ciphertext to decrypt.
    private_key : RSAPrivateKey
        The RSA private key to decrypt this ciphertext with.

    Returns
    -------
    bytes
        The plaintext after the decryption process is completed.
    
    """
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

# --- SHARED AES-256-GCM ---

def aes_x25519_decrypt(ciphertext: bytes, private_key: bytes, peer_public_key: bytes) -> bytes:
    """ Decrypts a ciphertext that's been encrypted with AES-256
    
    This varient derives the shared symmetric key from the provided public and private keys;
    the program expects these to be X25519 keys. Key derivation uses Elliptic Curve Diffie-Hellman.

    Parameters
    ----------
    ciphertext : bytes
        The ciphertext to decrypt
    private_key: bytes
        The application's private key, in a useable bytes format.
    peer_public_key : bytes
        The sender's public key in a useable bytes format.

    Returns
    -------
    bytes
        The plaintext after the decryption process is completed.
    """
    key = x25519_derive_shared_key(private_key, peer_public_key)
    return aes_decrypt(ciphertext, key)

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """ Decrypts a ciphertext that's been encrypted with AES-256
    
    This varient expects an already provided shared secret.

    Parameters
    ----------
    ciphertext : bytes
        The ciphertext to decrypt
    key : bytes
        The shared secret that both parties have in a useable bytes form.

    Returns
    -------
    bytes
        The plaintext after the decryption process is completed.
    """
    nonce = ciphertext[:NONCE_SIZE]
    tag = ciphertext[NONCE_SIZE:NONCE_SIZE+16]
    ct = ciphertext[NONCE_SIZE+16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ct) + decryptor.finalize_with_tag(tag)
