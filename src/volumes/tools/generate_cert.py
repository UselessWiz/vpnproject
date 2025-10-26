from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import datetime

def generate_self_signed_cert():
    """
    Generate a self-signed certificate for use with QUIC. 
    
    Starts by generating a private key (ECDSA for faster QUIC; RSA is optional). This private key is then used to sign a created certificate. The key and certificate are then both exported to files. This is a self-signed certificate, and should not be used for real applications (for test purposes only).

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Create a self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"AU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"NSW"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sydney"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UTS"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"10.9.0.11"),
    ])

    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"10.9.0.11")]),
            critical=False,
        )\
        .sign(private_key, hashes.SHA256(), default_backend())

    # Serialize to PEM format (bytes)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("cert.pem", "wb") as cert_file:
        cert_file.write(cert_pem)

    with open("key.pem", "wb") as key_file:
        key_file.write(key_pem)
