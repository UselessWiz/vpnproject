import oqs, base64, shared

def gen_keypair(pubkey_filename: str, seckey_filename: str):
    """
    Generates a ML-KEM keypair and saves them in pem format.

    This needs to be run before the VPN is used for the first time; This is different to the QUIC version which automatically calls the relevant script when the VPN is run.

    Parameters
    ----------
    pubkey_filename : str
        The file to export the public key to.

    seckey_filename : str
        The file to export the private key to.

    Returns
    -------
    None
    """
    # Create client and generate keys.
    client = oqs.KeyEncapsulation(shared.ALGORITHM)
    public_key = client.generate_keypair()
    secret_key = client.export_secret_key()

    print(public_key)
    print(secret_key)

    print(base64.b64encode(public_key).decode("ascii"))
    print(base64.b64encode(secret_key).decode("ascii"))

    # Export the keys to the requested files.
    shared.export_mlkem_pem(public_key, pubkey_filename, "PUBLIC")
    shared.export_mlkem_pem(secret_key, seckey_filename, "PRIVATE")

if __name__ == "__main__":
    print("CLIENT")
    gen_keypair("mlkem-client-public.pem", "mlkem-client-private.pem")
    print("SERVER")
    gen_keypair("mlkem-server-public.pem", "mlkem-server-private.pem")