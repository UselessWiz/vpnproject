import oqs, base64, shared

"""
Generates a keypair for both client and server, and saves them in pem format.
"""

def gen_keypair(pubkeyfilename: str, seckeyfilename: str):
    # Create client and generate keys
    client = oqs.KeyEncapsulation(shared.ALGORITHM)
    public_key = client.generate_keypair()
    secret_key = client.export_secret_key()

    print(public_key)
    print(secret_key)

    print(base64.b64encode(public_key).decode("ascii"))
    print(base64.b64encode(secret_key).decode("ascii"))

    shared.export_mlkem_pem(public_key, pubkeyfilename, "PUBLIC")
    shared.export_mlkem_pem(secret_key, seckeyfilename, "PRIVATE")

print("CLIENT")
gen_keypair("mlkem-client-public.pem", "mlkem-client-private.pem")
print("SERVER")
gen_keypair("mlkem-server-public.pem", "mlkem-server-private.pem")