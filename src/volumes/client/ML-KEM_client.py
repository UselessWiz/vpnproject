import os, oqs, socket, logging, select
from scapy.all import *
from shared.create_tun import create_tun
from shared.crypto.encrypt import aes_mlkem_encrypt
from shared.crypto.decrypt import aes_mlkem_decrypt
from shared.crypto.tools import import_mlkem_pem, derive_shared_key

ALGORITHM = "ML-KEM-1024"

# Logging setup
logging.basicConfig(
    filename='/volumes/client.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Create the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

client_private_key = import_mlkem_pem("/keys/ML-KEM/mlkem-client-private.pem")

# Create client and generate keys
client = oqs.KeyEncapsulation(ALGORITHM, client_private_key)

# Get server's public key
server_public_key = import_mlkem_pem("/keys/ML-KEM/mlkem-server-public.pem")

# Encapsulate shared secret
encapsulated_key, client_shared_secret = client.encap_secret(server_public_key) # encapsulated_key needs to be transmitted.

# Derive a symmetric key from the shared secret
sym_key = derive_shared_key(client_shared_secret)

# test creating a packet with the encapsulated in it.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.9.0.5', 9090))

server_addr = ("10.9.0.11", 9090)

# Send CLIENT HELLO
sock.sendto(b"CLIENT HELLO" + encapsulated_key, server_addr)

# Encrypt a message
message = b"This is a test."
ciphertext = aes_mlkem_encrypt(message, sym_key)

server_connected = False

while server_connected is False:
    data, (ip, port) = sock.recvfrom(2048)
    if len(data) > 0:
        if (ip, port) == server_addr and data[0:12] == b"SERVER HELLO" and \
            aes_mlkem_decrypt(data[12:], sym_key) == b"SHARED SECRET CONFIRMATION":
            sock.sendto(aes_mlkem_encrypt(b"SHARED SECRET CONFIRMED", sym_key), server_addr)
            server_connected = True

while True:
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            decrypted_data = aes_mlkem_decrypt(data, sym_key)
            pkt = IP(decrypted_data)
            logger.info("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, decrypted_data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            logger.info("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            encrypted_data = aes_mlkem_encrypt(packet, sym_key)
            sock.sendto(encrypted_data, ("10.9.0.11", 9090))