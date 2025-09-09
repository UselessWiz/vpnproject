import os, oqs, socket, logging, select
from scapy.all import *
from shared.create_tun import create_tun
from shared.crypto.encrypt import *
from shared.crypto.decrypt import *
from shared.crypto.tools import *

ALGORITHM = "ML-KEM-1024"

#Logging setup
logging.basicConfig(
    filename='/volumes/server.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Create the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
TUN_IP = "192.168.53.98"
ip = "127.0.0.1"

# Create the tun interface
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

# Set up the tun interface
os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname))
os.system("ip link set dev {} up".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.9.0.11', 9090))

server_private_key = import_mlkem_pem("/keys/ML-KEM/mlkem-server-private.pem")

server = oqs.KeyEncapsulation(ALGORITHM, server_private_key)

sym_key = None
client_addr = None
client_connected = False
i = 0

while True:
    # Handle the initial connection.
    if client_connected is False:
        # Receive data from socket
        buf = sock.recvfrom(2048)
        if len(buf) > 0: 
            # this is a CLIENT HELLO packet
            if buf[0][0:12] == b"CLIENT HELLO":
                shared_secret = server.decap_secret(buf[0][12:])
                sym_key = derive_shared_key(shared_secret)
                client_addr = buf[1]
                sock.sendto(b"SERVER HELLO" + aes_mlkem_encrypt(b"SHARED SECRET CONFIRMATION", sym_key), client_addr)
                continue

            # if not, must be a client ack packet.
            if sym_key is not None and aes_mlkem_decrypt(buf[0], sym_key) == b"SHARED SECRET CONFIRMED" and buf[1] == client_addr:
                client_connected = True
                continue
    
    # this will block until at least one interface is ready
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
            sock.sendto(encrypted_data, (ip, port))

