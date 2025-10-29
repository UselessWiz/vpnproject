import sys, os, oqs, socket, logging, select, threading
from scapy.all import *
from shared.create_tun import create_tun
from shared.crypto.encrypt import *
from shared.crypto.decrypt import *
from shared.crypto.tools import *

ALGORITHM = "ML-KEM-1024"

#Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("/volumes/server.log")] #, logging.StreamHandler(sys.stdout)]
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

server_private_key = import_mlkem_pem("/keys/ML-KEM/mlkem-server_private.pem")

server = oqs.KeyEncapsulation(ALGORITHM, server_private_key)

sym_key = None
client_addr = None
client_connected = False
i = 0

def confirmation_timeout():
    global sym_key, client_addr, client_connected
    if client_connected is False:
        logger.info("SHARED SECRET CONFIRMATION window timeout. Connection not formed. Waiting for CLIENT HELLO")
        sym_key = None
        client_addr = None

# Handle the initial connection.
while client_connected is False:
     # Receive data from socket
    data, (ip, port) = sock.recvfrom(2048)
    if len(data) > 0: 
        # this is a CLIENT HELLO packet
        if data[0:12] == b"CLIENT HELLO":
            shared_secret = server.decap_secret(data[12:])
            sym_key = derive_shared_key(shared_secret)
            client_addr = (ip, port)
            sock.sendto(b"SERVER HELLO" + aes_encrypt(b"SHARED SECRET CONFIRMATION", sym_key), client_addr)
            # Start a timer to detect a timeout between client hello and secret confirmation.
            threading.Timer(10, confirmation_timeout)
            continue

        # if not, must be a client ack packet.
        if sym_key is not None and aes_decrypt(data, sym_key) == b"SHARED SECRET CONFIRMED" and (ip, port) == client_addr:
            logger.info(f"Connection formed with {client_addr}")
            client_connected = True

while True:    
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            decrypted_data = aes_decrypt(data, sym_key)
            pkt = IP(decrypted_data)
            logger.info("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, decrypted_data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            logger.info("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            encrypted_data = aes_encrypt(packet, sym_key)
            sock.sendto(encrypted_data, (ip, port))

