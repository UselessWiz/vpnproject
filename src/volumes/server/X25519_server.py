#!/usr/bin/env python3

import os, logging, socket, select
from scapy.all import *
from shared.create_tun import create_tun
from shared.crypto.encrypt import aes_x25519_encrypt
from shared.crypto.decrypt import aes_x25519_decrypt
from shared.crypto.tools import load_public_key
from shared.crypto.tools import load_private_key

# Logging setup
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
ip = "8.8.8.8"

# Create the tun interface
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)

# Set up the tun interface
os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname))
os.system("ip link set dev {} up".format(ifname))

IP_A = "10.9.0.11"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

# Get X25519 keys
server_private_key = load_private_key("/keys/X25519/x-server_private.pem")
client_public_key = load_public_key("/keys/X25519/x-client_public.pem")

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            decrypted_data = aes_x25519_decrypt(data, server_private_key, client_public_key)
            pkt = IP(decrypted_data)
            logger.info("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, decrypted_data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            logger.info("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            encrypted_data = aes_x25519_encrypt(packet, server_private_key, client_public_key)
            sock.sendto(encrypted_data, (ip, port))
