#!/usr/bin/env python3
import logging, os, socket, select
from scapy.all import * # Used for deserializing network data (IP Packets) so their data can be used by the program.
from shared.create_tun import create_tun
from shared.crypto.encrypt import rsa_encrypt
from shared.crypto.decrypt import rsa_decrypt
from shared.crypto.tools import load_public_key, load_private_key

# Logging setup
logging.basicConfig(
    filename='/volumes/client.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Set flags for tunnel creation.
TUNSETIFF = 0x400454ca # Constant value for the IF set command.
IFF_TUN   = 0x0001 # Flag for if this interface is of type TUN
IFF_TAP   = 0x0002 # Flag for if this interface is of type TAP. TAP devices use ethernet frames.
IFF_NO_PI = 0x1000 # Flag for if packet information is not needed.
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI) # Create the tun interface

# Add the routes such that network traffic destined for the internal network are sent through the tunnel interface.
# See: https://www.geeksforgeeks.org/linux-unix/ip-command-in-linux-with-examples/
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname)) # The IP address of the tunnel
os.system("ip link set dev {} up".format(ifname)) # Set the tunnel interface to UP
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname)) # Add the route to the internal network via the tunnel interface.

# Create a network socket so the program can send and receive network data.
# AF_INET means addressing is in the format (host, port).
# SOCK_DGRAM indicates to use UDP as we're using IP based protocols in both socket and interface.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Get RSA keys
server_public_key = load_public_key("/keys/RSA/server_public.pem")
client_private_key = load_private_key("/keys/RSA/client_private.pem")

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], []) # select.select rlist waits until the given file descriptors are ready for reading.
    for fd in ready:
        if fd is sock:
            try:
                # Receive and decrypt data, writing to the tunnel interface.
                data, (ip, port) = sock.recvfrom(2048)
                decrypted_data = rsa_decrypt(data, client_private_key)
                pkt = IP(decrypted_data)
                logger.info("From socket (VPN SERVER) <==: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, decrypted_data)
            except Exception as e:
                logging.exception(f"Error decrypting from sock: {e}")

        if fd is tun:
            try:
                # Encrypt and send data, writing to the socket interface.
                packet = os.read(tun, 2048)
                pkt = IP(packet)
                logger.info("From tun (THIS HOST) ==>: {} --> {}".format(pkt.src, pkt.dst))
                encrypted_data = rsa_encrypt(packet, server_public_key) # RSA
                sock.sendto(encrypted_data, ("10.9.0.11", 9090))
            except Exception as e:
                logging.exception(f"Error encrypting from tun: {e}")
