#!/usr/bin/env python3
import ssl, os

# mTLS certificate paths
CA_CERT     = os.getenv("CA_CERT", "/keys/tls/ca/ca.crt")
CLIENT_CERT = os.getenv("CLIENT_CERT", "/keys/tls/client/client.crt")
CLIENT_KEY  = os.getenv("CLIENT_KEY", "/keys/tls/client/client.key")

import asyncio
import struct
import logging
from scapy.all import *
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from shared.create_tun import create_tun

# Logging setup
logging.basicConfig(
    filename='/volumes/client.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

SERVER_IP = "10.9.0.11"
QUIC_PORT = 4433
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# Create virtual TUN interface
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")
os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

async def recv_from_server(reader: asyncio.StreamReader):
    """
    Defines what to do when a data packet is received from the server.

    Parameters
    ----------
    reader : StreamReader
        The reader that aioquic receives network traffic from.

    Returns
    -------
    None
    """
    while True:
        try:
            length_bytes = await reader.readexactly(2)
            pkt_len = struct.unpack("!H", length_bytes)[0]
            if pkt_len <= 0 or pkt_len > 2000:
                continue

            data = await reader.readexactly(pkt_len)

            # Only handle IPv4
            if not data or len(data) < 20 or (data[0] >> 4) != 4:
                logger.info("From server <==: non-IPv4 or short frame ignored")
                continue

            try:
                pkt = IP(data)
                logger.info(f"From server <==: {pkt.src} --> {pkt.dst}")
            except Exception:
                pass

            os.write(tun, data)

        except asyncio.IncompleteReadError:
            logger.info("Server stream closed")
            return
        except Exception as e:
            logger.exception(f"[recv_from_server] Exception: {e}")
            return

def tun_read_cb(writer: asyncio.StreamWriter):
    """
    Defines what to do when a data packet is ready to be sent to the VPN server.

    Parameters
    ----------
    writer : StreamWriter
        The writer that the VPN writes to in preparation for sending to the server.

    Returns
    -------
    None
    """
    try:
        packet = os.read(tun, 2048)
        if not packet or len(packet) < 20 or (packet[0] >> 4) != 4:
            return

        try:
            pkt = IP(packet)
            if pkt.version != 4 or pkt.src == "0.0.0.0" or pkt.dst == "0.0.0.0":
                return
            logger.info(f"From tun ==>: {pkt.src} --> {pkt.dst}")
        except Exception:
            pass

        length_prefix = struct.pack("!H", len(packet))
        if not writer.is_closing():
            writer.write(length_prefix + packet)
    except Exception as e:
        logger.exception(f"[tun_read_cb] Exception: {e}")
        return

async def vpn_client():
    """
    Essentially the main function of the VPN client, describes all functionality 
    including mTLS and general tunneling operations performed by the VPN.

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hq-29"],
        max_stream_data=65536,
        max_data=524288
    )
    configuration.idle_timeout = 30.0

    # Load mTLS certs
    configuration.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    configuration.verify_mode = ssl.CERT_REQUIRED
    configuration.load_verify_locations(CA_CERT)

    # Must match server certificate CN or SAN
    configuration.server_name = "vpn.local"

    # Simple reconnect loop so the client survives stream closures
    while True:
        try:
            async with connect(SERVER_IP, QUIC_PORT, configuration=configuration) as connection:
                reader, writer = await connection.create_stream()
                loop = asyncio.get_running_loop()
                loop.add_reader(tun, tun_read_cb, writer)

                await recv_from_server(reader)

        except Exception as e:
            logger.info(f"Reconnect after error: {e}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(vpn_client())

