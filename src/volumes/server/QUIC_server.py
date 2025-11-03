#!/usr/bin/env python3

import asyncio
import os
import struct
import ssl
import logging
from scapy.all import *
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from shared.create_tun import create_tun
from tools.generate_cert import generate_self_signed_cert

# mTLS paths via environment with sensible defaults
CA_CERT_ENV     = os.getenv("CA_CERT", "/volumes/keys/tls/ca/ca.crt")
SERVER_CERT_ENV = os.getenv("SERVER_CERT", "/volumes/keys/tls/server/server.crt")
SERVER_KEY_ENV  = os.getenv("SERVER_KEY", "/volumes/keys/tls/server/server.key")

# Logging setup
logging.basicConfig(
    filename='/volumes/server.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
TUN_IP    = "192.168.53.98"
SERVER_IP = "10.9.0.11"
QUIC_PORT = 4433

# Create TUN and bring it up
ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add {TUN_IP}/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")


class VPNServerProtocol:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Defines how the VPN server communicates with the client.

        Members
        -------
        reader : StreamReader
            The reader that aioquic receives network traffic from.
        writer : StreamWriter
            The writer that the VPN writes to in preparation for sending to the client.
        """
        self.reader = reader
        self.writer = writer

    async def recv_from_client(self):
        """
        Defines what to do when a data packet is received from the client.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        while True:
            try:
                length_bytes = await self.reader.readexactly(2)
                pkt_len = struct.unpack("!H", length_bytes)[0]
                if pkt_len <= 0 or pkt_len > 2000:
                    continue

                data = await self.reader.readexactly(pkt_len)

                # Only parse IPv4; ignore anything else
                if not data or len(data) < 20 or (data[0] >> 4) != 4:
                    logger.info("From client <==: non-IPv4 or short frame ignored")
                    continue

                try:
                    pkt = IP(data)
                    logger.info(f"From client <==: {pkt.src} --> {pkt.dst}")
                except Exception:
                    # If scapy parsing fails, still forward the raw packet
                    pass

                os.write(tun, data)

            except asyncio.IncompleteReadError:
                logger.info("Client stream closed")
                break
            except Exception as e:
                logger.exception(f"[recv_from_client] Exception: {e}")
                break

    def tun_read_cb(self):
        """
        Defines what to do when a data packet is ready to be sent to the VPN client.

        Parameters
        ----------
        None

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
                # Drop obviously invalid sources or destinations
                if pkt.version != 4 or pkt.src == "0.0.0.0" or pkt.dst == "0.0.0.0":
                    return
                logger.info(f"From tun ==>: {pkt.src} --> {pkt.dst}")
            except Exception:
                # If parsing fails, still forward if it looks like IPv4
                pass

            length_prefix = struct.pack("!H", len(packet))
            if not self.writer.is_closing():
                self.writer.write(length_prefix + packet)
        except Exception as e:
            logger.exception(f"[tun_read_cb] Exception: {e}")
            return

    async def handle(self):
        """
        Handles the loop of receiving and sending data to and from the client.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        loop = asyncio.get_running_loop()
        loop.add_reader(tun, self.tun_read_cb)
        try:
            await self.recv_from_client()
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            try:
                loop.remove_reader(tun)
            except Exception:
                pass


def stream_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Creates the stream handling functionality using the VPNServerProtocol class.

    Because AIOQUIC is asynchronous, this must be an async task.

    Parameters
    ----------
    reader : StreamReader
            The reader that aioquic receives network traffic from.
    writer : StreamWriter
        The writer that the VPN writes to in preparation for sending to the client.

    Returns
    -------
    None
    """
    asyncio.create_task(VPNServerProtocol(reader, writer).handle())

async def vpn_server():
    """
    Essentially the main function of the VPN server, describes all functionality 
    including mTLS and general tunneling operations performed by the VPN.

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    # Keep existing behavior: generate self-signed certs if nothing provided
    generate_self_signed_cert()

    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["hq-29"],
        max_stream_data=65536,
        max_data=524288,
    )
    configuration.idle_timeout = 30.0

    # Prefer env-provided certs, else fall back to generated ones
    certfile = SERVER_CERT_ENV if os.path.exists(SERVER_CERT_ENV) else "cert.pem"
    keyfile  = SERVER_KEY_ENV  if os.path.exists(SERVER_KEY_ENV)  else "key.pem"
    configuration.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # mTLS: require client certificate and trust the CA
    configuration.verify_mode = ssl.CERT_REQUIRED
    if os.path.exists(CA_CERT_ENV):
        configuration.load_verify_locations(CA_CERT_ENV)
    else:
        logger.warning(
            f"CA certificate not found at {CA_CERT_ENV}. "
            "mTLS will fail unless a valid CA is provided."
        )

    server = await serve(
        host=SERVER_IP,
        port=QUIC_PORT,
        configuration=configuration,
        stream_handler=stream_handler,
    )
    logger.info(f"QUIC VPN server established on IP {SERVER_IP} and port {QUIC_PORT}")
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(vpn_server())

