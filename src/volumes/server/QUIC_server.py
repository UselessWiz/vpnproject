#!/usr/bin/env python3

import asyncio
import os
import struct
from scapy.all import *
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from shared.create_tun import create_tun
from tools.generate_cert import generate_self_signed_cert

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
TUN_IP = "192.168.53.98"
SERVER_IP = "10.9.0.11"
QUIC_PORT = 4433

ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add {TUN_IP}/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

class VPNServerProtocol:
    # These are Async streamreader/writers
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def recv_from_client(self):
        while True:
            try:
                length_bytes = await self.reader.readexactly(2) # Read exactly 2 bytes.
                pkt_len = struct.unpack("!H", length_bytes)[0] #! = network (big-endian), H = unsigned short.
                data = await self.reader.readexactly(pkt_len)

                pkt = IP(data)
                logger.info(f"From client <==: {pkt.src} --> {pkt.dst}")
                os.write(tun, data)
            except Exception as e:
                logger.exception(f"[recv_from_client] Exception: {e}")
                os._exit(1)

    def tun_read_cb(self):
        packet = os.read(tun, 2048)
        pkt = IP(packet)
        logger.info(f"From tun ==>: {pkt.src} --> {pkt.dst}")
        length_prefix = struct.pack("!H", len(packet))
        self.writer.write(length_prefix + packet)

    async def handle(self):
        loop = asyncio.get_running_loop()
        loop.add_reader(tun, self.tun_read_cb)
        await self.recv_from_client()


def stream_handler(reader, writer):
    asyncio.create_task(VPNServerProtocol(reader, writer).handle())


async def vpn_server():
    generate_self_signed_cert()
    configuration = QuicConfiguration(
        is_client=False,
        max_stream_data = 65536,
        max_data=524288
    )
    configuration.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
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
