#!/usr/bin/env python3

import asyncio
import os
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
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

ifname, tun = create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI)
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")
os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

async def recv_from_server(reader):
    while True:
        try:
            length_bytes = await reader.readexactly(2)
            pkt_len = struct.unpack("!H", length_bytes)[0]
            data = await reader.readexactly(pkt_len)

            pkt = IP(data)
            logger.info(f"From server <==: {pkt.src} --> {pkt.dst}")
            os.write(tun, data)
        except Exception as e:
            logger.exception(f"[recv_from_server] Exception")
            os._exit(1)

def tun_read_cb(writer):
    packet = os.read(tun, 2048)
    pkt = IP(packet)
    logger.info(f"From tun ==>: {pkt.src} --> {pkt.dst}")
    length_prefix = struct.pack("!H", len(packet))
    writer.write(length_prefix + packet)

async def vpn_client():
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=False,
        max_stream_data = 65536,
        max_data=524288
    )

    async with connect(SERVER_IP, 4433, configuration=configuration) as connection:
        reader, writer = await connection.create_stream()
        loop = asyncio.get_running_loop()
        loop.add_reader(tun, tun_read_cb, writer)

        await recv_from_server(reader)

if __name__ == "__main__":
    asyncio.run(vpn_client())