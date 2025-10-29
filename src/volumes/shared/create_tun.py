#!/usr/bin/env python3

import fcntl
import struct
import os
import logging

logger = logging.getLogger(__name__)

def create_tun(TUNSETIFF, IFF_TUN, IFF_NO_PI):
    """
    Creates a TUN interface which allows for networking in userspace program, such as the VPN. On the client side, traffic comes into the TUN interface, gets encrypted and sent out the actual interface over the internet.

    Parameters
    ----------
    TUNSETIFF : bytes
        The IOCTL command which binds a file descriptor to a network interface, as defined in the linux kernel.
    IFF_TUN : int
        The flag to describe if this interface should be opened in TUN mode or TUF mode.
    IFF_NO_PI : int
        The flag to describe if packet info should be provided.
    
    Returns
    -------
    string, int (File object)
        The interface name and a pointer to the TUN file
    """
    # Open the network tunnel file descriptor in read/write mode. Linux devices are represented as files in the /dev directory.
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)

    # Run the ioctl command to map the file descriptor to the interface
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

    # Get the interface name
    ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
    logger.info("Interface Name: {}".format(ifname))
    return ifname, tun
