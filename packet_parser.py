"""
packet_parser.py

Parses raw network packet bytes layer by layer:
  Ethernet → IP → TCP/UDP → Payload

Every network packet is like a Russian nesting doll:
┌─────────────────────────────────────┐
│ Ethernet Header (14 bytes)          │
│ ┌─────────────────────────────────┐ │
│ │ IP Header (20+ bytes)           │ │
│ │ ┌─────────────────────────────┐ │ │
│ │ │ TCP/UDP Header (20/8 bytes) │ │ │
│ │ │ ┌─────────────────────────┐ │ │ │
│ │ │ │ Payload (app data)      │ │ │ │
│ │ │ └─────────────────────────┘ │ │ │
│ │ └─────────────────────────────┘ │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
"""

import struct
import socket
from types_ import ParsedPacket, FiveTuple

# EtherType values
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP  = 0x0806

# IP Protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1


def parse(raw_data: bytes) -> ParsedPacket | None:
    """
    Parse raw packet bytes into a ParsedPacket.
    Returns None if the packet is too short or not IPv4.
    """
    pkt = ParsedPacket()

    # ── Layer 2: Ethernet Header (14 bytes) ─────────────────────────────────
    # Bytes 0-5:   Destination MAC
    # Bytes 6-11:  Source MAC
    # Bytes 12-13: EtherType
    if len(raw_data) < 14:
        return None

    dst_mac_bytes = raw_data[0:6]
    src_mac_bytes = raw_data[6:12]
    eth_type      = struct.unpack_from('!H', raw_data, 12)[0]

    pkt.dst_mac  = ':'.join(f'{b:02x}' for b in dst_mac_bytes)
    pkt.src_mac  = ':'.join(f'{b:02x}' for b in src_mac_bytes)
    pkt.eth_type = eth_type

    # We only handle IPv4 in this engine
    if eth_type != ETHERTYPE_IPV4:
        return None

    # ── Layer 3: IPv4 Header (minimum 20 bytes) ──────────────────────────────
    # Byte 0:      Version (high 4 bits) + IHL (low 4 bits)
    # Byte 8:      TTL
    # Byte 9:      Protocol
    # Bytes 12-15: Source IP
    # Bytes 16-19: Destination IP
    ip_start = 14
    if len(raw_data) < ip_start + 20:
        return None

    version_ihl = raw_data[ip_start]
    ip_version  = (version_ihl >> 4) & 0xF
    ip_ihl      = (version_ihl & 0xF) * 4    # header length in bytes

    if ip_version != 4:
        return None

    pkt.ttl      = raw_data[ip_start + 8]
    pkt.protocol = raw_data[ip_start + 9]

    src_ip_raw = raw_data[ip_start + 12 : ip_start + 16]
    dst_ip_raw = raw_data[ip_start + 16 : ip_start + 20]
    pkt.src_ip = socket.inet_ntoa(src_ip_raw)
    pkt.dst_ip = socket.inet_ntoa(dst_ip_raw)

    src_ip_int = int.from_bytes(src_ip_raw, 'big')
    dst_ip_int = int.from_bytes(dst_ip_raw, 'big')

    transport_start = ip_start + ip_ihl

    # ── Layer 4: TCP Header ───────────────────────────────────────────────────
    # Bytes 0-1:  Source Port
    # Bytes 2-3:  Destination Port
    # Bytes 4-7:  Sequence Number
    # Bytes 8-11: Acknowledgment Number
    # Byte 12:    Data Offset (high 4 bits) = TCP header length in 32-bit words
    # Byte 13:    Flags (URG ACK PSH RST SYN FIN)
    if pkt.protocol == PROTO_TCP:
        if len(raw_data) < transport_start + 20:
            return None
        pkt.has_tcp   = True
        pkt.src_port  = struct.unpack_from('!H', raw_data, transport_start)[0]
        pkt.dst_port  = struct.unpack_from('!H', raw_data, transport_start + 2)[0]
        pkt.tcp_flags = raw_data[transport_start + 13]
        data_offset   = (raw_data[transport_start + 12] >> 4) * 4
        pkt.payload   = raw_data[transport_start + data_offset:]

    # ── Layer 4: UDP Header ───────────────────────────────────────────────────
    # Bytes 0-1: Source Port
    # Bytes 2-3: Destination Port
    # Bytes 4-5: Length
    # Bytes 6-7: Checksum
    elif pkt.protocol == PROTO_UDP:
        if len(raw_data) < transport_start + 8:
            return None
        pkt.has_udp  = True
        pkt.src_port = struct.unpack_from('!H', raw_data, transport_start)[0]
        pkt.dst_port = struct.unpack_from('!H', raw_data, transport_start + 2)[0]
        pkt.payload  = raw_data[transport_start + 8:]

    else:
        # ICMP or other — no ports
        pkt.payload = raw_data[transport_start:]

    # ── Build Five-Tuple ──────────────────────────────────────────────────────
    pkt.five_tuple = FiveTuple(
        src_ip   = src_ip_int,
        dst_ip   = dst_ip_int,
        src_port = pkt.src_port,
        dst_port = pkt.dst_port,
        protocol = pkt.protocol
    )

    return pkt
