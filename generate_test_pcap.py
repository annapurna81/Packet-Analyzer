"""
generate_test_pcap.py

Creates a realistic test PCAP file with:
  - HTTPS traffic to YouTube, Facebook, Google, GitHub (with real TLS Client Hello + SNI)
  - Plain HTTP traffic to an example website
  - DNS queries
  - Unknown TCP traffic
  - Traffic from a "blocked" IP (192.168.1.50)

Run:  python generate_test_pcap.py
Output: test_dpi.pcap
"""

import struct
import random
import time


# ── Low-level helpers ────────────────────────────────────────────────────────

def mac_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(':'))


def ip_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split('.'))


def u16be(v: int) -> bytes:
    return struct.pack('!H', v)


def u32be(v: int) -> bytes:
    return struct.pack('!I', v)


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ── Build a real TLS Client Hello with SNI ───────────────────────────────────

def build_tls_client_hello(sni: str) -> bytes:
    """
    Builds a minimal but valid TLS 1.2 Client Hello packet containing
    the SNI extension with the given hostname.
    """
    sni_bytes = sni.encode('utf-8')
    sni_len   = len(sni_bytes)

    # SNI extension payload
    sni_ext = (
        b'\x00\x00'                  # extension type: SNI (0x0000)
        + u16be(sni_len + 5)         # extension length
        + u16be(sni_len + 3)         # SNI list length
        + b'\x00'                    # SNI type: hostname
        + u16be(sni_len)             # hostname length
        + sni_bytes                  # hostname
    )

    # A minimal set of cipher suites (TLS_RSA_WITH_AES_128_CBC_SHA)
    cipher_suites = b'\x00\x2f'
    cipher_block  = u16be(len(cipher_suites)) + cipher_suites

    # Compression: null only
    compression = b'\x01\x00'

    # Extensions block
    extensions = sni_ext
    ext_block  = u16be(len(extensions)) + extensions

    # Client Hello body
    client_hello_body = (
        b'\x03\x03'               # client version: TLS 1.2
        + random.randbytes(32)    # random (32 bytes)
        + b'\x00'                 # session ID length: 0
        + cipher_block
        + compression
        + ext_block
    )

    # Handshake header: type=0x01 (Client Hello) + 3-byte length
    hs_len  = len(client_hello_body)
    handshake = (
        b'\x01'                         # Handshake Type: Client Hello
        + struct.pack('!I', hs_len)[1:] # 3-byte length
        + client_hello_body
    )

    # TLS record header
    record = (
        b'\x16'           # Content Type: Handshake
        + b'\x03\x01'     # TLS version: 1.0
        + u16be(len(handshake))
        + handshake
    )

    return record


def build_http_request(host: str, path: str = '/') -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\n"
        f"\r\n"
    ).encode()


def build_dns_query(domain: str) -> bytes:
    """Build a minimal DNS query for the given domain."""
    txid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)  # 1 question
    qname  = b''
    for label in domain.split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    question = qname + b'\x00\x01\x00\x01'   # QTYPE=A, QCLASS=IN
    return header + question


# ── Build full Ethernet/IP/TCP packet ────────────────────────────────────────

CLIENT_MAC = mac_bytes('00:11:22:33:44:55')
ROUTER_MAC = mac_bytes('aa:bb:cc:dd:ee:ff')


def build_ethernet(src_mac, dst_mac, payload: bytes) -> bytes:
    # Ethernet II: dst_mac(6) + src_mac(6) + EtherType(2) + payload
    return dst_mac + src_mac + b'\x08\x00' + payload   # EtherType IPv4


def build_ip(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    ihl      = 5
    ver_ihl  = (4 << 4) | ihl
    total    = 20 + len(payload)
    ttl      = 64
    ip_id    = random.randint(1, 65535)
    hdr = struct.pack('!BBHHHBBH4s4s',
        ver_ihl, 0, total, ip_id, 0, ttl, proto, 0,
        ip_bytes(src_ip), ip_bytes(dst_ip)
    )
    cksum = checksum(hdr)
    hdr = hdr[:10] + struct.pack('!H', cksum) + hdr[12:]
    return hdr + payload


def build_tcp(src_port: int, dst_port: int, payload: bytes,
              flags: int = 0x18,       # PSH + ACK
              seq: int = None, ack: int = None) -> bytes:
    seq = seq or random.randint(1000, 999999)
    ack = ack or 0
    data_offset = (5 << 4)             # 5 × 4 = 20 bytes header
    hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, ack,
        data_offset, flags, 65535, 0, 0
    )
    return hdr + payload


def build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack('!HHHH', src_port, dst_port, length, 0) + payload


def make_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload, flags=0x18):
    tcp  = build_tcp(src_port, dst_port, payload, flags=flags)
    ip   = build_ip(src_ip, dst_ip, 6, tcp)
    eth  = build_ethernet(CLIENT_MAC, ROUTER_MAC, ip)
    return eth


def make_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    udp = build_udp(src_port, dst_port, payload)
    ip  = build_ip(src_ip, dst_ip, 17, udp)
    eth = build_ethernet(CLIENT_MAC, ROUTER_MAC, ip)
    return eth


# ── PCAP writer ───────────────────────────────────────────────────────────────

def write_pcap(filename: str, packets: list[bytes]):
    with open(filename, 'wb') as f:
        # Global header (24 bytes: magic+vmaj+vmin+thiszone+sigfigs+snaplen+network)
        f.write(struct.pack('<IHHiIII',
            0xa1b2c3d4,   # magic
            2,            # version major
            4,            # version minor
            0,            # timezone
            0,            # sigfigs
            65535,        # snaplen
            1             # Ethernet
        ))
        ts = int(time.time())
        for i, pkt in enumerate(packets):
            f.write(struct.pack('<IIII',
                ts + i, 0, len(pkt), len(pkt)
            ))
            f.write(pkt)
    print(f"[Generator] Wrote {len(packets)} packets → {filename}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    packets = []
    client  = '192.168.1.100'
    blocked_client = '192.168.1.50'
    dns_server = '8.8.8.8'

    # ── HTTPS sessions with TLS Client Hello (SNI visible) ───────────────────
    sessions = [
        ('172.217.14.206', 'www.youtube.com',  random.randint(50000, 60000)),
        ('31.13.79.35',    'www.facebook.com', random.randint(50000, 60000)),
        ('142.250.185.78', 'www.google.com',   random.randint(50000, 60000)),
        ('140.82.112.4',   'github.com',       random.randint(50000, 60000)),
        ('52.94.236.248',  'www.amazon.com',   random.randint(50000, 60000)),
    ]

    for server_ip, domain, sport in sessions:
        # TCP SYN
        packets.append(make_tcp_packet(client, server_ip, sport, 443, b'', flags=0x02))
        # TCP SYN-ACK (reversed)
        packets.append(make_tcp_packet(server_ip, client, 443, sport, b'', flags=0x12))
        # TCP ACK
        packets.append(make_tcp_packet(client, server_ip, sport, 443, b'', flags=0x10))
        # TLS Client Hello with SNI  ← this is what the DPI engine inspects
        tls_hello = build_tls_client_hello(domain)
        packets.append(make_tcp_packet(client, server_ip, sport, 443, tls_hello))
        # A few data packets (already encrypted, no SNI)
        for _ in range(3):
            dummy = random.randbytes(random.randint(100, 400))
            packets.append(make_tcp_packet(client, server_ip, sport, 443, dummy))

    # ── Plain HTTP traffic (Host header visible) ──────────────────────────────
    http_sessions = [
        ('93.184.216.34', 'www.example.com',  random.randint(50000, 60000)),
        ('151.101.1.140', 'old.reddit.com',   random.randint(50000, 60000)),
    ]
    for server_ip, domain, sport in http_sessions:
        req = build_http_request(domain)
        packets.append(make_tcp_packet(client, server_ip, sport, 80, req))
        for _ in range(2):
            packets.append(make_tcp_packet(client, server_ip, sport, 80,
                                           random.randbytes(200)))

    # ── DNS queries ───────────────────────────────────────────────────────────
    for domain in ['www.youtube.com', 'www.facebook.com', 'www.google.com',
                   'github.com']:
        dns_payload = build_dns_query(domain)
        sport = random.randint(40000, 50000)
        packets.append(make_udp_packet(client, dns_server, sport, 53, dns_payload))

    # ── Traffic from a blocked IP ─────────────────────────────────────────────
    for domain, server_ip in [('www.youtube.com', '172.217.14.206'),
                               ('www.google.com',  '142.250.185.78')]:
        sport = random.randint(50000, 60000)
        tls_hello = build_tls_client_hello(domain)
        packets.append(make_tcp_packet(blocked_client, server_ip, sport, 443, b'', flags=0x02))
        packets.append(make_tcp_packet(blocked_client, server_ip, sport, 443, tls_hello))

    # ── Unknown / misc TCP traffic ────────────────────────────────────────────
    for _ in range(5):
        packets.append(make_tcp_packet(
            client, f'10.0.0.{random.randint(1,254)}',
            random.randint(50000,60000), random.randint(1024, 49151),
            random.randbytes(random.randint(50, 300))
        ))

    random.shuffle(packets)
    write_pcap('test_dpi.pcap', packets)
    print(f"[Generator] Domains included: youtube, facebook, google, github, amazon, example.com, reddit")
    print(f"[Generator] Blocked IP traffic: {blocked_client}")
    print(f"[Generator] Test with:")
    print(f"  python main.py test_dpi.pcap output.pcap --block-app YOUTUBE --block-ip {blocked_client}")


if __name__ == '__main__':
    main()
