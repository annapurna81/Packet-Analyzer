"""
pcap_reader.py
Reads PCAP files (the format Wireshark saves captures in).
No external libraries needed — pure Python struct parsing.
"""

import struct


# PCAP magic number that identifies the file format
PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAGIC_NANO = 0xa1b23c4d  # nanosecond variant

GLOBAL_HEADER_SIZE = 24  # bytes
PACKET_HEADER_SIZE = 16  # bytes


class RawPacket:
    """Holds one raw packet read from the PCAP file."""
    def __init__(self, ts_sec, ts_usec, data):
        self.ts_sec  = ts_sec    # timestamp seconds
        self.ts_usec = ts_usec   # timestamp microseconds
        self.data    = data      # raw bytes of the packet


class PcapReader:
    """
    Reads a PCAP file packet by packet.

    PCAP file layout:
    ┌─────────────────────────┐
    │ Global Header (24 bytes)│  ← read once
    ├─────────────────────────┤
    │ Packet Header (16 bytes)│  ← repeated for each packet
    │ Packet Data  (N bytes)  │
    ├─────────────────────────┤
    │ ... more packets ...    │
    └─────────────────────────┘
    """

    def __init__(self):
        self._f          = None
        self._byteorder  = '<'   # little-endian by default
        self.snaplen     = 0
        self.network     = 0

    def open(self, filename: str) -> bool:
        """Open and validate a PCAP file. Returns True on success."""
        try:
            self._f = open(filename, 'rb')
        except FileNotFoundError:
            print(f"[PcapReader] ERROR: File not found: {filename}")
            return False

        raw_header = self._f.read(GLOBAL_HEADER_SIZE)
        if len(raw_header) < GLOBAL_HEADER_SIZE:
            print("[PcapReader] ERROR: File too small to be a valid PCAP.")
            return False

        # Detect byte order from magic number
        magic = struct.unpack_from('<I', raw_header, 0)[0]
        if magic in (PCAP_MAGIC, PCAP_MAGIC_NANO):
            self._byteorder = '<'
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            self._byteorder = '>'
        else:
            print(f"[PcapReader] ERROR: Not a valid PCAP file (bad magic: {magic:#010x})")
            return False

        bo = self._byteorder
        _, _, _, _, self.snaplen, self.network = struct.unpack_from(
            f'{bo}IHHiII', raw_header, 0
        )
        return True

    def read_next_packet(self):
        """
        Read the next packet from the file.
        Returns a RawPacket, or None when there are no more packets.
        """
        if self._f is None:
            return None

        hdr = self._f.read(PACKET_HEADER_SIZE)
        if len(hdr) < PACKET_HEADER_SIZE:
            return None   # End of file

        bo = self._byteorder
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(f'{bo}IIII', hdr, 0)

        data = self._f.read(incl_len)
        if len(data) < incl_len:
            return None   # Truncated

        return RawPacket(ts_sec, ts_usec, data)

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    # ── context manager support ──────────────────────────────────────────────
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
