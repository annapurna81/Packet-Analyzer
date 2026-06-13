"""
pcap_writer.py
Writes packets to a PCAP file (same format Wireshark can open).
"""

import struct

PCAP_MAGIC    = 0xa1b2c3d4
VERSION_MAJOR = 2
VERSION_MINOR = 4
SNAPLEN       = 65535
NETWORK       = 1   # Ethernet


class PcapWriter:
    """Writes RawPacket objects to a PCAP file."""

    def __init__(self):
        self._f = None

    def open(self, filename: str) -> bool:
        try:
            self._f = open(filename, 'wb')
        except OSError as e:
            print(f"[PcapWriter] ERROR: Cannot open {filename}: {e}")
            return False

        # Write global header
        self._f.write(struct.pack(
            '<IHHiIII',
            PCAP_MAGIC,
            VERSION_MAJOR,
            VERSION_MINOR,
            0,       # timezone offset
            0,       # sigfigs
            SNAPLEN,
            NETWORK
        ))
        return True

    def write_packet(self, raw_packet):
        """Write one RawPacket to the file."""
        if self._f is None:
            return
        data = raw_packet.data
        self._f.write(struct.pack(
            '<IIII',
            raw_packet.ts_sec,
            raw_packet.ts_usec,
            len(data),
            len(data)
        ))
        self._f.write(data)

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
