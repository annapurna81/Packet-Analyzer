"""
sni_extractor.py

Extracts domain names (SNI) from:
  1. TLS Client Hello  (HTTPS traffic — port 443)
  2. HTTP Host header  (plain HTTP traffic — port 80)

WHY SNI IS VISIBLE IN HTTPS:
  Even though HTTPS encrypts everything, the very FIRST packet
  (TLS Client Hello) contains the target domain in plaintext
  so the server knows which certificate to present.

TLS Client Hello structure we navigate:
  Byte 0:     0x16 = TLS Handshake record
  Bytes 1-2:  TLS version
  Bytes 3-4:  Record length
  Byte 5:     0x01 = Client Hello handshake type
  Bytes 6-8:  Handshake length
  Bytes 9-10: Client version
  Bytes 11-42: Random (32 bytes)
  Byte 43:    Session ID length (N)
  ... Session ID (N bytes) ...
  ... Cipher Suites ...
  ... Compression Methods ...
  ... Extensions ...
    Extension type 0x0000 = SNI  ← we find THIS
      SNI list length
      SNI type (0x00 = hostname)
      SNI length
      SNI value  ← "www.youtube.com"  ← GOAL
"""

import struct
from typing import Optional


# ── TLS SNI Extraction ───────────────────────────────────────────────────────

TLS_HANDSHAKE      = 0x16
TLS_CLIENT_HELLO   = 0x01
EXT_SNI            = 0x0000


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Try to extract the SNI hostname from a TLS Client Hello payload.
    Returns the hostname string, or None if not found / not a Client Hello.
    """
    try:
        if len(payload) < 6:
            return None

        # Check TLS record type (Byte 0 must be 0x16 = Handshake)
        if payload[0] != TLS_HANDSHAKE:
            return None

        # Check handshake type (Byte 5 must be 0x01 = Client Hello)
        if payload[5] != TLS_CLIENT_HELLO:
            return None

        # Offset 43 = after: record header(5) + hs header(4) +
        #                     version(2) + random(32) = 43
        offset = 43

        if offset >= len(payload):
            return None

        # Skip Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        # Skip Cipher Suites
        cipher_suites_len = struct.unpack_from('!H', payload, offset)[0]
        offset += 2 + cipher_suites_len

        if offset + 1 > len(payload):
            return None

        # Skip Compression Methods
        compression_len = payload[offset]
        offset += 1 + compression_len

        if offset + 2 > len(payload):
            return None

        # Read Extensions total length
        extensions_len = struct.unpack_from('!H', payload, offset)[0]
        offset += 2
        ext_end = offset + extensions_len

        # Walk through each extension looking for type 0x0000 (SNI)
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type   = struct.unpack_from('!H', payload, offset)[0]
            ext_length = struct.unpack_from('!H', payload, offset + 2)[0]
            offset += 4

            if ext_type == EXT_SNI:
                # SNI extension layout:
                #   2 bytes: SNI list length
                #   1 byte:  SNI type (0x00 = hostname)
                #   2 bytes: hostname length
                #   N bytes: hostname
                if offset + 5 > len(payload):
                    return None

                # skip SNI list length (2) + SNI type (1) = 3 bytes
                sni_name_len = struct.unpack_from('!H', payload, offset + 3)[0]
                sni_start    = offset + 5

                if sni_start + sni_name_len > len(payload):
                    return None

                return payload[sni_start : sni_start + sni_name_len].decode(
                    'utf-8', errors='ignore'
                )

            offset += ext_length

    except (struct.error, IndexError):
        pass

    return None


# ── HTTP Host Header Extraction ──────────────────────────────────────────────

HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'DELETE ',
                b'HEAD ', b'OPTIONS ', b'CONNECT ', b'PATCH ')


def extract_http_host(payload: bytes) -> Optional[str]:
    """
    Extract the Host header value from an HTTP request.
    e.g.  "GET / HTTP/1.1\r\nHost: www.example.com\r\n..."
          → returns "www.example.com"
    """
    try:
        # Must start with an HTTP method
        if not any(payload.startswith(m) for m in HTTP_METHODS):
            return None

        # Search for "Host:" header (case-insensitive)
        payload_str = payload.decode('utf-8', errors='ignore')
        for line in payload_str.split('\r\n'):
            if line.lower().startswith('host:'):
                host = line[5:].strip()
                # Remove port if present  e.g. "example.com:8080"
                return host.split(':')[0]
    except Exception:
        pass

    return None


# ── Unified extractor ────────────────────────────────────────────────────────

def extract_domain(payload: bytes, dst_port: int) -> Optional[str]:
    """
    Try to extract a domain name from a packet's payload.
    Tries TLS SNI first (port 443), then HTTP Host (port 80).
    """
    if not payload:
        return None

    if dst_port == 443:
        return extract_sni(payload)

    if dst_port == 80:
        return extract_http_host(payload)

    # Try both for non-standard ports
    sni = extract_sni(payload)
    if sni:
        return sni
    return extract_http_host(payload)
