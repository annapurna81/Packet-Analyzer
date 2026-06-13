"""
types_.py  —  re-export everything from types.py
(Using types_.py as the import name to avoid clash with Python's built-in 'types' module)
"""
from types import *  # noqa
from dataclasses import dataclass, field
from enum import Enum, auto
import socket


class AppType(Enum):
    UNKNOWN   = auto()
    HTTP      = auto()
    HTTPS     = auto()
    DNS       = auto()
    GOOGLE    = auto()
    YOUTUBE   = auto()
    FACEBOOK  = auto()
    TWITTER   = auto()
    INSTAGRAM = auto()
    TIKTOK    = auto()
    GITHUB    = auto()
    NETFLIX   = auto()
    WHATSAPP  = auto()
    TELEGRAM  = auto()
    REDDIT    = auto()
    AMAZON    = auto()
    MICROSOFT = auto()
    APPLE     = auto()


SNI_MAP = [
    ("youtube",     AppType.YOUTUBE),
    ("youtu.be",    AppType.YOUTUBE),
    ("googlevideo", AppType.YOUTUBE),
    ("facebook",    AppType.FACEBOOK),
    ("fbcdn",       AppType.FACEBOOK),
    ("instagram",   AppType.INSTAGRAM),
    ("tiktok",      AppType.TIKTOK),
    ("twitter",     AppType.TWITTER),
    ("twimg",       AppType.TWITTER),
    ("x.com",       AppType.TWITTER),
    ("netflix",     AppType.NETFLIX),
    ("whatsapp",    AppType.WHATSAPP),
    ("telegram",    AppType.TELEGRAM),
    ("github",      AppType.GITHUB),
    ("reddit",      AppType.REDDIT),
    ("amazon",      AppType.AMAZON),
    ("amazonaws",   AppType.AMAZON),
    ("microsoft",   AppType.MICROSOFT),
    ("office365",   AppType.MICROSOFT),
    ("apple.com",   AppType.APPLE),
    ("icloud",      AppType.APPLE),
    ("google",      AppType.GOOGLE),
]


def sni_to_app_type(sni: str) -> AppType:
    sni_lower = sni.lower()
    for keyword, app in SNI_MAP:
        if keyword in sni_lower:
            return app
    return AppType.UNKNOWN


@dataclass(frozen=True)
class FiveTuple:
    src_ip:   int
    dst_ip:   int
    src_port: int
    dst_port: int
    protocol: int

    def src_ip_str(self) -> str:
        return socket.inet_ntoa(self.src_ip.to_bytes(4, 'big'))

    def dst_ip_str(self) -> str:
        return socket.inet_ntoa(self.dst_ip.to_bytes(4, 'big'))

    def __str__(self):
        return (f"{self.src_ip_str()}:{self.src_port} → "
                f"{self.dst_ip_str()}:{self.dst_port} "
                f"({'TCP' if self.protocol == 6 else 'UDP'})")


@dataclass
class Flow:
    tuple:    FiveTuple = None
    sni:      str       = ""
    app_type: AppType   = None
    blocked:  bool      = False
    packets:  int       = 0
    bytes:    int       = 0

    def __post_init__(self):
        if self.app_type is None:
            self.app_type = AppType.UNKNOWN


@dataclass
class ParsedPacket:
    src_mac:    str       = ""
    dst_mac:    str       = ""
    eth_type:   int       = 0
    src_ip:     str       = ""
    dst_ip:     str       = ""
    protocol:   int       = 0
    ttl:        int       = 0
    src_port:   int       = 0
    dst_port:   int       = 0
    tcp_flags:  int       = 0
    has_tcp:    bool      = False
    has_udp:    bool      = False
    payload:    bytes     = b""
    five_tuple: FiveTuple = None
