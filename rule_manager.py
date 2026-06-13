"""
rule_manager.py

Manages the three types of blocking rules:
  1. IP rules    — block all traffic from a specific source IP
  2. App rules   — block all traffic of a specific app type (e.g. YouTube)
  3. Domain rules — block any connection whose SNI contains a keyword

Blocking flow for each packet:
  Is source IP blocked?   → DROP
  Is app type blocked?    → DROP
  Does SNI match domain?  → DROP
  Otherwise               → FORWARD
"""

import socket
from types_ import AppType, FiveTuple


class RuleManager:

    def __init__(self):
        self._blocked_ips:     set[int]      = set()   # stored as uint32
        self._blocked_apps:    set[AppType]  = set()
        self._blocked_domains: list[str]     = []      # substring match

    # ── Adding rules ─────────────────────────────────────────────────────────

    def block_ip(self, ip_str: str):
        """Block all traffic from this source IP. e.g. '192.168.1.50'"""
        try:
            packed = socket.inet_aton(ip_str)
            ip_int = int.from_bytes(packed, 'big')
            self._blocked_ips.add(ip_int)
            print(f"[Rules] Blocked IP: {ip_str}")
        except OSError:
            print(f"[Rules] WARNING: Invalid IP address: {ip_str}")

    def block_app(self, app_name: str):
        """Block all traffic of a named app. e.g. 'YouTube', 'TikTok'"""
        try:
            app = AppType[app_name.upper()]
            self._blocked_apps.add(app)
            print(f"[Rules] Blocked app: {app_name}")
        except KeyError:
            print(f"[Rules] WARNING: Unknown app '{app_name}'. "
                  f"Known apps: {[a.name for a in AppType]}")

    def block_domain(self, domain_keyword: str):
        """Block any SNI containing this keyword. e.g. 'tiktok', 'facebook'"""
        self._blocked_domains.append(domain_keyword.lower())
        print(f"[Rules] Blocked domain keyword: {domain_keyword}")

    # ── Checking rules ────────────────────────────────────────────────────────

    def is_blocked(self, src_ip_int: int, app_type: AppType, sni: str) -> bool:
        """
        Returns True if this packet/flow should be dropped.
        Checks all three rule types in order.
        """
        # 1. IP blacklist
        if src_ip_int in self._blocked_ips:
            return True

        # 2. App blacklist
        if app_type in self._blocked_apps:
            return True

        # 3. Domain keyword match (substring)
        if sni:
            sni_lower = sni.lower()
            for keyword in self._blocked_domains:
                if keyword in sni_lower:
                    return True

        return False

    def has_rules(self) -> bool:
        return bool(self._blocked_ips or self._blocked_apps or self._blocked_domains)

    def summary(self) -> str:
        lines = []
        if self._blocked_ips:
            import socket as _s
            ips = [_s.inet_ntoa(ip.to_bytes(4,'big')) for ip in self._blocked_ips]
            lines.append(f"  Blocked IPs:     {', '.join(ips)}")
        if self._blocked_apps:
            lines.append(f"  Blocked apps:    {', '.join(a.name for a in self._blocked_apps)}")
        if self._blocked_domains:
            lines.append(f"  Blocked domains: {', '.join(self._blocked_domains)}")
        return '\n'.join(lines) if lines else "  (no rules set)"
