"""
dpi_engine.py  —  Simple (Single-Threaded) DPI Engine

Journey of a packet through this engine:

  1. Read raw packet from PCAP file
  2. Parse Ethernet → IP → TCP/UDP headers
  3. Look up (or create) the flow in the flow table using the 5-tuple
  4. If the flow has no SNI yet, try to extract it from the payload
  5. Map SNI → AppType
  6. Check blocking rules
  7. Forward (write to output PCAP) or Drop
  8. After all packets → print report
"""

from pcap_reader  import PcapReader
from pcap_writer  import PcapWriter
import packet_parser
from sni_extractor import extract_domain
from rule_manager  import RuleManager
from types_        import Flow, AppType, FiveTuple
from collections   import defaultdict


class DPIEngine:

    def __init__(self, rules: RuleManager):
        self.rules = rules

        # Flow table: FiveTuple → Flow
        # All packets with the same 5-tuple share one Flow object.
        self._flows: dict[FiveTuple, Flow] = {}

        # Counters
        self.total_packets   = 0
        self.total_bytes     = 0
        self.forwarded       = 0
        self.dropped         = 0
        self.tcp_packets     = 0
        self.udp_packets     = 0
        self.app_stats:  dict[AppType, int] = defaultdict(int)
        self.found_domains:  dict[str, AppType] = {}   # for the report

    def process(self, input_pcap: str, output_pcap: str):
        """Main entry point: read input_pcap, write filtered output_pcap."""

        reader = PcapReader()
        if not reader.open(input_pcap):
            return

        writer = PcapWriter()
        if not writer.open(output_pcap):
            reader.close()
            return

        print(f"\n[Engine] Processing: {input_pcap}")
        print(f"[Engine] Output:     {output_pcap}\n")

        try:
            while True:
                raw = reader.read_next_packet()
                if raw is None:
                    break

                self.total_packets += 1
                self.total_bytes   += len(raw.data)

                # ── Parse the packet ─────────────────────────────────────
                parsed = packet_parser.parse(raw.data)

                if parsed is None:
                    # Not IPv4 or too short — forward as-is
                    writer.write_packet(raw)
                    self.forwarded += 1
                    continue

                if parsed.has_tcp:
                    self.tcp_packets += 1
                elif parsed.has_udp:
                    self.udp_packets += 1

                # ── Look up / create the flow ────────────────────────────
                ft = parsed.five_tuple
                if ft not in self._flows:
                    self._flows[ft] = Flow(tuple=ft)
                flow = self._flows[ft]
                flow.packets += 1
                flow.bytes   += len(raw.data)

                # ── Deep Packet Inspection: extract SNI if not yet seen ──
                if not flow.sni and parsed.payload:
                    domain = extract_domain(parsed.payload, parsed.dst_port)
                    if domain:
                        flow.sni      = domain
                        flow.app_type = self._sni_to_app(domain)

                        # Record for the report
                        if domain not in self.found_domains:
                            self.found_domains[domain] = flow.app_type

                        # Now that we know the app, re-check blocking
                        if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                            flow.blocked = True

                # ── Classify by port if still unknown ────────────────────
                if flow.app_type == AppType.UNKNOWN:
                    flow.app_type = self._classify_by_port(
                        parsed.dst_port, parsed.has_tcp, parsed.has_udp
                    )

                # ── Apply blocking rule ───────────────────────────────────
                if not flow.blocked:
                    if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                        flow.blocked = True

                # ── Forward or Drop ───────────────────────────────────────
                if flow.blocked:
                    self.dropped += 1
                else:
                    self.forwarded += 1
                    self.app_stats[flow.app_type] += 1
                    writer.write_packet(raw)

        finally:
            reader.close()
            writer.close()

        self._print_report()

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _sni_to_app(self, sni: str) -> AppType:
        from types_ import sni_to_app_type
        return sni_to_app_type(sni)

    def _classify_by_port(self, port: int, is_tcp: bool, is_udp: bool) -> AppType:
        """Fallback classification when SNI is not available."""
        if port == 443:
            return AppType.HTTPS
        if port == 80:
            return AppType.HTTP
        if port == 53 and is_udp:
            return AppType.DNS
        return AppType.UNKNOWN

    # ── Report ────────────────────────────────────────────────────────────────

    def _print_report(self):
        W = 64   # box width

        def box_line(text="", fill="═"):
            pad = W - 2 - len(text)
            return f"║ {text}{' ' * pad} ║"

        def divider():
            return "╠" + "═" * (W - 2) + "╣"

        print("\n" + "╔" + "═" * (W - 2) + "╗")
        title = "PROCESSING REPORT  (Single-Threaded DPI)"
        print(box_line(title.center(W - 4)))
        print(divider())
        print(box_line(f"Total Packets : {self.total_packets}"))
        print(box_line(f"Total Bytes   : {self.total_bytes}"))
        print(box_line(f"TCP Packets   : {self.tcp_packets}"))
        print(box_line(f"UDP Packets   : {self.udp_packets}"))
        print(divider())
        print(box_line(f"Forwarded     : {self.forwarded}"))
        print(box_line(f"Dropped       : {self.dropped}"))
        print(divider())

        print(box_line("APPLICATION BREAKDOWN"))
        print(box_line())

        total_fwd = max(self.forwarded, 1)
        sorted_apps = sorted(self.app_stats.items(), key=lambda x: x[1], reverse=True)

        for app, count in sorted_apps:
            pct  = count / total_fwd * 100
            bar  = "#" * min(int(pct / 2), 20)
            line = f"  {app.name:<12} {count:>5}  {pct:5.1f}%  {bar}"
            print(box_line(line))

        # Also show blocked apps
        blocked_flows = [f for f in self._flows.values() if f.blocked]
        if blocked_flows:
            print(divider())
            print(box_line("BLOCKED FLOWS"))
            seen_apps: dict[AppType, int] = defaultdict(int)
            for f in blocked_flows:
                seen_apps[f.app_type] += f.packets
            for app, pkt_count in sorted(seen_apps.items(), key=lambda x: x[1], reverse=True):
                print(box_line(f"  {app.name:<12} {pkt_count:>5} packets  (BLOCKED)"))

        print(divider())
        print(box_line("DETECTED DOMAINS / SNIs"))
        print(box_line())
        if self.found_domains:
            for domain, app in sorted(self.found_domains.items()):
                print(box_line(f"  {domain}  →  {app.name}"))
        else:
            print(box_line("  (none detected)"))

        print("╚" + "═" * (W - 2) + "╝\n")
