"""
main.py  —  Deep Packet Inspection Engine (Python)
============================================================
Usage:
  # Simple (single-threaded):
  python main.py input.pcap output.pcap

  # With blocking rules:
  python main.py input.pcap output.pcap --block-app YOUTUBE --block-app TIKTOK
  python main.py input.pcap output.pcap --block-ip 192.168.1.50
  python main.py input.pcap output.pcap --block-domain facebook

  # Multi-threaded version:
  python main.py input.pcap output.pcap --multi-thread
  python main.py input.pcap output.pcap --multi-thread --lbs 2 --fps 2

  # Combine everything:
  python main.py test_dpi.pcap filtered.pcap \\
      --block-app YOUTUBE \\
      --block-ip 192.168.1.50 \\
      --block-domain tiktok \\
      --multi-thread --lbs 2 --fps 2
"""

import argparse
import sys
import os

# Make sure all modules in this folder are importable
sys.path.insert(0, os.path.dirname(__file__))

from rule_manager import RuleManager


def main():
    parser = argparse.ArgumentParser(
        description="Python Deep Packet Inspection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Positional args
    parser.add_argument('input_pcap',  help='Input PCAP file (e.g. test_dpi.pcap)')
    parser.add_argument('output_pcap', help='Output PCAP file (filtered packets)')

    # Blocking rules
    parser.add_argument('--block-app',    action='append', default=[], metavar='APP',
                        help='Block an app by name. E.g. --block-app YOUTUBE')
    parser.add_argument('--block-ip',     action='append', default=[], metavar='IP',
                        help='Block all traffic from an IP. E.g. --block-ip 192.168.1.50')
    parser.add_argument('--block-domain', action='append', default=[], metavar='KEYWORD',
                        help='Block any SNI containing this keyword. E.g. --block-domain tiktok')

    # Engine choice
    parser.add_argument('--multi-thread', action='store_true',
                        help='Use the multi-threaded engine (default: single-threaded)')
    parser.add_argument('--lbs', type=int, default=2,
                        help='Number of Load Balancer threads (multi-threaded only, default: 2)')
    parser.add_argument('--fps', type=int, default=2,
                        help='Number of Fast Path threads per LB (default: 2)')

    args = parser.parse_args()

    # ── Print banner ─────────────────────────────────────────────────────────
    mode = "Multi-Threaded" if args.multi_thread else "Single-Threaded"
    print("╔══════════════════════════════════════════════════════════╗")
    print(f"║         Python DPI Engine  [{mode:^16}]         ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Set up rules ─────────────────────────────────────────────────────────
    rules = RuleManager()
    for app in args.block_app:
        rules.block_app(app)
    for ip in args.block_ip:
        rules.block_ip(ip)
    for domain in args.block_domain:
        rules.block_domain(domain)

    if not rules.has_rules():
        print("[Rules] No blocking rules set — all traffic will be forwarded.")
    else:
        print("[Rules] Active rules:")
        print(rules.summary())

    # ── Run the engine ────────────────────────────────────────────────────────
    if args.multi_thread:
        from dpi_mt import MTDPIEngine
        engine = MTDPIEngine(rules, num_lbs=args.lbs, fps_per_lb=args.fps)
    else:
        from dpi_engine import DPIEngine
        engine = DPIEngine(rules)

    engine.process(args.input_pcap, args.output_pcap)


if __name__ == '__main__':
    main()
