"""
dpi_mt.py  —  Multi-Threaded DPI Engine

Architecture:
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │ hash(5-tuple) % num_lbs
              ┌──────────────┴──────────────┐
              ▼                             ▼
    ┌──────────────────┐         ┌──────────────────┐
    │  LoadBalancer-0  │         │  LoadBalancer-1  │
    └────────┬─────────┘         └────────┬─────────┘
             │ hash % fps_per_lb           │
      ┌──────┴──────┐               ┌──────┴──────┐
      ▼             ▼               ▼             ▼
 ┌─────────┐  ┌─────────┐    ┌─────────┐  ┌─────────┐
 │ FastPath│  │ FastPath│    │ FastPath│  │ FastPath│
 │   FP-0  │  │   FP-1  │    │   FP-2  │  │   FP-3  │
 └────┬────┘  └────┬────┘    └────┬────┘  └────┬────┘
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │     Output Queue      │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │   Writer Thread       │
              │  (writes to PCAP)     │
              └───────────────────────┘

KEY DESIGN: Consistent hashing
  - Same 5-tuple always → same FastPath thread
  - So all packets of one TCP connection land on the same FP
  - FP can maintain correct per-flow state without locking
"""

import threading
import queue
from collections import defaultdict

from pcap_reader   import PcapReader
from pcap_writer   import PcapWriter
import packet_parser
from sni_extractor import extract_domain
from rule_manager  import RuleManager
from types_        import Flow, AppType, FiveTuple, sni_to_app_type


# Sentinel to signal a thread it should shut down
_STOP = object()

# How many packets each queue can hold before the producer blocks
QUEUE_MAXSIZE = 2000


# ── Thread-Safe Queue wrapper ────────────────────────────────────────────────

class TSQueue:
    """
    A thread-safe queue that wraps Python's queue.Queue.
    - push() adds an item (blocks if full)
    - pop()  removes an item (blocks if empty)
    """

    def __init__(self, maxsize: int = QUEUE_MAXSIZE):
        self._q = queue.Queue(maxsize=maxsize)

    def push(self, item):
        self._q.put(item)

    def pop(self):
        return self._q.get()

    def empty(self) -> bool:
        return self._q.empty()

    def size(self) -> int:
        return self._q.qsize()


# ── Fast Path Thread ─────────────────────────────────────────────────────────

class FastPath(threading.Thread):
    """
    Does the actual DPI work:
      - Maintains its own flow table (no locking needed due to consistent hashing)
      - Extracts SNI
      - Checks blocking rules
      - Forwards or drops
    """

    def __init__(self, fp_id: int, rules: RuleManager, output_queue: TSQueue):
        super().__init__(daemon=True, name=f"FP-{fp_id}")
        self.fp_id        = fp_id
        self.rules        = rules
        self.output_queue = output_queue

        self.input_queue  = TSQueue()

        # Each FP has its own private flow table
        self._flows: dict[FiveTuple, Flow] = {}

        # Stats
        self.processed   = 0
        self.dropped     = 0
        self.found_domains: dict[str, AppType] = {}

    def run(self):
        while True:
            item = self.input_queue.pop()
            if item is _STOP:
                break

            raw, parsed = item
            self.processed += 1

            if parsed is None:
                self.output_queue.push(raw)
                continue

            ft = parsed.five_tuple
            if ft not in self._flows:
                self._flows[ft] = Flow(tuple=ft)
            flow = self._flows[ft]
            flow.packets += 1
            flow.bytes   += len(raw.data)

            # Extract SNI
            if not flow.sni and parsed.payload:
                domain = extract_domain(parsed.payload, parsed.dst_port)
                if domain:
                    flow.sni      = domain
                    flow.app_type = sni_to_app_type(domain)
                    self.found_domains[domain] = flow.app_type
                    if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                        flow.blocked = True

            # Port-based fallback
            if flow.app_type == AppType.UNKNOWN:
                if parsed.dst_port == 443:
                    flow.app_type = AppType.HTTPS
                elif parsed.dst_port == 80:
                    flow.app_type = AppType.HTTP
                elif parsed.dst_port == 53 and parsed.has_udp:
                    flow.app_type = AppType.DNS

            # Apply rules
            if not flow.blocked:
                if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                    flow.blocked = True

            if flow.blocked:
                self.dropped += 1
            else:
                self.output_queue.push(raw)


# ── Load Balancer Thread ─────────────────────────────────────────────────────

class LoadBalancer(threading.Thread):
    """
    Receives packets from the Reader and distributes them to FastPath threads.
    Uses consistent hashing: hash(5-tuple) % num_fps → same FP every time.
    """

    def __init__(self, lb_id: int, fast_paths: list[FastPath]):
        super().__init__(daemon=True, name=f"LB-{lb_id}")
        self.lb_id       = lb_id
        self.fast_paths  = fast_paths
        self.input_queue = TSQueue()
        self.dispatched  = 0

    def run(self):
        n = len(self.fast_paths)
        while True:
            item = self.input_queue.pop()
            if item is _STOP:
                # Propagate stop to all FPs
                for fp in self.fast_paths:
                    fp.input_queue.push(_STOP)
                break

            raw, parsed = item
            if parsed is not None and parsed.five_tuple is not None:
                idx = hash(parsed.five_tuple) % n
            else:
                idx = self.dispatched % n

            self.fast_paths[idx].input_queue.push(item)
            self.dispatched += 1


# ── Multi-Threaded Engine ────────────────────────────────────────────────────

class MTDPIEngine:

    def __init__(self, rules: RuleManager, num_lbs: int = 2, fps_per_lb: int = 2):
        self.rules      = rules
        self.num_lbs    = num_lbs
        self.fps_per_lb = fps_per_lb

        self.total_packets = 0
        self.total_bytes   = 0
        self.tcp_packets   = 0
        self.udp_packets   = 0

    def process(self, input_pcap: str, output_pcap: str):
        output_queue = TSQueue(maxsize=4000)

        # Create FastPath threads (one set per LB)
        all_fps: list[FastPath] = []
        lbs: list[LoadBalancer] = []

        for lb_i in range(self.num_lbs):
            fps = [FastPath(lb_i * self.fps_per_lb + fp_i, self.rules, output_queue)
                   for fp_i in range(self.fps_per_lb)]
            all_fps.extend(fps)
            lbs.append(LoadBalancer(lb_i, fps))

        total_fps = len(all_fps)
        total_threads = self.num_lbs + total_fps

        print(f"\n[MT Engine] Load Balancers : {self.num_lbs}")
        print(f"[MT Engine] Fast Paths     : {total_fps}  ({self.fps_per_lb} per LB)")
        print(f"[MT Engine] Total threads  : {total_threads + 1} (+ writer)\n")

        # Start all threads
        for fp in all_fps:
            fp.start()
        for lb in lbs:
            lb.start()

        # Writer thread: pulls from output_queue and writes to file
        written: list[int] = [0]
        write_done = threading.Event()

        writer = PcapWriter()
        writer.open(output_pcap)

        def writer_thread():
            while True:
                item = output_queue.pop()
                if item is _STOP:
                    break
                writer.write_packet(item)
                written[0] += 1
            writer.close()
            write_done.set()

        wt = threading.Thread(target=writer_thread, daemon=True, name="Writer")
        wt.start()

        # Reader: main thread reads PCAP and pushes to LBs
        reader = PcapReader()
        if not reader.open(input_pcap):
            return

        n_lbs = len(lbs)
        pkt_idx = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            self.total_packets += 1
            self.total_bytes   += len(raw.data)

            parsed = packet_parser.parse(raw.data)
            if parsed:
                if parsed.has_tcp:
                    self.tcp_packets += 1
                elif parsed.has_udp:
                    self.udp_packets += 1

            # Route to LB using hash (or round-robin for non-IP)
            if parsed is not None and parsed.five_tuple:
                lb_idx = hash(parsed.five_tuple) % n_lbs
            else:
                lb_idx = pkt_idx % n_lbs

            lbs[lb_idx].input_queue.push((raw, parsed))
            pkt_idx += 1

        reader.close()
        print(f"[Reader] Done reading {self.total_packets} packets\n")

        # Signal LBs to stop (they will cascade stop to FPs)
        for lb in lbs:
            lb.input_queue.push(_STOP)

        # Wait for LBs and FPs to finish
        for lb in lbs:
            lb.join()
        for fp in all_fps:
            fp.join()

        # Signal writer to stop
        output_queue.push(_STOP)
        write_done.wait()

        self._print_report(lbs, all_fps, written[0])

    # ── Report ────────────────────────────────────────────────────────────────

    def _print_report(self, lbs, fps, written):
        total_dropped = sum(fp.dropped for fp in fps)
        all_domains: dict[str, AppType] = {}
        for fp in fps:
            all_domains.update(fp.found_domains)

        app_stats: dict[AppType, int] = defaultdict(int)
        for fp in fps:
            for flow in fp._flows.values():
                if not flow.blocked:
                    app_stats[flow.app_type] += flow.packets

        W = 66

        def box_line(text=""):
            pad = W - 2 - len(text)
            return f"║ {text}{' ' * max(pad,0)} ║"

        def divider():
            return "╠" + "═" * (W - 2) + "╣"

        print("╔" + "═" * (W - 2) + "╗")
        print(box_line("PROCESSING REPORT  (Multi-Threaded DPI)".center(W - 4)))
        print(divider())
        print(box_line(f"Total Packets : {self.total_packets}"))
        print(box_line(f"Total Bytes   : {self.total_bytes}"))
        print(box_line(f"TCP Packets   : {self.tcp_packets}"))
        print(box_line(f"UDP Packets   : {self.udp_packets}"))
        print(divider())
        print(box_line(f"Forwarded     : {written}"))
        print(box_line(f"Dropped       : {total_dropped}"))
        print(divider())
        print(box_line("THREAD STATISTICS"))
        for lb in lbs:
            print(box_line(f"  {lb.name} dispatched : {lb.dispatched}"))
        for fp in fps:
            print(box_line(f"  {fp.name} processed  : {fp.processed}  (dropped: {fp.dropped})"))
        print(divider())
        print(box_line("APPLICATION BREAKDOWN"))
        print(box_line())
        total_fwd = max(written, 1)
        for app, cnt in sorted(app_stats.items(), key=lambda x: x[1], reverse=True):
            pct = cnt / total_fwd * 100
            bar = "#" * min(int(pct / 2), 20)
            print(box_line(f"  {app.name:<12} {cnt:>5}  {pct:5.1f}%  {bar}"))
        print(divider())
        print(box_line("DETECTED DOMAINS / SNIs"))
        print(box_line())
        if all_domains:
            for domain, app in sorted(all_domains.items()):
                print(box_line(f"  {domain}  →  {app.name}"))
        else:
            print(box_line("  (none detected)"))
        print("╚" + "═" * (W - 2) + "╝\n")
