# Deep Packet Inspection (DPI) Engine — Python

A full Python implementation of a Deep Packet Inspection engine that reads
PCAP network capture files, classifies traffic by application (YouTube, Facebook, etc.),
applies blocking rules, and writes filtered output — all using **zero external libraries**.

---

## What is DPI?

Deep Packet Inspection looks *inside* network packets — not just headers (source/destination IP)
but also the payload — to identify which application the traffic belongs to.

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates report
```

**Key insight:** Even though HTTPS is encrypted, the very first packet (TLS Client Hello)
contains the destination domain name in plaintext as the **SNI (Server Name Indication)**
field. This is how the engine identifies apps even on port 443.

---

## Project Structure

```
dpi_project/
│
├── main.py                  ← Entry point (run this)
│
├── pcap_reader.py           ← Reads .pcap files (Wireshark format)
├── pcap_writer.py           ← Writes filtered .pcap output
├── packet_parser.py         ← Parses Ethernet → IP → TCP/UDP headers
├── sni_extractor.py         ← Extracts domain from TLS Client Hello / HTTP Host
├── rule_manager.py          ← Manages IP / App / Domain blocking rules
├── dpi_engine.py            ← Single-threaded DPI engine
├── dpi_mt.py                ← Multi-threaded DPI engine
├── types_.py                ← Data structures (FiveTuple, Flow, AppType)
│
└── generate_test_pcap.py    ← Generates a test PCAP with sample traffic
```

---

## Requirements

- **Python 3.10 or higher**
- **No external libraries needed** — uses only Python standard library
  (`struct`, `socket`, `threading`, `queue`, `collections`, `argparse`)

---

## How to Run

### Step 1 — Generate a test PCAP file

```bash
python generate_test_pcap.py
```

This creates `test_dpi.pcap` with realistic traffic to:
YouTube, Facebook, Google, GitHub, Amazon, Reddit, example.com
and also includes traffic from a "blocked" IP (192.168.1.50).

---

### Step 2 — Run the DPI engine

**Basic (no blocking rules — just classify):**
```bash
python main.py test_dpi.pcap output.pcap
```

**Block YouTube:**
```bash
python main.py test_dpi.pcap output.pcap --block-app YOUTUBE
```

**Block a specific IP address:**
```bash
python main.py test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

**Block a domain keyword (any SNI containing "tiktok"):**
```bash
python main.py test_dpi.pcap output.pcap --block-domain tiktok
```

**Combine multiple rules:**
```bash
python main.py test_dpi.pcap output.pcap \
    --block-app YOUTUBE \
    --block-app TIKTOK \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Use the multi-threaded engine:**
```bash
python main.py test_dpi.pcap output.pcap --multi-thread
```

**Multi-threaded with custom thread counts:**
```bash
python main.py test_dpi.pcap output.pcap \
    --block-app YOUTUBE \
    --block-ip 192.168.1.50 \
    --multi-thread --lbs 2 --fps 2
```

---

### Step 3 — Open the output in Wireshark (optional)

```bash
wireshark output.pcap
```

The output PCAP contains only the packets that were *not* blocked.

---

## Command-Line Arguments

| Argument | Description | Example |
|---|---|---|
| `input_pcap` | Input PCAP file to analyse | `test_dpi.pcap` |
| `output_pcap` | Output PCAP with filtered packets | `output.pcap` |
| `--block-app APP` | Block by app name (repeatable) | `--block-app YOUTUBE` |
| `--block-ip IP` | Block by source IP (repeatable) | `--block-ip 192.168.1.50` |
| `--block-domain KW` | Block by SNI keyword (repeatable) | `--block-domain tiktok` |
| `--multi-thread` | Use multi-threaded engine | flag |
| `--lbs N` | Number of Load Balancer threads (default: 2) | `--lbs 2` |
| `--fps N` | Fast Path threads per LB (default: 2) | `--fps 2` |

**Supported app names for `--block-app`:**
`YOUTUBE`, `FACEBOOK`, `INSTAGRAM`, `TIKTOK`, `TWITTER`, `NETFLIX`,
`WHATSAPP`, `TELEGRAM`, `GITHUB`, `REDDIT`, `AMAZON`, `GOOGLE`,
`MICROSOFT`, `APPLE`, `HTTP`, `HTTPS`, `DNS`

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           PROCESSING REPORT  (Single-Threaded DPI)           ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets : 54                                           ║
║ Total Bytes   : 9230                                         ║
║ TCP Packets   : 50                                           ║
║ UDP Packets   : 4                                            ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded     : 45                                           ║
║ Dropped       : 9                                            ║
╠══════════════════════════════════════════════════════════════╣
║ APPLICATION BREAKDOWN                                        ║
║   HTTPS           10   22.2%  ###########                    ║
║   GITHUB           5   11.1%  #####                          ║
║   FACEBOOK         4    8.9%  ####                           ║
╠══════════════════════════════════════════════════════════════╣
║ BLOCKED FLOWS                                                ║
║   YOUTUBE          8 packets  (BLOCKED)                      ║
╠══════════════════════════════════════════════════════════════╣
║ DETECTED DOMAINS / SNIs                                      ║
║   www.youtube.com  →  YOUTUBE                                ║
║   www.facebook.com  →  FACEBOOK                              ║
║   github.com  →  GITHUB                                      ║
╚══════════════════════════════════════════════════════════════╝
```

---

## How It Works — Key Concepts

### The Five-Tuple
Every TCP/UDP connection is uniquely identified by 5 values:

| Field | Example | Meaning |
|---|---|---|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it is going |
| Source Port | 54321 | Sender's app identifier |
| Destination Port | 443 | Service (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

All packets sharing the same five-tuple belong to the **same flow**.
Once a flow is blocked, all its subsequent packets are also dropped.

### SNI Extraction (the "deep" in DPI)
```
TLS Client Hello packet layout:
  Byte 0:     0x16 = Handshake
  Byte 5:     0x01 = Client Hello
  ...
  Extension type 0x0000 = SNI
    → "www.youtube.com"   ← extracted here!
```

### Flow-Based Blocking
```
Packet 1 (SYN)           → No SNI yet → FORWARD
Packet 2 (ACK)           → No SNI yet → FORWARD
Packet 3 (Client Hello)  → SNI: www.youtube.com → BLOCKED!
Packet 4 (Data)          → Flow already blocked → DROP
Packet 5 (Data)          → Flow already blocked → DROP
```

### Multi-Threaded Architecture
```
Reader → [LB-0] → [FP-0]  ─┐
       → [LB-1] → [FP-1]  ─┼→ Output Queue → Writer
                → [FP-2]  ─┘
```

- **Consistent hashing**: same five-tuple always → same FastPath thread
- **No locking on flow tables**: each FastPath owns its own private flow table
- **Thread-safe queues**: producer/consumer pattern with `threading.Event`

---

## Use Your Own PCAP

If you have Wireshark installed, capture real traffic and analyse it:

```bash
# Capture 100 packets on your network interface
tshark -c 100 -w my_capture.pcap

# Analyse with DPI engine
python main.py my_capture.pcap my_filtered.pcap --block-app YOUTUBE
```

---

## File-by-File Guide

| File | What it does |
|---|---|
| `pcap_reader.py` | Opens a `.pcap` file and reads packets one-by-one using `struct` |
| `pcap_writer.py` | Writes filtered packets to a new `.pcap` file |
| `packet_parser.py` | Parses raw bytes: Ethernet→IP→TCP/UDP, builds FiveTuple |
| `sni_extractor.py` | Navigates TLS Client Hello bytes to find the SNI hostname |
| `rule_manager.py` | Stores and checks IP/app/domain block rules |
| `types_.py` | `FiveTuple`, `Flow`, `AppType`, `ParsedPacket` dataclasses |
| `dpi_engine.py` | Main loop: read → parse → classify → block/forward → report |
| `dpi_mt.py` | Same logic with Reader + LoadBalancer + FastPath + Writer threads |
| `generate_test_pcap.py` | Builds test packets with real TLS Client Hello + SNI from scratch |
