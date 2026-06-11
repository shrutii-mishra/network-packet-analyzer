# Network Packet Analyzer — Deep Packet Inspection (DPI) Engine

A high-performance **Deep Packet Inspection engine** built in C++ that captures, parses, classifies, and filters network traffic in real time. Supports both single-threaded and multi-threaded pipeline architectures.

---

## What is DPI?

Deep Packet Inspection (DPI) goes beyond traditional firewalls — instead of only checking packet headers (source/destination IP), it inspects the **payload** of each packet to identify the application layer protocol and content.

**Real-world use cases:**
- ISPs throttling BitTorrent or streaming traffic
- Enterprises blocking social media on office networks
- Security systems detecting malware or intrusion attempts
- Parental controls filtering inappropriate content

---

## Features

- **Multi-layer protocol parsing** — Ethernet → IP → TCP/UDP header extraction
- **TLS SNI extraction** — identifies destination domains from HTTPS traffic even without decrypting it
- **HTTP Host header parsing** — classifies plain HTTP traffic by domain
- **5-tuple flow tracking** — statefully tracks connections (src IP, dst IP, src port, dst port, protocol)
- **Application classification** — identifies YouTube, Facebook, Google, GitHub, DNS, and more
- **Rule-based packet blocking** — block by IP address, application type, or domain substring
- **Multi-threaded pipeline** — Load Balancer + Fast Path worker threads with consistent hashing
- **Thread-safe queues** — producer-consumer architecture using mutex + condition variables
- **PCAP file support** — reads Wireshark captures as input, writes filtered output as PCAP

---

## Architecture

```
                      ┌─────────────────┐
                      │  Reader Thread  │
                      │  (reads .pcap)  │
                      └────────┬────────┘
                               │
                ┌──────────────┴──────────────┐
                │      hash(5-tuple) % N       │
                ▼                             ▼
      ┌──────────────────┐         ┌──────────────────┐
      │  Load Balancer 0 │         │  Load Balancer 1 │
      └────────┬─────────┘         └────────┬─────────┘
               │                            │
        ┌──────┴──────┐              ┌──────┴──────┐
        ▼             ▼              ▼             ▼
  ┌──────────┐ ┌──────────┐  ┌──────────┐ ┌──────────┐
  │Fast Path │ │Fast Path │  │Fast Path │ │Fast Path │
  │  Thread  │ │  Thread  │  │  Thread  │ │  Thread  │
  └─────┬────┘ └─────┬────┘  └─────┬────┘ └─────┬────┘
        └────────────┴──────────────┴────────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │    Output Writer      │
                 │  (writes filtered     │
                 │      .pcap)           │
                 └───────────────────────┘
```

**Why consistent hashing?**
All packets belonging to the same TCP connection are always routed to the same Fast Path thread, ensuring correct stateful flow tracking.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | C++17 |
| Concurrency | POSIX threads (`std::thread`, `std::mutex`, `std::condition_variable`) |
| Packet capture | Raw PCAP file parsing (no libpcap dependency) |
| Build system | CMake |
| Test data | Python (`generate_test_pcap.py`) |

---

## Project Structure

```
network-packet-analyzer/
├── include/
│   ├── types.h                # FiveTuple, AppType, Flow structs
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Ethernet/IP/TCP/UDP parsing
│   ├── sni_extractor.h        # TLS SNI + HTTP Host extraction
│   ├── connection_tracker.h   # Flow state management
│   ├── rule_manager.h         # Blocking rules engine
│   ├── load_balancer.h        # LB thread (multi-threaded)
│   ├── fast_path.h            # FP thread (multi-threaded)
│   └── thread_safe_queue.h    # Thread-safe producer-consumer queue
│
├── src/
│   ├── main_working.cpp       # Single-threaded version
│   ├── dpi_mt.cpp             # Multi-threaded version
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   └── types.cpp
│
├── generate_test_pcap.py      # Generates sample .pcap test data
├── test_dpi.pcap              # Sample network capture
└── CMakeLists.txt
```

---

## Build & Run

### Prerequisites
- C++17 compiler (`g++` or `clang++`)
- CMake 3.10+
- Linux / macOS (or WSL on Windows)

### Build

**Single-threaded version:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Multi-threaded version:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Run

**Basic usage:**
```bash
./dpi_engine input.pcap output.pcap
```

**With blocking rules:**
```bash
./dpi_engine input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure thread count:**
```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
```

### Generate test data
```bash
python3 generate_test_pcap.py
./dpi_engine test_dpi.pcap output.pcap
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           DPI ENGINE v2.0 (Multi-threaded)                   ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:        77     Forwarded:      69              ║
║ TCP Packets:          73     Dropped:         8              ║
╠══════════════════════════════════════════════════════════════╣
║              APPLICATION BREAKDOWN                           ║
║  HTTPS          39   50.6%  ##########                       ║
║  YouTube         4    5.2%  # (BLOCKED)                      ║
║  Facebook        3    3.9%                                   ║
║  DNS             4    5.2%  #                                ║
╚══════════════════════════════════════════════════════════════╝

[Detected SNIs]
  www.youtube.com  → YouTube  (BLOCKED)
  www.facebook.com → Facebook
  www.google.com   → Google
  github.com       → GitHub
```

---

## How SNI Extraction Works

Even though HTTPS encrypts the payload, the **TLS Client Hello** packet — sent before encryption begins — contains the destination domain name in plaintext as the **Server Name Indication (SNI)** extension.

```
TLS Client Hello:
└── Extensions:
    └── SNI Extension (type 0x0000):
        └── Server Name: "www.youtube.com"  ← extracted here
```

This is the core of DPI: identifying application traffic without decrypting it.

---

## Blocking Logic

Packets are dropped at the **flow level**, not individually:

```
Packet 1 (SYN)          → flow unknown     → FORWARD
Packet 2 (Client Hello) → SNI: youtube.com → BLOCK flow
Packet 3, 4, 5...       → flow is blocked  → DROP all
```

Rules supported:
- Block by **source IP**
- Block by **application type** (YouTube, TikTok, etc.)
- Block by **domain substring** (e.g. "facebook" matches all Facebook subdomains)

---

## License

MIT — free to use, modify, and distribute.
