# Jev-Guard: AI-Driven Layer-2 ARP Spoofing & DDoS Defense Laboratory

**Jev-Guard** is an isolated Layer-2 security testbed built on **Mininet**, **Open vSwitch (OVS)**, and **Python** that demonstrates real-time detection and active mitigation of **ARP Cache Poisoning (MITM)** and **ARP Request Flood (DDoS)** attacks.

Unlike traditional static ARP defenses that rely on manual endpoint configuration and fail against unpinned hosts or volumetric ARP floods, Jev-Guard analyzes 1-second Layer-2 telemetry windows (`EtherType 0x0806`), classifies threat vectors using the **`typesafe/jev-1.14` Decision Model API**, and enforces automated sub-second remediation across both endpoints and OpenFlow switches.

---

## Key Capabilities & Engineering Highlights

- **Multi-Vector ARP Spoofing Detection & Sub-500ms Remediation:**
  Detects forged `IP -> MAC` bindings across unsolicited ARP replies (`opcode=2`), unicast forged ARP requests (`opcode=1`), and broadcast Gratuitous ARP frames. Upon detection (`ARP_SPOOFING`), Jev-Guard executes a three-stage defense (`RESTORE_BINDINGS`) in **~100–200 ms**:
  1. **Endpoint Kernel Pinning:** Installs permanent neighbor entries (`nud permanent`) on honest hosts.
  2. **Wire-Level Cache Cure:** Transmits 5 corrective `is-at` (`opcode=2`) frames (unicast + broadcast) to immediately heal poisoned caches.
  3. **Switch-Level Port Containment:** Programs OpenFlow drop rules (`priority=200`) on Open vSwitch (`s1`) to block further spoofed ARP packets at the attacker's ingress port while preserving legitimate traffic.

- **Cryptographic SHA-256 Hash-Puzzle Defense Against ARP DDoS:**
  Distinguishes volumetric ARP request floods (`arp_pps > 20` or `request_to_reply_ratio > 20` with no binding conflict) from spoofing attacks (`ARP_DDOS_FLOOD` $\rightarrow$ `ENABLE_ARP_HASH_PUZZLE`). Drops unsolved flood packets at the switch and broadcasts a difficulty $k = 16$ birthday-paradox challenge:
  $$\left(\text{int}(H(x_1)) + \text{int}(H(x_2))\right) \bmod 2^{16} = S$$
  Honest clients solve the SHA-256 nonce pair $(x_1, x_2)$ in **~1 ms**, and the defender validates the proof in constant time (`hmac.compare_digest`) in **~0.09 ms** (`< 0.3 ms` SLA) before issuing an ARP reply.

- **Reproducible Packet-Level Forensics:**
  Every scenario is automated end-to-end and generates a dedicated, time-ordered `.pcap` capture (`pcaps/scene1.pcap` – `pcaps/scene6.pcap`) for verification in Wireshark.

---

## Network Topology

All six scenes execute inside an isolated two-switch, three-host Mininet LAN (`10.0.0.0/24`) with deterministic MAC addressing for clean packet inspection:

```text
Alice (10.0.0.1 / 00:00:00:00:00:01) ──┐
                                       ├── s1 (OVS Bridge) ═══ s2 (OVS Bridge) ─── Bob (10.0.0.3 / 00:00:00:00:00:03)
Eve   (10.0.0.2 / 00:00:00:00:00:02) ──┘
```

| Node | IPv4 Address | Hardware MAC | Switch Port | Role |
|---|---|---|---|---|
| **Alice** | `10.0.0.1/24` | `00:00:00:00:00:01` | `s1-eth1` | Honest Host A (Victim / Puzzle Solver) |
| **Eve** | `10.0.0.2/24` | `00:00:00:00:00:02` | `s1-eth2` | Adversary (MITM Spoofer / Flood Generator) |
| **Bob** | `10.0.0.3/24` | `00:00:00:00:00:03` | `s2-eth1` | Honest Host B (Victim / Puzzle Verifier) |
| **s1, s2** | — | — | Trunked | Open vSwitch bridges managed via `ovs-ofctl` |

---

## Six-Scene Experimental Matrix

| Scene | Script | Jev-Guard | Scenario Description | Decision Class / Action | Output Artifact |
|---|---|---|---|---|---|
| **Scene 1** | `scenes/scene1.py` | `OFF` | Baseline ARP `who-has` (`op=1`) and `is-at` (`op=2`) resolution between Alice and Bob, verified with direct ICMP echo (`ttl=64`). | `NORMAL_ARP` / `NO_ACTION` | `pcaps/scene1.pcap` |
| **Scene 2** | `scenes/scene2.py` | `OFF` | **Bidirectional MITM Spoof:** Eve sends unsolicited unicast `op=2` replies to both Alice and Bob, poisoning both caches and intercepting ICMP (`ttl=63`). | — | `pcaps/scene2.pcap` |
| **Scene 3** | `scenes/scene3.py` | `OFF` | **Asymmetric Single-Victim Spoof:** Eve sends a forged unicast `op=1` `who-has` to Alice claiming Bob's IP; only Alice's cache is poisoned while Bob retains true bindings. | — | `pcaps/scene3.pcap` |
| **Scene 4** | `scenes/scene4.py` | `OFF` | **Broadcast Gratuitous ARP Spoof:** Eve broadcasts a Gratuitous ARP (`psrc=pdst=10.0.0.3, hwsrc=Eve`), redirecting Alice's subsequent ICMP traffic to Eve. | — | `pcaps/scene4.pcap` |
| **Scene 5** | `scenes/scene5.py` | `ON` | **Active Spoof Remediation:** Re-runs Scenes 2, 3, and 4 with Jev-Guard active. Detects all three vectors, restores caches in `< 205 ms`, and blocks Eve's spoofed IPs at OVS `s1`. | `ARP_SPOOFING` $\rightarrow$ `RESTORE_BINDINGS` | `pcaps/scene5.pcap` |
| **Scene 6** | `scenes/scene6.py` | `ON` | **Hash-Puzzle DDoS Mitigation:** Eve floods 40 `op=1` requests/sec with no binding conflict. Jev-Guard drops unsolved floods and resolves Alice via a $k=16$ SHA-256 puzzle. | `ARP_DDOS_FLOOD` $\rightarrow$ `ENABLE_ARP_HASH_PUZZLE` | `pcaps/scene6.pcap` |

---

## Repository Structure

```text
.
├── lab-up.py                     # Core Mininet topology, raw packet engine, OVS flow controller & Jev-Guard client
├── README.md                     # Project overview, architecture, and execution guide
├── .env                          # Environment configuration (OPENROUTER_API_KEY, OPENROUTER_MODEL)
├── scenes/                       # Automated experiment runners
│   ├── scene1.py                 # Scene 1: Normal ARP baseline
│   ├── scene2.py                 # Scene 2: Unsolicited op=2 MITM spoofing
│   ├── scene3.py                 # Scene 3: Unicast op=1 single-victim spoofing
│   ├── scene4.py                 # Scene 4: Broadcast Gratuitous ARP traffic redirection
│   ├── scene5.py                 # Scene 5: Jev-Guard RESTORE_BINDINGS defense
│   └── scene6.py                 # Scene 6: Jev-Guard ENABLE_ARP_HASH_PUZZLE defense
├── pcaps/                        # Generated packet captures for Wireshark inspection
│   ├── scene1.pcap .. scene6.pcap
├── md/                           # Technical documentation & forensic guides
│   ├── DESIGN.md                 # System architecture and implementation design document
│   ├── WHAT-TO-LOOK-AT.md        # Packet-by-packet Wireshark & terminal verification guide
│   ├── BEFORE-AND-AFTER-JEV.md   # Quantitative evaluation of security improvements with Jev-Guard
│   └── six-scenes.md             # Formal laboratory specification and pass criteria
└── docs/                         # Background reports & slides
    ├── COMP4334_ARP_Lab_Report.pdf
    └── Upgrade-Plan-5min.pptx
```

---

## Prerequisites & Setup

### 1. System Requirements
- **OS:** Linux or Kali Linux (WSL2 supported) with root privileges (`sudo`) required for Linux network namespaces and Open vSwitch.
- **Dependencies:** `mininet`, `openvswitch-switch`, `python3-scapy`, `tcpdump`, and `wireshark` (optional, for GUI inspection).

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-scapy tcpdump
sudo service openvswitch-switch start
```

### 2. API Configuration (`.env`)
Scenes 5 and 6 query the `typesafe/jev-1.14` decision model via the OpenRouter Decisions API. Configure your `.env` file in the project root:

```ini
OPENROUTER_API_KEY=sk-or-v1-<your-key>
OPENROUTER_MODEL=typesafe/jev-1.14
```

---

## Running the Laboratory

Execute any scene from the project root directory:

```bash
sudo python3 scenes/scene1.py
sudo python3 scenes/scene2.py
sudo python3 scenes/scene3.py
sudo python3 scenes/scene4.py
sudo python3 scenes/scene5.py
sudo python3 scenes/scene6.py
```

Each script automatically:
1. Starts `openvswitch-switch` if not already running and resets any stale OpenFlow rules.
2. Provisions the virtual topology via `lab-up.py`.
3. Starts per-host `tcpdump` capture in `--immediate-mode`.
4. Executes the attack/defense workflow and runs built-in `assert` verifications against neighbor tables, repair latency (`< 500 ms`), and puzzle verification time (`< 0.3 ms`).
5. Writes the merged, deduplicated capture to `pcaps/sceneN.pcap` and tears down the virtual network cleanly.

To launch an interactive Mininet CLI session for manual experimentation:
```bash
sudo python3 lab-up.py
```

If a previous Mininet session was interrupted, clean up stale virtual interfaces with:
```bash
sudo mn -c
```

---

## Summary of Experimental Results

| Metric | Baseline / Without Jev-Guard (Scenes 2–4) | With Jev-Guard Active (Scenes 5–6) |
|---|---|---|
| **Spoof Vector Coverage** | Vulnerable to `op=2` replies, `op=1` requests, and broadcast GARP | **100% detected** (`confidence: 1.0` via `typesafe/jev-1.14`) |
| **Cache Recovery Latency** | Never recovers (traffic remains MITM'd at `ttl=63`) | **99 ms – 204 ms** (`< 500 ms` target SLA) |
| **Post-Mitigation Spoof Leakage** | Forged frames continue reaching victim NICs | **0 packets** (dropped at OVS `s1` ingress port) |
| **Unsolved Flood Amplification** | Responder processes and replies to every flood request | **0 replies** to 40-packet flood burst |
| **Hash-Puzzle Solve / Verify Time** | N/A | Client solve: **~0.7–1.2 ms** \| Defender verify: **~0.09–0.14 ms** (`< 0.3 ms` SLA) |

For a packet-by-packet walkthrough of `pcaps/scene1.pcap` – `pcaps/scene6.pcap`, see [`md/WHAT-TO-LOOK-AT.md`](md/WHAT-TO-LOOK-AT.md). For a detailed architectural comparison, see [`md/BEFORE-AND-AFTER-JEV.md`](md/BEFORE-AND-AFTER-JEV.md).
