# Mininet ARP Lab Handbook

A simple Layer-2 Mininet lab with 3 hosts (`Alice`, `Eve`, `Bob`) and 2 switches (`s1`, `s2`) to test normal ARP, ARP spoofing, and static ARP defense.

## Topology

```text
Alice (10.0.0.1) --- s1 === s2 --- Bob (10.0.0.3)
                     |
                    Eve (10.0.0.2)
```

| Host | IP Address | MAC Address | Switch |
|---|---|---|---|
| **Alice** | `10.0.0.1/24` | `00:00:00:00:00:01` | `s1` |
| **Eve** | `10.0.0.2/24` | `00:00:00:00:00:02` | `s1` |
| **Bob** | `10.0.0.3/24` | `00:00:00:00:00:03` | `s2` |

---

## Constraints & Requirements

1. **Linux / Kali Only**: Must be run inside Linux (or Kali WSL) because Mininet uses Linux network namespaces and Open vSwitch. It will **not** run directly on Windows PowerShell.
2. **Root Privileges (`sudo`)**: Creating virtual switches, hosts, and capturing packets requires `root`.
3. **Required Packages**:
   - `mininet`
   - `openvswitch-switch`
   - `python3-scapy`
   - `tcpdump`
   - `wireshark` (optional, for viewing `.pcap` files)

   Install on Kali / Ubuntu if missing:
   ```bash
   sudo apt update
   sudo apt install -y mininet openvswitch-switch python3-scapy tcpdump
   sudo service openvswitch-switch start
   ```

---

## Files in This Folder

| File | Description |
|---|---|
| `lab-up.py` | Builds the Mininet topology and provides helper functions (`get_mac`, `spoof`, `restore`, `pin`, `forward`, `ping`, `flush_arp`, `dump_arp`, `pcap_start`, `pcap_stop`). |
| `scene1.py` | **Normal ARP**: Alice and Bob learn each other's MAC addresses and ping. Saves `scene1.pcap`. |
| `scene2.py` | **Eve Interferes**: Eve spoofs ARP caches on Alice and Bob and forwards their ping traffic. Saves `scene2.pcap`. |
| `scene3.py` | **Static ARP Defense**: Alice and Bob pin (`PERMANENT`) each other's real MACs so Eve's spoof is ignored. Saves `scene3.pcap`. |

---

## How to Run

Open your Kali terminal inside this folder and run:

### Run the 3 Automated Scenes
```bash
sudo python3 scene1.py
sudo python3 scene2.py
sudo python3 scene3.py
```

### Run Interactive Mininet CLI (Optional)
If you want to manually type commands on the hosts:
```bash
sudo python3 lab-up.py
```
Inside `mininet>`, you can run commands like `Alice ping -c 2 Bob` or `exit` to close.

### Clean Up If a Run Crashes
If Mininet exits abnormally and leaves old switches behind:
```bash
sudo mn -c
```

---

## How to Test & Verify

### 1. Check Terminal Output
- **Scene 1**:
  - Alice learns Bob is at `00:00:00:00:00:03`.
  - Ping succeeds with `ttl=64`.
- **Scene 2**:
  - After Eve's spoof, both Alice and Bob list `00:00:00:00:00:02` (Eve's MAC) in their ARP caches.
  - Ping still succeeds, but with `ttl=63` (showing packets went through Eve).
- **Scene 3**:
  - Alice and Bob pin the real MACs (`PERMANENT`).
  - Even after Eve spoofs again, the ARP tables stay at `00:00:00:00:00:03` and `00:00:00:00:00:01` (`PERMANENT`), and ping has `ttl=64`.

### 2. Inspect Packet Captures in Wireshark
Each scene generates a `.pcap` file (`scene1.pcap`, `scene2.pcap`, `scene3.pcap`).

1. Open any capture in Wireshark:
   ```bash
   wireshark scene1.pcap
   ```
2. Set the Wireshark display filter to:
   ```text
   arp || icmp
   ```
3. Compare Ethernet MAC addresses on the ICMP ping packets:
   - **`scene1.pcap`**: ICMP goes directly from `00:00:00:00:00:01` (Alice) to `00:00:00:00:00:03` (Bob).
   - **`scene2.pcap`**: Unsolicited ARP replies (`is-at`) come from `00:00:00:00:00:02` (Eve), and ICMP frames go to `00:00:00:00:00:02` first.
   - **`scene3.pcap`**: Eve's fake ARP replies are visible on the wire, but Alice's ICMP frames still go directly to `00:00:00:00:00:03` (Bob).
