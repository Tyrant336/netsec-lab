# Wireshark & Terminal Inspection Guide (`WHAT-TO-LOOK-AT.md`)

Use this guide when reviewing the terminal output and opening `scene1.pcap` – `scene6.pcap` in Wireshark.

## Ground-Truth Topology & Trusted Bindings

| Host | IPv4 | MAC Address | Switch Port | Role |
|---|---|---|---|---|
| **Alice** | `10.0.0.1` | `00:00:00:00:00:01` | `s1-eth1` | Honest Host A |
| **Eve** | `10.0.0.2` | `00:00:00:00:00:02` | `s1-eth2` | Attacker / Interferer |
| **Bob** | `10.0.0.3` | `00:00:00:00:00:03` | `s2-eth1` | Honest Host B |

**Recommended Wireshark Columns:**
- `No.`, `Time`, `Source` (Ethernet src), `Destination` (Ethernet dst), `Protocol`, `Info`

---

## Scene 1 — Normal ARP Request and Reply (`scene1.pcap`)
- **Jev State:** OFF
- **Wireshark Display Filter:** `arp` (or `arp || icmp` to also view the ping)
- **Packets to Look At (`scene1.pcap`, 6 packets):**
  - **Packet #1 (`Who-has`):** Ethernet `00:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff`, ARP `opcode=1` (request), Sender `10.0.0.1` / `00:00:00:00:00:01`, Target IP `10.0.0.3`.
  - **Packet #2 (`Is-at`):** Ethernet `00:00:00:00:00:03 -> 00:00:00:00:00:01`, ARP `opcode=2` (reply), Sender `10.0.0.3` / `00:00:00:00:00:03`, Target `10.0.0.1`.
  - **Packet #3 & #4:** Bob's symmetric `who-has 10.0.0.1` and Alice's `is-at` reply.
  - **Packet #5 & #6:** ICMP echo request (`00:00:00:00:00:01 -> 00:00:00:00:00:03`) and reply (`ttl=64`).
- **Terminal Check:** Both Alice and Bob list the true MACs (`00:00:00:00:00:03` and `00:00:00:00:00:01`). No corrective ARP or puzzle frames exist.

---

## Scene 2 — Basic ARP Spoof (`scene2.pcap`)
- **Jev State:** OFF
- **Wireshark Display Filter:** `arp || icmp`
- **Packets to Look At (`scene2.pcap`, 14 packets):**
  - **Packet #5 (Spoof to Alice):** Unsolicited `opcode=2` (`is-at`), Ethernet src `00:00:00:00:00:02` -> dst `00:00:00:00:00:01`, ARP Sender IP `10.0.0.3`, Sender MAC `00:00:00:00:00:02`.
  - **Packet #6 (Spoof to Bob):** Unsolicited `opcode=2` (`is-at`), Ethernet src `00:00:00:00:00:02` -> dst `00:00:00:00:00:03`, ARP Sender IP `10.0.0.1`, Sender MAC `00:00:00:00:00:02`.
  - **Packet #7 (Intercepted Ping):** Alice's ICMP echo request to `10.0.0.3` has **Ethernet destination `00:00:00:00:00:02` (Eve)** instead of Bob.
- **Terminal Check:** Both Alice's and Bob's neighbor caches show `00:00:00:00:00:02` (`REACHABLE`), and `ping` reports `ttl=63` (decremented by Eve's IP forwarding).

---

## Scene 3 — Forged Binding, One Victim (`scene3.pcap`)
- **Jev State:** OFF
- **Wireshark Display Filter:** `arp`
- **Packets to Look At (`scene3.pcap`, 6 packets):**
  - **Packet #5 (Forged `opcode=1` Claim to Alice only):** Ethernet `00:00:00:00:00:02 -> 00:00:00:00:00:01`, ARP `opcode=1` (`who-has 10.0.0.1`), **Sender IP `10.0.0.3`, Sender MAC `00:00:00:00:00:02`**.
  - Notice why this is distinct from Scene 2: it is a **unicast `opcode=1` request** with a forged source binding rather than an unsolicited `opcode=2` reply pair.
- **Terminal Check:**
  - **Alice's cache (victim):** `10.0.0.3 lladdr 00:00:00:00:00:02` (poisoned).
  - **Bob's cache (other honest host):** `10.0.0.1 lladdr 00:00:00:00:00:01` (untouched, still true MAC).

---

## Scene 4 — Forged Binding that Redirects Traffic (`scene4.pcap`)
- **Jev State:** OFF
- **Wireshark Display Filter:** `arp || icmp`
- **Packets to Look At (`scene4.pcap`, 10 packets):**
  - **Packet #5 (Broadcast Gratuitous ARP):** Ethernet `00:00:00:00:00:02 -> ff:ff:ff:ff:ff:ff`, ARP `opcode=2`, **Sender IP `10.0.0.3`, Target IP `10.0.0.3`, Sender MAC `00:00:00:00:00:02`**. (Distinct from both Scene 2's unicast pair and Scene 3's unicast `op=1`).
  - **Packet #6 (Redirected ICMP):** Alice's ICMP echo request (`10.0.0.1 -> 10.0.0.3`) has **Ethernet destination `00:00:00:00:00:02` (Eve)**.
- **Terminal Check:** Alice's neighbor cache maps `10.0.0.3` to `00:00:00:00:00:02` and traffic flows to Eve first.

---

## Scene 5 — Jev Prevents the Spoofs (`scene5.pcap`)
- **Jev State:** ON (`ARP_SPOOFING` -> `RESTORE_BINDINGS`)
- **Wireshark Display Filter:** `arp || icmp`
- **Packets to Look At (`scene5.pcap`, 35 packets):**
  - **Packets #5–#6 (Scene 2 claim) -> Packets #7–#18 (Jev 5x Corrective `is-at`):** Immediately after Eve's spoof, Jev emits 5 corrective `opcode=2` replies per conflicted IP (4 unicast to the victim + 1 broadcast to `ff:ff:ff:ff:ff:ff`) restoring `10.0.0.3 -> 00:00:00:00:00:03` and `10.0.0.1 -> 00:00:00:00:00:01`.
  - **Packet #12 (Scene 3 `op=1` claim) -> Packets #19–#23 (Jev 5x Corrective `is-at`):** Proves Jev catches `opcode=1` spoofing too.
  - **Packet #24 (Scene 4 broadcast Gratuitous claim) -> Packets #25–#29 (Jev 5x Corrective `is-at`):** Proves Jev catches broadcast gratuitous spoofing too.
  - **Packets #30–#31 (Protected ICMP):** Alice's ICMP echo to `10.0.0.3` uses **Ethernet destination `00:00:00:00:00:03` (Bob's true MAC)** with `ttl=64`.
  - **Step [7] OVS Switch Drop Proof:** Eve transmits another round of forged claims for `10.0.0.3` and `10.0.0.1`, and **0 forged frames appear on the victim capture** because `s1` drops ARP from Eve's port with `arp_spa=10.0.0.1` or `10.0.0.3`.
  - **Packets #32–#35 (Scene 1 Resolution Still Works):** Alice and Bob perform a fresh `who-has` / `is-at` exchange (`#32–#35`) after the switch drop rule is active.
- **Terminal Check:**
  - Every `RESTORE_BINDINGS` completes in `~100–205 ms` (well under the `500 ms` requirement).
  - Decision JSON logs `class: "ARP_SPOOFING"`, `action: "RESTORE_BINDINGS"`, plus window telemetry (`mac_ip_conflict: true`, `unsolicited_gratuitous`, `ether_arp_mac_mismatch_count`).

---

## Scene 6 — Hash Puzzle Prevents ARP DDoS (`scene6.pcap`)
- **Jev State:** ON (`ARP_DDOS_FLOOD` -> `ENABLE_ARP_HASH_PUZZLE`, `k = 16`)
- **Wireshark Display Filter:** `arp`
- **Packets to Look At (`scene6.pcap`, 43 packets):**
  - **Packets #1–#40 (Unsolved `who-has` Flood):** 40 rapid `opcode=1` `who-has 10.0.0.3 tell 10.0.0.2` frames from `00:00:00:00:00:02` (no binding conflict, since `10.0.0.2` is Eve's own IP). Notice there are **zero `is-at` replies** to these 40 frames.
  - **Packet #41 (Puzzle Challenge Broadcast):** `00:00:00:00:00:03 -> ff:ff:ff:ff:ff:ff`, ARP `opcode=1`. Click the frame in Wireshark and expand the trailer/padding bytes to see the JSON challenge:
    `{"type": "JEV_ARP_PUZZLE_CHALLENGE", "k": 16, "seed_hash": "...", "S": ...}`
  - **Packet #42 (Honest Solved Request from Alice):** `00:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff`, ARP `opcode=1` `who-has 10.0.0.3 tell 10.0.0.1` carrying the solved SHA-256 nonce pair:
    `{"type": "JEV_ARP_PUZZLE_SOLUTION", "k": 16, "seed_hash": "...", "x1": "...", "x2": "..."}`
  - **Packet #43 (Single Verified `is-at` Reply):** `00:00:00:00:00:03 -> 00:00:00:00:00:01`, ARP `opcode=2` (`10.0.0.3 is at 00:00:00:00:00:03`) sent **only** after the valid `(x1, x2)` proof.
- **Terminal Check:**
  - Jev classifies the burst as `ARP_DDOS_FLOOD` (`arp_pps: 40.0`, `request_to_reply_ratio: 40.0`, `mac_ip_conflict: false`).
  - Defender SHA-256 constant-time verification runs in `~0.09 ms` (well under the `0.3 ms` requirement).
  - Alice caches `10.0.0.3 -> 00:00:00:00:00:03 REACHABLE`.
