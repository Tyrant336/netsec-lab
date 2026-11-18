# Jev-Guard 6-Scene Lab — Design Document

## 1. Architecture Overview

Following the existing architecture in `COMP4334_ARP_Lab_Report.pdf`, **all shared topology, packet crafting, capture, and Jev-Guard logic lives in `lab-up.py`**. Each scene script (`scene1.py` – `scene6.py`) is a short orchestration script that imports `lab-up.py`, runs its scenario, prints verification output, and writes `sceneN.pcap`.

```text
Alice (10.0.0.1 / 00:00:00:00:00:01) ──┐
                                       ├── s1 (OVS) ═══ s2 (OVS) ─── Bob (10.0.0.3 / 00:00:00:00:00:03)
Eve   (10.0.0.2 / 00:00:00:00:00:02) ──┘
```

### Trusted Ground-Truth Table (`TRUSTED_BINDINGS` in `lab-up.py`)
```json
{
  "10.0.0.1": "00:00:00:00:00:01",
  "10.0.0.2": "00:00:00:00:00:02",
  "10.0.0.3": "00:00:00:00:00:03"
}
```

---

## 2. Audit of Current Files vs. `six-scenes.md`

| File | Current State | Matches `six-scenes.md`? | Action Needed |
|---|---|---|---|
| `lab-up.py` | Has basic `get_mac`, `spoof`, `restore`, `pin`, `forward`, `ping`, `pcap_start/stop` | Partial | Add Scene 3/4 spoof variants, Jev 1-second ARP window analyzer + OpenRouter `typesafe/jev-1.14` classifier (`.env`), `RESTORE_BINDINGS` (pin + 5x corrective `is-at` + OVS port filter), and Scene 6 SHA-256 hash puzzle (`k=16`). |
| `scene1.py` | Normal ARP request/reply + ping | Yes | Keep as-is (ensure both neighbor tables show true MACs). |
| `scene2.py` | Eve sends unsolicited `op=2` replies to Alice & Bob + ping redirects via Eve | Yes | Keep as-is. |
| `scene3.py` | **MISMATCH**: Currently implements static ARP `pin()` defense from the old 3-scene report | **No** | Replace with **Scene 3: Forged binding, one victim** (Jev off, no pin; only Alice is poisoned via a distinct forged ARP claim while Bob keeps true MACs). |
| `scene4.py` | Missing | **No** | Create **Scene 4: Forged binding that redirects traffic** (Jev off; gratuitous/broadcast forged claim distinct from Scenes 2 & 3, followed by ICMP echo delivered to Eve's MAC). |
| `scene5.py` | Missing | **No** | Create **Scene 5: Jev prevents the spoofs** (Jev on; runs Scene 2, 3, and 4 claims, triggers `ARP_SPOOFING` → `RESTORE_BINDINGS`, repairs caches <500 ms, blocks Eve's forged IPs at OVS `s1`, verifies ICMP uses true MAC and Scene 1 ARP still works). |
| `scene6.py` | Missing | **No** | Create **Scene 6: Hash puzzle prevents ARP DDoS** (Jev on; high-rate `op=1` who-has flood with no IP-MAC conflict triggers `ARP_DDOS_FLOOD` → `ENABLE_ARP_HASH_PUZZLE` with `k=16`, drops unsolved requests, broadcasts challenge, Alice solves `(x1, x2)` and resolves Bob). |

---

## 3. Detailed Scene & Method Design (`lab-up.py`)

### 3.1 Distinct Spoof Forms (Scenes 2, 3, 4)

Why three forms? Scene 5 must prove that Jev keys off **trusted-binding mismatch (`psrc` → `hwsrc`) across both `op=1` and `op=2`**, rather than filtering only Scene 2's unsolicited unicast `op=2`.

| Scene | Method in `lab-up.py` | Wire Format | Effect on Caches |
|---|---|---|---|
| **Scene 2** | `lab.spoof(eve, target_ip, spoofed_ip)` | Unicast `op=2` (`is-at`) to Alice (`psrc=10.0.0.3, hwsrc=Eve`) AND to Bob (`psrc=10.0.0.1, hwsrc=Eve`). | **Both** Alice and Bob map each other to `00:00:00:00:00:02`. ICMP goes to Eve. |
| **Scene 3** | `lab.spoof_one_victim(eve, victim_ip, victim_mac, claimed_ip)` | Unicast `op=1` (`who-has`) from Eve to Alice only: `Ether(src=Eve, dst=Alice) / ARP(op=1, psrc=10.0.0.3, hwsrc=Eve, pdst=10.0.0.1)`. | Linux updates Alice's cache for `10.0.0.3` → `00:00:00:00:00:02` because `pdst` is Alice. **Bob never receives it** and keeps `10.0.0.1` → `00:00:00:00:00:01`. |
| **Scene 4** | `lab.spoof_gratuitous(eve, claimed_ip)` | Broadcast Gratuitous ARP (`Ether(src=Eve, dst=ff:ff:ff:ff:ff:ff) / ARP(op=1, psrc=10.0.0.3, hwsrc=Eve, pdst=10.0.0.3, hwdst=ff:ff:ff:ff:ff:ff)`). | Updates Alice's existing neighbor entry for `10.0.0.3` → `00:00:00:00:00:02`. Subsequent `ping` from Alice to `10.0.0.3` has Ethernet dst `00:00:00:00:00:02`. |

---

### 3.2 Jev-Guard Engine (Scenes 5 & 6)

#### A. 1-Second ARP Window Feature Extraction (`lab.jev_window(packets, duration=1.0)`)
Filters `EtherType == 0x0806` (ARP) and computes the window telemetry JSON required by `six-scenes.md`:
```json
{
  "window_sec": 1.0,
  "arp_pps": 4.0,
  "request_count": 2,
  "reply_count": 2,
  "request_to_reply_ratio": 1.0,
  "mac_ip_conflict": true,
  "unsolicited_gratuitous": 1,
  "ether_arp_mac_mismatch_count": 0,
  "conflicts": [
    {"src_mac": "00:00:00:00:00:02", "claimed_ip": "10.0.0.3", "expected_mac": "00:00:00:00:00:03", "op": 1}
  ]
}
```
- `mac_ip_conflict`: `True` if any ARP packet (`op=1` or `op=2`) has `psrc in TRUSTED_BINDINGS` and `hwsrc != TRUSTED_BINDINGS[psrc]`.
- `unsolicited_gratuitous`: Count of ARP packets where `psrc == pdst` or `op == 2` without a matching prior `who-has`.
- `ether_arp_mac_mismatch_count`: Count of frames where `Ether.src != ARP.hwsrc`.

#### B. Jev Decision Classifier (`lab.jev_decide(window, use_api=False)`)
Returns the standardized decision JSON:
```json
{
  "class": "ARP_SPOOFING | ARP_DDOS_FLOOD | NORMAL_ARP",
  "confidence": 0.99,
  "src_mac": "00:00:00:00:00:02",
  "claimed_ip": "10.0.0.3",
  "action": "RESTORE_BINDINGS | ENABLE_ARP_HASH_PUZZLE | NO_ACTION"
}
```
- **Rule priority** (per `six-scenes.md`):
  1. If `mac_ip_conflict` is `True` → `ARP_SPOOFING` / `RESTORE_BINDINGS` (even if rate is high).
  2. Else if `arp_pps > 20` or `request_to_reply_ratio > 20` → `ARP_DDOS_FLOOD` / `ENABLE_ARP_HASH_PUZZLE` (`k=16`).
  3. Else → `NORMAL_ARP` / `NO_ACTION`.
- **OpenRouter Decisions API (`https://openrouter.ai/api/alpha/decisions`)**: Reads `OPENROUTER_API_KEY` and `OPENROUTER_MODEL=typesafe/jev-1.14` from `.env` and classifies the 1-second ARP window.

---

### 3.3 Scene 5 Action: `lab.restore_bindings(net, conflict_info)`

When `ARP_SPOOFING` triggers, `lab.restore_bindings()` executes all three required steps in `<500 ms`:

1. **Pin true neighbor entries (`nud permanent`)**:
   - On `Alice`: pins `10.0.0.3 -> 00:00:00:00:00:03` and `10.0.0.2 -> 00:00:00:00:00:02`.
   - On `Bob`: pins `10.0.0.1 -> 00:00:00:00:00:01` and `10.0.0.2 -> 00:00:00:00:00:02`.
2. **Send 5x Corrective `is-at` (`op=2`)**:
   - For each conflicted `claimed_ip`, sends 5 ARP `op=2` frames with `psrc=claimed_ip, hwsrc=TRUSTED_BINDINGS[claimed_ip]` (4 unicast to the victim(s) + 1 broadcast to `ff:ff:ff:ff:ff:ff`, totaling 5 copies on the wire).
3. **Install OVS Switch Drop Rules on `s1`**:
   - Detects Eve's switch port (`s1-eth2`) and installs OpenFlow rules via `ovs-ofctl`:
     ```bash
     ovs-ofctl add-flow s1 "priority=200,arp,in_port=2,arp_spa=10.0.0.1,actions=drop"
     ovs-ofctl add-flow s1 "priority=200,arp,in_port=2,arp_spa=10.0.0.3,actions=drop"
     ```
   - Eve's legitimate ARP (`arp_spa=10.0.0.2, arp_sha=00:00:00:00:00:02`) and Alice↔Bob ARP continue to pass normally.

---

### 3.4 Scene 6 Action: `lab.enable_arp_hash_puzzle()` & Solve Flow

1. **Flood Input**:
   - Eve sends a burst of >30 ARP `who-has` (`op=1`) frames within 1 second using her own valid binding (`psrc=10.0.0.2, hwsrc=00:00:00:00:00:02`, targeting `10.0.0.3`).
   - Window shows `mac_ip_conflict = False`, `arp_pps > 20`, `request_to_reply_ratio > 20` → Jev returns `ARP_DDOS_FLOOD` / `ENABLE_ARP_HASH_PUZZLE`.
2. **Switch Rate/Puzzle Gate**:
   - OVS drops standard unsolved `who-has` frames from flooding Bob so unsolved requests receive **no `is-at`**.
3. **Challenge Broadcast**:
   - Defender broadcasts an ARP challenge packet (`op=1` or custom ARP trailer to `ff:ff:ff:ff:ff:ff`) containing JSON payload:
     `{"type": "JEV_PUZZLE", "k": 16, "seed_hash": H(s), "S": S}` where `S in [0, 2^16 - 1]`.
4. **Client Solver (`Alice`)**:
   - Finds nonces `(x1, x2)` such that `(int(SHA256(x1), 16) + int(SHA256(x2), 16)) % (1 << 16) == S` (using a small dict of random hashes, solves in ~256 SHA-256 evaluations ≈ `<1 ms`).
   - Sends one ARP `who-has` for `10.0.0.3` carrying `Raw(load=json.dumps({"x1": x1, "x2": x2}))`.
5. **Constant-Time Defender Verification (<0.3 ms)**:
   - Defender computes `lhs = (int(sha256(x1), 16) + int(sha256(x2), 16)) % (1 << k)` and checks `hmac.compare_digest(f"{lhs:08x}", f"{S:08x}")`.
   - Timing is measured with `time.perf_counter()` (typically `~0.01 ms`, well under the `0.3 ms` limit).
   - Upon valid proof, defender sends the unicast `is-at` (`10.0.0.3 is at 00:00:00:00:00:03`) to Alice, and Alice updates her neighbor cache.

---

## 4. Planned File Changes

1. **`lab-up.py`**: Expand with all helpers for Scenes 1–6 (including `pcap_start` filter adjustment so ARP + ICMP are captured cleanly, and host-side CLI actions for `spoof_one`, `spoof_garp`, `cure`, `flood`, `puzzle_challenge`, `puzzle_request`, `puzzle_reply`).
2. **`scene1.py`**: Minor cleanup if needed so both Alice and Bob kernel neighbor tables are populated and verified.
3. **`scene2.py`**: Keep existing flow + clear pass/fail check.
4. **`scene3.py`**: Rewrite to match **Scene 3 (Forged binding, one victim)**.
5. **`scene4.py`**: New script for **Scene 4 (Forged binding that redirects traffic)**.
6. **`scene5.py`**: New script for **Scene 5 (Jev `RESTORE_BINDINGS` across Scenes 2, 3, 4)**.
7. **`scene6.py`**: New script for **Scene 6 (Jev `ENABLE_ARP_HASH_PUZZLE` DDoS defense)**.
