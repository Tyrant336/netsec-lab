# Before Jev vs. After Jev — Major Improvements (`BEFORE-AND-AFTER-JEV.md`)

## Executive Summary

Before Jev-Guard (Scenes 1–4 and the original 3-scene static-pin lab), the network either had **zero protection** against ARP cache poisoning and ARP request floods, or relied on **manual static neighbor pins** (`ip neigh replace ... nud permanent` in the old Scene 3) that only covered a single pre-configured pair, did not clean up wire traffic, and provided no defense against ARP DDoS floods.

With **Jev-Guard** enabled (Scenes 5–6), the lab transitions from passive/manual endpoint configuration to **automated, sub-second, multi-layer detection and active mitigation** across both spoofing (`RESTORE_BINDINGS`) and flooding (`ENABLE_ARP_HASH_PUZZLE`).

---

## Side-by-Side Comparison: Before Jev vs. After Jev

| Dimension | Before Jev (Scenes 2, 3, 4 & Old Static Lab) | After Jev (Scenes 5 & 6) | What Is Majorly Improved |
|---|---|---|---|
| **1. Detection Mechanism** | **None.** Hosts blindly accept unsolicited `op=2` replies, forged `op=1` requests, and broadcast Gratuitous ARP (`arp_accept=1`). | **1-Second ARP Window Telemetry + Classifier.** Inspects `EtherType 0x0806` for trusted-table mismatches (`mac_ip_conflict`), `unsolicited_gratuitous`, `ether_arp_mac_mismatch_count`, `arp_pps`, and `request_to_reply_ratio`. | Catches **all ARP spoof variants** (`op=1`, `op=2`, unicast, broadcast) by keying off ground-truth `IP -> MAC` bindings rather than a single packet format. |
| **2. Multi-Vector Spoof Coverage** | Old Scene 3 only demonstrated manual static pinning against Scene 2's unsolicited unicast `op=2` pair. | **Unified `RESTORE_BINDINGS` handles Scenes 2, 3, and 4.** Whether Eve poisons both hosts (`op=2`), one victim (`op=1` unicast), or broadcasts Gratuitous ARP, the same conflict trigger fires. | Eliminates protocol blind spots: attackers cannot bypass detection by switching from `is-at` replies (`op=2`) to forged `who-has` requests (`op=1`) or broadcast GARP. |
| **3. Active Cache Recovery Time** | **Infinite (stays poisoned).** Once Alice or Bob caches `00:00:00:00:00:02`, ICMP traffic (`ttl=63`) is silently MITM'd by Eve indefinitely. | **`~100–205 ms` automated cure (`< 500 ms` SLA).** Jev pins `nud permanent` entries on honest hosts AND transmits 5 corrective `is-at` frames (`4 unicast + 1 broadcast`). | Victim neighbor caches recover in under **0.2 seconds** without human intervention, and ICMP immediately returns to the direct path (`00:00:00:00:00:03`, `ttl=64`). |
| **4. Switch-Level Isolation (Containment)** | **No switch enforcement.** Even with static ARP pins on endpoints, Eve's forged frames continue flooding the LAN and reaching every host's NIC. | **Automated Open vSwitch Port Filtering.** Jev installs `priority=200` OVS rules on `s1` (`in_port=s1-eth2, arp_spa=10.0.0.1/10.0.0.3, actions=drop`). | **Stops the attack at the ingress switch port.** Later spoofs from Eve never even reach Alice's or Bob's network interfaces (`0` leaked packets), while Eve's own IP (`10.0.0.2`) and Alice↔Bob ARP still work. |
| **5. ARP DDoS / Request Flood Defense** | **Vulnerable to exhaustion.** A flood of `who-has` requests with valid source bindings bypasses static ARP checks and forces the target to process and reply to every frame. | **Cryptographic Hash Puzzle (`ENABLE_ARP_HASH_PUZZLE`, `k=16`).** When `arp_pps > 20` or `request_to_reply_ratio > 20` (with `mac_ip_conflict=False`), unsolved `who-has` frames are dropped. | **100% of unsolved flood packets get 0 replies**, while an honest host (Alice) solves `(int(H(x1)) + int(H(x2))) mod 2^16 = S` in `~1 ms` and Defender verifies it in constant time (`~0.09 ms < 0.3 ms`). |

---

## Measured Evidence from the Lab Runs

### 1. Spoofing & MITM (Scenes 2–4 vs. Scene 5)
- **Before Jev (Scenes 2, 3, 4):**
  - **Scene 2:** Alice and Bob both map each other to Eve (`00:00:00:00:00:02`). Alice's ICMP echo goes to `00:00:00:00:00:02` (`ttl=63`).
  - **Scene 3:** Eve's unicast `op=1` claim poisons Alice (`10.0.0.3 -> 00:00:00:00:00:02`) without touching Bob.
  - **Scene 4:** Eve's broadcast Gratuitous ARP poisons Alice (`10.0.0.3 -> 00:00:00:00:00:02`) and redirects Alice's ICMP echo to Eve.
- **After Jev (Scene 5):**
  - Jev detects all three attacks with `confidence: 0.99` (`class: "ARP_SPOOFING"`, `action: "RESTORE_BINDINGS"`).
  - Repair times measured: **204.56 ms** (Scene 2 claim), **99.16 ms** (Scene 3 claim), **166.90 ms** (Scene 4 claim) — all well below the **500 ms** requirement.
  - Post-repair ICMP echo goes directly `00:00:00:00:00:01 -> 00:00:00:00:00:03` with `ttl=64`.
  - Follow-up spoof burst from Eve after OVS rule installation: **0 packets** reached Alice or Bob.

### 2. High-Rate ARP Flood (Scene 6)
- **Why Scene 5's rule alone isn't enough:** In Scene 6, Eve floods `who-has 10.0.0.3` using her **own legitimate binding** (`10.0.0.2 / 00:00:00:00:00:02`). Because there is no IP-MAC conflict (`mac_ip_conflict: false`), a simple spoofing filter lets the flood through.
- **How Jev's Hash Puzzle solves it:**
  - Jev measures `arp_pps: 40.0` and `request_to_reply_ratio: 40.0` (vs. `< 20` in Scene 1) and classifies the window as `ARP_DDOS_FLOOD` -> `ENABLE_ARP_HASH_PUZZLE` (`k=16`).
  - All **40 unsolved flood frames** receive **0 `is-at` replies**.
  - Alice solves the `k=16` SHA-256 birthday pair `(x1, x2)` in **1.20 ms**, attaches it to a single `who-has` frame, and Bob's constant-time verifier (`hmac.compare_digest`) validates the proof in **0.0943 ms** (`< 0.3 ms` requirement) before sending the single legitimate `is-at` reply (`00:00:00:00:00:03`).
