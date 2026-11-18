# Jev-Guard — Six Scene Requirements

Layer-2 lab on the existing Mininet topology. All six scenes run in this virtual network and are shown in Wireshark.

| Host | IP | MAC | Switch |
|---|---|---|---|
| Alice | `10.0.0.1` | `00:00:00:00:00:01` | s1 |
| Eve | `10.0.0.2` | `00:00:00:00:00:02` | s1 |
| Bob | `10.0.0.3` | `00:00:00:00:00:03` | s2 |

Trusted bindings (ground truth for Jev):

```json
{
  "10.0.0.1": "00:00:00:00:00:01",
  "10.0.0.2": "00:00:00:00:00:02",
  "10.0.0.3": "00:00:00:00:00:03"
}
```

Each scene writes its own pcap. Display filter: `arp`. Scene 4 also uses `icmp`.

Jev is off for Scenes 1–4. Those scenes only show the traffic. Jev runs in Scene 5 (spoof repair) and Scene 6 (hash puzzle). When it is on, it reads one-second ARP windows (EtherType `0x0806` only) and returns one class:

| Class | When | Action |
|---|---|---|
| `NORMAL_ARP` | Request/reply match the trusted table, low rate | `NO_ACTION` |
| `ARP_SPOOFING` | A claimed IP→MAC pair disagrees with the trusted table | `RESTORE_BINDINGS` |
| `ARP_DDOS_FLOOD` | High ARP request rate, or a very high request-to-reply ratio, with no binding conflict | `ENABLE_ARP_HASH_PUZZLE` |

The spoofing decision keys off the trusted binding. Opcode, gratuitous form, and whether Ethernet source matches ARP `hwsrc` are recorded in the window, and they are not the only trigger.

---

## Scene 1 — Normal ARP request and reply

Alice resolves Bob. Bob resolves Alice. One ping confirms the path. Jev is not running.

**Packets to show:**

1. Who-has. Ethernet destination `ff:ff:ff:ff:ff:ff`. ARP opcode `1`. Sender `10.0.0.1` / `00:00:00:00:00:01`. Target IP `10.0.0.3`.
2. Is-at. Ethernet source `00:00:00:00:00:03`, destination `00:00:00:00:00:01`. ARP opcode `2`. Sender `10.0.0.3` / `00:00:00:00:00:03`. Target Alice.

**Pass:** Both neighbor tables show the true MAC. Ping succeeds. No corrective ARP and no puzzle frame in the pcap.

---

## Scene 2 — Basic ARP spoof

The spoof already implemented: Eve sends unsolicited is-at replies.

- To Alice: Bob’s IP `10.0.0.3` is at Eve’s MAC `00:00:00:00:00:02`.
- To Bob: Alice’s IP `10.0.0.1` is at Eve’s MAC `00:00:00:00:00:02`.

No Jev action in this scene. This is the attack by itself, before the defense in Scene 5.

**Why it is the easy case:** The lie is an unsolicited opcode `2`, and the claimed IP belongs to the other host. A permanent neighbor entry for that one pair stops this exact lie. Scene 2 exists to show the easy case, not to apply that pin.

**Packets to show:**

1. Opcode `2`, Ethernet source `00:00:00:00:00:02`, ARP sender IP `10.0.0.3`, ARP sender MAC `00:00:00:00:00:02`, target Alice.
2. Opcode `2`, Ethernet source `00:00:00:00:00:02`, ARP sender IP `10.0.0.1`, ARP sender MAC `00:00:00:00:00:02`, target Bob.
3. Alice’s ICMP echo to `10.0.0.3` with Ethernet destination `00:00:00:00:00:02`.

**Pass:** Alice’s cache maps `10.0.0.3` to Eve. Bob’s cache maps `10.0.0.1` to Eve. The ICMP frame is addressed to Eve’s MAC.

---

## Scene 3 — Forged binding, one victim

Eve forges a trusted IP onto her own MAC, and only one honest host takes the lie. The other honest host keeps the true MAC.

This scene is a different claim from Scene 2’s pair of unicast replies. The pcap must show a forged ARP claim whose sender IP is a trusted address and whose sender MAC is `00:00:00:00:00:02`.

The permanent Alice↔Bob pin, and a filter that only looks for Scene 2’s unsolicited unicast is-at, are not the defense for this scene. Scene 5 is.

**Packets to show:**

1. The forged ARP claim (trusted IP, Eve’s MAC).
2. The victim neighbor table listing that trusted IP at `00:00:00:00:00:02`.
3. The other honest host’s table still showing true MACs.

**Pass:** Exactly one honest cache is wrong. The frame is present on the wire. Jev is not applied yet.

---

## Scene 4 — Forged binding that redirects traffic

Eve again claims a trusted IP with her own MAC, in a form that is not Scene 2 and not Scene 3. After the claim, an ICMP echo between Alice and Bob is delivered toward Eve.

Same rule as Scene 3: do not rely on the permanent pin or on an “unsolicited unicast reply” check. Scene 5 is the defense.

**Packets to show:**

1. The forged ARP claim, distinct in the capture from Scene 2 and Scene 3.
2. ICMP from an honest host to a trusted IP, Ethernet destination `00:00:00:00:00:02`.

**Pass:** A trusted IP is mapped to Eve, and the following ICMP frame uses Eve’s MAC. Jev is not applied yet.

Scenes 3 and 4 stay inside this lab. The requirement is the evidence above (a wrong binding, then a frame sent to Eve). This document does not specify a method for hiding a spoof from detection.

---

## Scene 5 — Jev prevents the spoofs

Run the claims from Scenes 2, 3, and 4 again with Jev in the path. One action handles all of them, because every one of them is the same fact: a trusted IP is announced with the wrong MAC.

### Trigger

`ARP_SPOOFING` when any ARP sender IP in the trusted table is paired with a MAC other than the table value. Check opcode `1` and opcode `2`. Record these in the window JSON and do not use them as the only trigger:

- `mac_ip_conflict`
- `unsolicited_gratuitous`
- `ether_arp_mac_mismatch_count`

Decision JSON must include `class`, `confidence` in `[0.0, 1.0]`, `src_mac`, `claimed_ip`, and `action`.

### Action `RESTORE_BINDINGS`

Jev does all three steps on every conflict. Doing only one of them leaves a hole the other scenes can fall through.

1. **Pin the true neighbor entries** on Alice and Bob for every trusted IP, `nud permanent`, using the ground-truth MAC.
2. **Corrective is-at.** Send ARP opcode `2` that maps each conflicted IP back to its true MAC. Send each cure to the victim and one copy to `ff:ff:ff:ff:ff:ff`. Five copies is the target count.
3. **Drop further lies on the switch.** Open vSwitch drops ARP (`dl_type=0x0806`) that arrives from Eve’s port and uses Alice’s or Bob’s IP as the ARP sender address. Eve’s own IP `10.0.0.2` with Eve’s MAC `00:00:00:00:00:02` is still allowed.

### Packets to show

1. The forged claim.
2. A corrective is-at: sender IP is the trusted IP, sender MAC is the true MAC from the table, not Eve.
3. The next ICMP echo between Alice and Bob. Ethernet destination is the true MAC (`00:00:00:00:00:01` or `00:00:00:00:00:03`).

### Pass

- Scenes 2, 3, and 4 all end with true MACs in both honest caches.
- Victim caches show the true MAC within 500 ms of the conflict.
- A later forged claim from Eve for `10.0.0.1` or `10.0.0.3` does not appear on the victim’s capture.
- Scene 1 still resolves. Alice and Bob can ARP for each other after the drop rule is installed.

---

## Scene 6 — Hash puzzle prevents ARP DDoS

This is the DDoS scene. There is no separate flood scene. A burst of ARP who-has inside this Mininet network is only the input that makes Jev turn the puzzle on.

### Trigger

`ARP_DDOS_FLOOD` when the one-second window has a high `arp_pps` or a high `request_to_reply_ratio`, and `mac_ip_conflict` is false. A binding conflict stays on the Scene 5 path even if the rate is also high.

Suggested window thresholds, measured against Scene 1:

- `arp_pps` above the Scene 1 rate by a wide margin (Scene 1 stays under 20 ARP packets in the window)
- `request_to_reply_ratio` greater than 20

Decision action: `ENABLE_ARP_HASH_PUZZLE` with difficulty `k = 16`.

### Puzzle

The defender broadcasts a challenge with a target sum `S`, a seed hash `H(s)`, and difficulty `k`.

A host that wants an ARP answer attaches a nonce pair `(x1, x2)` such that:

```text
(int(H(x1)) + int(H(x2))) mod 2^k = S
```

`H` is SHA-256. The defender checks the two hashes and the modular sum in constant time. A pair that matches is accepted and that host receives the ARP resolution. Who-has frames with no valid pair are dropped at the switch and get no is-at.

A legitimate host should produce one valid pair in well under a second and then cache the resolved MAC. The requirement is a working solve-and-resolve on this lab, not a general flood tool.

### Packets to show

1. Many opcode `1` who-has frames, and no is-at for the ones that carry no valid pair.
2. The puzzle challenge broadcast (difficulty `k = 16`, seed hash, target sum `S`).
3. One request from an honest host that carries a valid `(x1, x2)`.
4. The is-at that follows only that solved request. Sender MAC is the true MAC for the target IP.

### Pass

- Jev’s class for the burst is `ARP_DDOS_FLOOD`, not `ARP_SPOOFING`.
- Unsolved who-has frames get no reply.
- The honest host that solves the pair learns the true MAC.
- SHA-256 pair check on the defender stays under 0.3 ms per response.
- Scene 5’s binding drop rule is not what stopped this burst. The puzzle is.

---

## Scene order

| Order | Scene | Jev | Pcap must contain |
|---|---|---|---|
| 1 | Normal request and reply | Off | Who-has + matching is-at |
| 2 | Basic unsolicited is-at spoof | Off | Eve claims Alice and Bob; ICMP goes to Eve |
| 3 | Forged binding, one victim | Off | One honest cache wrong |
| 4 | Forged binding that redirects traffic | Off | Forged claim + ICMP to Eve’s MAC |
| 5 | Jev `RESTORE_BINDINGS` | On | Cure is-at + later ICMP to the true MAC |
| 6 | Hash puzzle | On | Challenge, one solved request, one is-at; unsolved flood has no reply |
