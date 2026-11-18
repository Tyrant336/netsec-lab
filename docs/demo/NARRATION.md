# Jev-Guard 5-minute demo — narration script

The video is silent. Read this while it plays. When a **LOOK** bar is on screen, pause on that packet.

Video: `docs/demo/Jev-Guard-5min-demo.mp4`

---

## 0:00–0:08  Title

Jev-Guard is a Layer-2 lab. It detects ARP poisoning and ARP floods, then mitigates them on the host and on the switch.

## 0:08–0:18  Topology

Alice `:01`, Eve the adversary `:02`, Bob `:03`. Two Open vSwitch bridges. Jev is off for scenes one through four, on for five and six.

## 0:18–0:30  Scene 1 terminal

`sudo python3 scenes/scene1.py`. Honest ARP, then one ping, `ttl=64`. True MACs in both caches.

## 0:30–0:42  Scene 1 packet 1 — who-has

This is the capture. Packet 1: Alice broadcasts who-has `10.0.0.3`. Opcode 1. Sender MAC is Alice `:01`.

## 0:42–0:58  Scene 1 packet 2 — is-at

Packet 2: Bob’s unicast is-at. `10.0.0.3 is at 00:00:00:00:00:03`. Opcode 2. That is the honest reply every later scene will violate.

## 0:58–1:08  Scene 2 terminal

Jev still off. Eve sends two unsolicited opcode-2 replies. Both caches list Eve. Ping comes back with `ttl=63`.

## 1:08–1:26  Scene 2 packet 5 — the spoof

Look at the packet. Ethernet source is Eve. Opcode 2. Sender IP is Bob’s `10.0.0.3`. Sender MAC is Eve `:02`. That is the lie, on the wire.

## 1:26–1:38  Scene 2 packet 7 — MITM ICMP

Alice pings `10.0.0.3`, but Ethernet destination is Eve, not Bob. The frame is hijacked.

## 1:38–1:46  Scene 3 terminal

Different lie: a unicast opcode-1 who-has, to Alice only.

## 1:46–1:58  Scene 3 packet 5 — forged who-has

Opcode 1, not 2. Destination is Alice only. Sender IP `10.0.0.3`, sender MAC Eve. One victim.

## 1:58–2:06  Scene 4 terminal

Third vector: broadcast Gratuitous ARP.

## 2:06–2:18  Scene 4 packet 5 — GARP

Ethernet destination is broadcast. `psrc` and `pdst` are both `10.0.0.3`. Sender MAC is Eve.

## 2:18–2:28  Scene 4 packet 6 — ICMP to Eve

After that GARP, Alice’s ICMP Ethernet destination is Eve again.

## 2:28–2:34  Jev on

Same three claims. Now Jev runs `RESTORE_BINDINGS`: pin, five corrective is-at, drop Eve at `s1`.

## 2:34–2:46  Scene 5 terminal

Three repairs: two hundred five milliseconds, ninety-nine, one hundred sixty-seven. Under five hundred. Caches go permanent on the true MACs.

## 2:46–2:56  Scene 5 — Eve’s spoof still appears

The lie is still in the capture. Jev has to answer it.

## 2:56–3:14  Scene 5 — corrective is-at

Look: opcode 2, sender IP is the trusted address, sender MAC is the **true** MAC, not Eve. That is the cure on the wire.

## 3:14–3:24  Scene 5 — honest ICMP

Ethernet destination is Bob `:03`, `ttl=64`. Later spoofs from Eve: zero packets at the victims.

## 3:24–3:36  Scene 6 terminal

Not spoofing. Forty who-has with Eve’s own valid binding. Class `ARP_DDOS_FLOOD`. Zero replies to the flood. Puzzle on.

## 3:36–3:46  Scene 6 — flood packet

Forty of these who-has frames. No is-at. The flood is dropped.

## 3:46–4:06  Scene 6 packet 41 — puzzle challenge

Expand the ARP trailer. JSON on the wire: `JEV_ARP_PUZZLE_CHALLENGE`, `k=16`, seed hash, target `S=27603`.

## 4:06–4:24  Scene 6 packet 42 — solution

Alice’s who-has carries `JEV_ARP_PUZZLE_SOLUTION` with nonce pair `x1`, `x2`. Solved in about one millisecond. Verify in zero point zero nine milliseconds.

## 4:24–4:34  Scene 6 packet 43 — the only is-at

Only this reply is sent: `10.0.0.3 is at 00:00:00:00:00:03`. After a valid proof.

## 4:34–4:46  Results

Before Jev: poisoned caches, `ttl=63`, floods get answers. After: detection, sub-200 ms repair, zero leakage, puzzle-gated resolution.

## 4:46–5:00  Close

Six scenes, each with a pcap you just saw inside the video. That is the lab.
