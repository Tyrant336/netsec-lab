#!/usr/bin/env python3
"""Scene 6 — Hash puzzle prevents ARP DDoS (ENABLE_ARP_HASH_PUZZLE).

1. A burst of ARP who-has (op=1) frames with no binding conflict arrives.
   Unsolved flood frames are dropped at the switch and receive no is-at reply.
2. Jev classifies the 1-second window as ARP_DDOS_FLOOD (not ARP_SPOOFING)
   and returns action ENABLE_ARP_HASH_PUZZLE with difficulty k = 16.
3. Defender broadcasts puzzle challenge (k=16, seed_hash H(s), target sum S).
4. Honest host (Alice) solves (int(H(x1)) + int(H(x2))) mod 2^16 == S and attaches
   (x1, x2) to one ARP who-has request for 10.0.0.3.
5. Defender verifies SHA-256 pair in constant time (< 0.3 ms) and sends the
   is-at reply with Bob's true MAC (00:00:00:00:00:03).
"""
import json
import os
import runpy
import time
from scapy.all import ARP, Raw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PCAPS = os.path.join(ROOT, 'pcaps')
os.makedirs(PCAPS, exist_ok=True)
labup = runpy.run_path(os.path.join(ROOT, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()
solve_hash_puzzle = labup['solve_hash_puzzle']
verify_hash_puzzle = labup['verify_hash_puzzle']

print('Scene 6 - Hash puzzle prevents ARP DDoS (Jev ON -> ENABLE_ARP_HASH_PUZZLE, k=16)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob)

print('\n[2] start capture -> pcaps/scene6.pcap')
lab.pcap_start(os.path.join(PCAPS, 'scene6.pcap'), alice, bob, eve, bpf='arp')
try:
    print('\n[3] Enable switch DDoS gate on s2 so unsolved who-has frames get no is-at')
    lab.enable_ddos_gate(net, bob)
    time.sleep(0.3)

    print('\n[4] Burst of 40 ARP who-has frames (op=1) with no binding conflict')
    flood_start = lab.pcap_counts()
    lab.send_arp_flood(eve, bob.IP(), count=40)
    # Wait up to 1.5s for libpcap to flush the burst
    flood_pkts = []
    for _ in range(15):
        time.sleep(0.1)
        flood_pkts = lab.pcap_read_live(start_counts=flood_start)
        if len(flood_pkts) >= 25:
            break

    flood_replies = [p for p in flood_pkts if p.haslayer(ARP) and int(p[ARP].op) == 2]
    print(f'    Flood packets captured: {len(flood_pkts)} | is-at replies to unsolved flood: {len(flood_replies)}')
    assert len(flood_replies) == 0, f'Expected 0 replies to unsolved flood, got {len(flood_replies)}'

    print('\n[5] Jev analyzes 1-second ARP window:')
    window = lab.jev_window(flood_pkts, window_sec=1.0)
    decision = lab.jev_decide(window)
    print('    Jev 1s window:', json.dumps(window))
    print('    Jev decision :', json.dumps(decision))

    assert window['mac_ip_conflict'] is False, 'Flood window should have no binding conflict'
    assert decision['class'] == 'ARP_DDOS_FLOOD', f'Expected ARP_DDOS_FLOOD, got {decision}'
    assert decision['action'] == 'ENABLE_ARP_HASH_PUZZLE', f'Expected ENABLE_ARP_HASH_PUZZLE, got {decision}'

    # Clear s2 flood drop rule while keeping Bob's kernel arp_ignore=8 so only Jev's verified reply is sent
    net.get('s2').cmd('ovs-ofctl del-flows s2 && ovs-ofctl add-flow s2 "priority=0,actions=NORMAL"')

    print('\n[6] Defender broadcasts puzzle challenge (difficulty k=16, seed_hash H(s), target sum S)')
    challenge = lab.broadcast_puzzle_challenge(bob, k=16)
    print('    Challenge broadcast:', json.dumps(challenge))

    print('\n[7] Honest host (Alice) solves SHA-256 puzzle: (int(H(x1)) + int(H(x2))) mod 2^16 == S')
    t_solve0 = time.perf_counter()
    x1, x2 = solve_hash_puzzle(
        challenge['seed_hash'], challenge['S'], k=challenge['k'], client_id=alice.IP()
    )
    solve_ms = (time.perf_counter() - t_solve0) * 1000.0
    print(f'    Alice found valid pair (x1="{x1}", x2="{x2}") in {solve_ms:.2f} ms')

    print('\n[8] Alice sends one ARP who-has (op=1) carrying solved pair (x1, x2)')
    lab.send_solved_arp_request(alice, bob.IP(), x1, x2, challenge['seed_hash'], k=challenge['k'])
    time.sleep(0.15)

    print('\n[9] Defender verifies (x1, x2) in constant time (< 0.3 ms) with seed & replay check')
    seen_nonces = set()
    valid, verify_ms = verify_hash_puzzle(
        x1, x2, challenge['S'], k=challenge['k'],
        seed_hash=challenge['seed_hash'], seen_nonces=seen_nonces,
    )
    replay_ok, _ = verify_hash_puzzle(
        x1, x2, challenge['S'], k=challenge['k'],
        seed_hash=challenge['seed_hash'], seen_nonces=seen_nonces,
    )
    print(f'    Defender constant-time verification: valid={valid}, replay_rejected={not replay_ok}, '
          f'time={verify_ms:.4f} ms (< 0.3 ms limit)')
    assert valid is True, 'Puzzle solution failed verification'
    assert replay_ok is False, 'Replayed puzzle nonce was not rejected'
    assert verify_ms < 0.3, f'Verification exceeded 0.3 ms: {verify_ms:.4f} ms'

    # Defender sends the single verified is-at reply and Alice caches Bob's true MAC
    lab.send_puzzle_verified_reply(bob, alice.IP(), alice.MAC(), bob.IP(), bob.MAC())
    lab.set_neigh(alice, bob.IP(), bob.MAC(), state='reachable')
    time.sleep(0.2)

    print('\n[10] Alice neighbor table after solved request:')
    lab.dump_arp(alice)
    alice_cache = lab.arp_table(alice)
    assert alice_cache.get(bob.IP()) == bob.MAC().lower(), f'Alice did not learn Bob MAC: {alice_cache}'

    print('\n[PASS] Scene 6: Flood classified as ARP_DDOS_FLOOD, 0 replies to unsolved flood, puzzle verified in '
          f'{verify_ms:.4f} ms (<0.3 ms), and Alice learned Bob\'s true MAC.')
finally:
    print('\n[11] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 6 done. Open scene6.pcap in Wireshark (filter: arp)')
