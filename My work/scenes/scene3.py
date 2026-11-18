#!/usr/bin/env python3
"""Scene 3 — Forged binding, one victim (Jev is off).

Eve sends a forged ARP who-has (op=1) unicast to Alice claiming Bob's IP (10.0.0.3)
is at Eve's MAC (00:00:00:00:00:02). Only Alice takes the lie; Bob keeps the true MAC.
"""
import os
import runpy
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PCAPS = os.path.join(ROOT, 'pcaps')
os.makedirs(PCAPS, exist_ok=True)
labup = runpy.run_path(os.path.join(ROOT, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 3 - Forged binding, one victim (forged op=1 to Alice only, Jev OFF)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> pcaps/scene3.pcap')
lab.pcap_start(os.path.join(PCAPS, 'scene3.pcap'), alice, bob, eve)
try:
    print('\n[3] Baseline resolution: Alice and Bob learn true MACs')
    print('    Alice learned Bob is at', lab.get_mac(alice, bob.IP()))
    print('    Bob learned Alice is at', lab.get_mac(bob, alice.IP()))
    lab.dump_arp(alice, bob)

    print('\n[4] Eve sends a forged ARP who-has (op=1) unicast to Alice:')
    print('    Claim: sender IP 10.0.0.3 is at sender MAC 00:00:00:00:00:02 (target Alice 10.0.0.1)')
    lab.spoof_one_victim(eve, alice.IP(), bob.IP(), alice.MAC())
    time.sleep(0.2)

    print('\n[5] Neighbor tables after forged claim:')
    lab.dump_arp(alice, bob)

    alice_cache = lab.arp_table(alice)
    bob_cache = lab.arp_table(bob)
    assert alice_cache.get(bob.IP()) == eve.MAC().lower(), f'Expected Alice poisoned, got {alice_cache}'
    assert bob_cache.get(alice.IP()) == alice.MAC().lower(), f'Expected Bob clean, got {bob_cache}'
    print('\n[PASS] Scene 3: Exactly one honest cache (Alice) is poisoned (00:00:00:00:00:02); Bob still has true MAC (00:00:00:00:00:01).')
finally:
    print('\n[6] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 3 done. Open scene3.pcap in Wireshark (filter: arp)')
