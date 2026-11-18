#!/usr/bin/env python3
"""Scene 4 — Forged binding that redirects traffic (Jev is off).

Eve broadcasts a Gratuitous ARP (psrc=10.0.0.3, pdst=10.0.0.3, hwsrc=00:00:00:00:00:02,
Ether dst=ff:ff:ff:ff:ff:ff) — distinct from Scene 2 (unicast op=2 pair) and Scene 3
(unicast op=1 to Alice). After the claim, Alice's ICMP echo to 10.0.0.3 is delivered
to Eve's MAC (00:00:00:00:00:02).
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

print('Scene 4 - Forged binding that redirects traffic (Broadcast Gratuitous ARP, Jev OFF)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> pcaps/scene4.pcap')
lab.pcap_start(os.path.join(PCAPS, 'scene4.pcap'), alice, bob, eve)
try:
    print('\n[3] Baseline resolution: Alice and Bob learn true MACs')
    print('    Alice learned Bob is at', lab.get_mac(alice, bob.IP()))
    print('    Bob learned Alice is at', lab.get_mac(bob, alice.IP()))
    lab.dump_arp(alice, bob)

    print('\n[4] Eve enables forwarding and broadcasts Gratuitous ARP for 10.0.0.3:')
    print('    Ether dst=ff:ff:ff:ff:ff:ff, psrc=10.0.0.3, pdst=10.0.0.3, hwsrc=00:00:00:00:00:02')
    lab.forward(eve, on=1)
    lab.spoof_gratuitous(eve, bob.IP())
    time.sleep(0.2)

    print('\n[5] Neighbor tables after Gratuitous ARP:')
    lab.dump_arp(alice, bob)

    alice_cache = lab.arp_table(alice)
    assert alice_cache.get(bob.IP()) == eve.MAC().lower(), f'Expected Alice poisoned, got {alice_cache}'

    print('\n[6] Alice sends ICMP echo to 10.0.0.3 -> delivered to Eve\'s MAC (00:00:00:00:00:02)')
    lab.ping(alice, bob, count=1)

    print('\n[7] Neighbor tables after ICMP echo:')
    lab.dump_arp(alice, bob)
    print('\n[PASS] Scene 4: Gratuitous ARP mapped 10.0.0.3 to Eve (00:00:00:00:00:02) and redirected ICMP to Eve.')
finally:
    print('\n[8] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 4 done. Open scene4.pcap in Wireshark (filter: arp || icmp)')
