#!/usr/bin/env python3
"""Pin the real MACs so Eve's spoof cannot replace them."""
import os, runpy

HERE = os.path.dirname(os.path.abspath(__file__))
labup = runpy.run_path(os.path.join(HERE, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 3 - pin the real MACs, then Eve tries again')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> scene3.pcap')
lab.pcap_start(os.path.join(HERE, 'scene3.pcap'), alice, bob, eve)
try:
    print('\n[3] Alice ARPs for Bob, Bob ARPs for Alice (real MACs)')
    bob_mac = lab.get_mac(alice, bob.IP())
    alice_mac = lab.get_mac(bob, alice.IP())
    print('    Alice learned Bob is at', bob_mac)
    print('    Bob learned Alice is at', alice_mac)
    lab.dump_arp(alice, bob)

    print('\n[4] pin those mappings so they cannot be replaced')
    lab.pin(alice, bob.IP(), bob_mac)
    print('    Alice pinned', bob.IP(), '->', bob_mac, '(permanent)')
    lab.pin(bob, alice.IP(), alice_mac)
    print('    Bob pinned', alice.IP(), '->', alice_mac, '(permanent)')
    print('    caches after pin:')
    lab.dump_arp(alice, bob)

    print('\n[5] Eve sends the same lies as Scene 2')
    lab.spoof(eve, alice.IP(), bob.IP())
    print('    Eve told Alice that Bob is at', eve.MAC())
    lab.spoof(eve, bob.IP(), alice.IP())
    print('    Eve told Bob that Alice is at', eve.MAC())
    print('    caches after Eve (pin should still win):')
    lab.dump_arp(alice, bob)

    print('\n[6] Alice pings Bob - should still use Bob\'s real MAC')
    lab.ping(alice, bob)

    print('\n[7] ARP caches after ping')
    lab.dump_arp(alice, bob, eve)
    print('    Expect Alice still has', bob.IP(), '->', bob_mac)
    print('    Expect Bob still has', alice.IP(), '->', alice_mac)
finally:
    print('\n[8] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 3 done. Open scene3.pcap in Wireshark (filter: arp || icmp)')
