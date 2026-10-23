#!/usr/bin/env python3
"""Alice and Bob ARP so Alice learns Bob's MAC."""
import os, runpy

HERE = os.path.dirname(os.path.abspath(__file__))
labup = runpy.run_path(os.path.join(HERE, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 1 - Alice and Bob learn each other')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> scene1.pcap')
lab.pcap_start(os.path.join(HERE, 'scene1.pcap'), alice, bob)
try:
    print('\n[3] Alice ARPs: who-has Bob?')
    bob_mac = lab.get_mac(alice, bob.IP())
    print('    Alice learned Bob is at', bob_mac)
    lab.dump_arp(alice)

    print('\n[4] Bob ARPs: who-has Alice?')
    alice_mac = lab.get_mac(bob, alice.IP())
    print('    Bob learned Alice is at', alice_mac)
    lab.dump_arp(bob)

    print('\n[5] Alice pings Bob (uses the MAC she just learned)')
    lab.ping(alice, bob)

    print('\n[6] ARP caches after ping')
    lab.dump_arp(alice, bob, eve)
finally:
    print('\n[7] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 1 done. Open scene1.pcap in Wireshark (filter: arp || icmp)')
