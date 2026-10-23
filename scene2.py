#!/usr/bin/env python3
"""Eve tells Alice she is Bob, and Bob she is Alice."""
import os, runpy

HERE = os.path.dirname(os.path.abspath(__file__))
labup = runpy.run_path(os.path.join(HERE, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 2 - Eve interferes')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> scene2.pcap')
lab.pcap_start(os.path.join(HERE, 'scene2.pcap'), alice, bob, eve)
try:
    print('\n[3] Alice ARPs for Bob, Bob ARPs for Alice (real MACs)')
    print('    Alice learned Bob is at', lab.get_mac(alice, bob.IP()))
    print('    Bob learned Alice is at', lab.get_mac(bob, alice.IP()))
    print('    caches before Eve:')
    lab.dump_arp(alice, bob)

    print('\n[4] Eve can forward the packets she intercepts')
    lab.forward(eve)

    print('\n[5] Eve tells Alice: Bob lives at Eve\'s MAC', eve.MAC())
    lab.spoof(eve, alice.IP(), bob.IP())
    print('    Eve tells Bob: Alice lives at Eve\'s MAC', eve.MAC())
    lab.spoof(eve, bob.IP(), alice.IP())
    print('    caches after Eve:')
    lab.dump_arp(alice, bob)

    print('\n[6] Alice pings Bob - frames should go to Eve first')
    lab.ping(alice, bob)

    print('\n[7] ARP caches after ping')
    lab.dump_arp(alice, bob, eve)
    print('    If Eve succeeded, Alice lists Bob as', eve.MAC())
    print('    If Eve succeeded, Bob lists Alice as', eve.MAC())
finally:
    print('\n[8] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 2 done. Open scene2.pcap in Wireshark (filter: arp || icmp)')
