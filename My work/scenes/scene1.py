#!/usr/bin/env python3
"""Scene 1 — Normal ARP request and reply (Jev is off)."""
import os
import runpy

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PCAPS = os.path.join(ROOT, 'pcaps')
os.makedirs(PCAPS, exist_ok=True)
labup = runpy.run_path(os.path.join(ROOT, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 1 - Normal ARP request and reply (Jev OFF)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)
lab.dump_arp(alice, bob, eve)

print('\n[2] start capture -> pcaps/scene1.pcap')
lab.pcap_start(os.path.join(PCAPS, 'scene1.pcap'), alice, bob)
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
    ping_out = lab.ping(alice, bob, count=1)

    print('\n[6] ARP caches after ping')
    lab.dump_arp(alice, bob, eve)

    alice_cache = lab.arp_table(alice)
    bob_cache = lab.arp_table(bob)
    assert alice_cache.get(bob.IP()) == bob.MAC().lower(), f'Alice cache wrong: {alice_cache}'
    assert bob_cache.get(alice.IP()) == alice.MAC().lower(), f'Bob cache wrong: {bob_cache}'
    assert '0% packet loss' in ping_out, 'Ping failed'
    print('\n[PASS] Scene 1: Both neighbor tables show true MACs and ping succeeded.')
finally:
    print('\n[7] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 1 done. Open scene1.pcap in Wireshark (filter: arp)')
