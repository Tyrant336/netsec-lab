#!/usr/bin/env python3
"""Scene 5 — Jev prevents the spoofs (RESTORE_BINDINGS).

Runs the forged claims from Scenes 2, 3, and 4 with Jev in the path:
1. Detects ARP_SPOOFING on any trusted IP -> wrong MAC conflict (op=1 or op=2).
2. Executes RESTORE_BINDINGS in < 500 ms:
   - Pins true neighbor entries (nud permanent) on Alice and Bob.
   - Sends 5 corrective is-at (op=2) frames mapping conflicted IP back to true MAC.
   - Installs OVS drop rules on s1 blocking Eve's port from spoofing 10.0.0.1 or 10.0.0.3.
3. Verifies:
   - Honest caches end with true MACs within 500 ms.
   - Subsequent ICMP uses true MAC (00:00:00:00:00:03).
   - Later forged claims from Eve are dropped at s1 and do not appear on victim capture.
   - Scene 1 normal ARP resolution between Alice and Bob still works.
"""
import json
import os
import runpy
import time
from scapy.all import ARP

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PCAPS = os.path.join(ROOT, 'pcaps')
os.makedirs(PCAPS, exist_ok=True)
labup = runpy.run_path(os.path.join(ROOT, 'lab-up.py'))
net, lab, alice, bob, eve = labup['start']()

print('Scene 5 - Jev prevents the spoofs (Jev ON -> RESTORE_BINDINGS)')
print('  Alice', alice.IP(), alice.MAC())
print('  Bob  ', bob.IP(), bob.MAC())
print('  Eve  ', eve.IP(), eve.MAC())

print('\n[1] flush ARP caches')
lab.flush_arp(alice, bob, eve)

print('\n[2] start capture -> pcaps/scene5.pcap (capturing on Alice and Bob)')
lab.pcap_start(os.path.join(PCAPS, 'scene5.pcap'), alice, bob)
try:
    print('\n[3] Baseline resolution: Alice and Bob learn true MACs')
    lab.get_mac(alice, bob.IP())
    lab.get_mac(bob, alice.IP())
    lab.dump_arp(alice, bob)

    attacks = [
        ('Scene 2 claim (unsolicited op=2)', lambda: (
            lab.spoof(eve, alice.IP(), bob.IP(), alice.MAC()),
            lab.spoof(eve, bob.IP(), alice.IP(), bob.MAC()),
        )),
        ('Scene 3 claim (forged op=1 to one victim)', lambda: (
            lab.spoof_one_victim(eve, alice.IP(), bob.IP(), alice.MAC()),
        )),
        ('Scene 4 claim (broadcast Gratuitous ARP)', lambda: (
            lab.spoof_gratuitous(eve, bob.IP()),
        )),
    ]

    for idx, (label, run_attack) in enumerate(attacks, start=1):
        print(f'\n[4.{idx}] Running {label}...')
        # Keep OVS open during the 3 demo claims so each claim appears on wire and triggers Jev repair;
        # install the OVS port block on the 3rd claim so we then prove subsequent claims are dropped at s1.
        install_drop = (idx == len(attacks))
        time.sleep(0.45)
        start_counts = lab.pcap_counts()
        run_attack()
        time.sleep(0.45)
        new_pkts = lab.pcap_read_live(start_counts=start_counts)

        window = lab.jev_window(new_pkts, window_sec=1.0)
        decision = lab.jev_decide(window)
        print('    Jev 1s window:', json.dumps(window))
        print('    Jev decision :', json.dumps(decision))

        assert decision['class'] == 'ARP_SPOOFING', f'Expected ARP_SPOOFING, got {decision}'
        assert decision['action'] == 'RESTORE_BINDINGS', f'Expected RESTORE_BINDINGS, got {decision}'

        repair_ms = lab.restore_bindings(
            net, alice, bob, eve, window['conflicts'], install_ovs_drop=install_drop
        )
        print(f'    RESTORE_BINDINGS completed in {repair_ms:.2f} ms (< 500 ms limit)')
        assert repair_ms < 500.0, f'Repair took too long: {repair_ms:.2f} ms'

        alice_cache = lab.arp_table(alice)
        bob_cache = lab.arp_table(bob)
        assert alice_cache.get(bob.IP()) == bob.MAC().lower(), f'Alice cache not restored: {alice_cache}'
        assert bob_cache.get(alice.IP()) == alice.MAC().lower(), f'Bob cache not restored: {bob_cache}'

    print('\n[5] Caches after all 3 spoof types and Jev RESTORE_BINDINGS:')
    lab.dump_arp(alice, bob)

    print('\n[6] Alice pings Bob -> Ethernet destination is true MAC (00:00:00:00:00:03)')
    ping_out = lab.ping(alice, bob, count=1)
    assert '0% packet loss' in ping_out, 'Ping after restore failed'

    print('\n[7] Test OVS switch drop rule: Eve sends a later forged claim for 10.0.0.3 and 10.0.0.1')
    time.sleep(0.3)
    blocked_start = lab.pcap_counts()
    lab.spoof(eve, alice.IP(), bob.IP(), alice.MAC())
    lab.spoof_one_victim(eve, alice.IP(), bob.IP(), alice.MAC())
    lab.spoof_gratuitous(eve, bob.IP())
    time.sleep(0.3)
    pkts_after_blocked = lab.pcap_read_live(start_counts=blocked_start)
    leaked_spoofs = [
        p for p in pkts_after_blocked
        if p.haslayer(ARP) and p[ARP].hwsrc.lower() == eve.MAC().lower()
        and p[ARP].psrc in (alice.IP(), bob.IP())
    ]
    print(f'    Forged packets reaching victims after OVS drop rule: {len(leaked_spoofs)}')
    assert len(leaked_spoofs) == 0, f'Switch failed to drop Eve spoof: {leaked_spoofs}'

    print('\n[8] Verify Scene 1 still resolves after drop rule is installed:')
    lab.unpin_all(alice, bob)
    resolved_bob = lab.get_mac(alice, bob.IP())
    resolved_alice = lab.get_mac(bob, alice.IP())
    print('    Alice resolved Bob ->', resolved_bob)
    print('    Bob resolved Alice ->', resolved_alice)
    assert resolved_bob == bob.MAC().lower()
    assert resolved_alice == alice.MAC().lower()
    # Re-pin true bindings so final state remains protected
    for host in (alice, bob):
        for ip, mac in lab.TRUSTED.items():
            if ip != host.IP():
                lab.pin(host, ip, mac)

    print('\n[PASS] Scene 5: All 3 spoof types repaired in <500ms, later spoofs dropped at s1, Scene 1 ARP still resolves.')
finally:
    print('\n[9] stop capture')
    lab.pcap_stop()
    net.stop()
    print('\nScene 5 done. Open scene5.pcap in Wireshark (filter: arp || icmp)')
