#!/usr/bin/env python3
"""lab-up.py - Mininet topology, packet actions, and Jev-Guard engine for the 6-scene ARP lab.

Topology:
    Alice (10.0.0.1) --- s1 === s2 --- Bob (10.0.0.3)
                         |
                        Eve (10.0.0.2)
"""

from collections import Counter, defaultdict
import hashlib
import hmac
import json
import math
import os
import secrets
import socket
import struct
import sys
import time
import urllib.request

try:
    from mininet.cli import CLI
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.topo import Topo
except ImportError:
    CLI = Mininet = OVSBridge = None
    Topo = object

try:
    from scapy.all import ARP, Ether, rdpcap, srp, wrpcap
except ImportError:
    rdpcap = srp = wrpcap = None

    class Ether:
        def __init__(self, src='00:00:00:00:00:00', dst='ff:ff:ff:ff:ff:ff'):
            self.src, self.dst, self._arp, self.time = src, dst, None, 0.0

        def __truediv__(self, other):
            self._arp = other
            return self

        def haslayer(self, cls):
            return cls is Ether or (cls is ARP and self._arp is not None)

        def __getitem__(self, cls):
            return self if cls is Ether else self._arp

    class ARP:
        def __init__(self, op=1, hwsrc='00:00:00:00:00:00', psrc='0.0.0.0', hwdst='00:00:00:00:00:00', pdst='0.0.0.0'):
            self.op, self.hwsrc, self.psrc, self.hwdst, self.pdst = op, hwsrc, psrc, hwdst, pdst

SELF = os.path.abspath(__file__)
HERE = os.path.dirname(SELF)
JEV_URL = 'https://openrouter.ai/api/alpha/decisions'

TRUSTED_BINDINGS = {
    '10.0.0.1': '00:00:00:00:00:01',
    '10.0.0.2': '00:00:00:00:00:02',
    '10.0.0.3': '00:00:00:00:00:03',
}


def load_env(path=None):
    """Load OPENROUTER_API_KEY and OPENROUTER_MODEL from .env."""
    if path is None:
        path = os.path.join(HERE, '.env')
    if not os.path.isfile(path):
        return
    with open(path, encoding='utf-8') as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


load_env()


def sha256_int(text):
    """Return full 256-bit integer value of SHA-256(text)."""
    return int.from_bytes(hashlib.sha256(text.encode('utf-8')).digest(), 'big')


def solve_hash_puzzle(seed_hash, target_sum, k=16, client_id=''):
    """Find (x1, x2) such that (int(H(x1)) + int(H(x2))) mod 2^k == S."""
    mod = 1 << k
    mask = mod - 1
    prefix = f'{seed_hash[:8]}:{client_id}:' if client_id else f'{seed_hash[:8]}:'
    seen = {}
    i = 0
    while True:
        x = f'{prefix}{i}'
        rem = sha256_int(x) & mask
        need = (target_sum - rem) & mask
        if need in seen:
            return seen[need], x
        seen[rem] = x
        i += 1


def verify_hash_puzzle(x1, x2, target_sum, k=16, seed_hash=None, seen_nonces=None):
    """Constant-time, replay-safe verification of (int(H(x1)) + int(H(x2))) mod 2^k == S.

    Returns (is_valid, elapsed_ms).
    """
    t0 = time.perf_counter()
    mask = (1 << k) - 1
    h1 = int.from_bytes(hashlib.sha256(x1.encode('utf-8')).digest(), 'big')
    h2 = int.from_bytes(hashlib.sha256(x2.encode('utf-8')).digest(), 'big')
    lhs = (h1 + h2) & mask
    rhs = int(target_sum) & mask
    sum_ok = hmac.compare_digest(lhs.to_bytes(4, 'big'), rhs.to_bytes(4, 'big'))
    prefix_ok = True if not seed_hash else (
        x1.startswith(f'{seed_hash[:8]}:') and x2.startswith(f'{seed_hash[:8]}:')
    )
    pair = (x1, x2) if x1 <= x2 else (x2, x1)
    fresh_ok = x1 != x2 and (seen_nonces is None or pair not in seen_nonces)
    valid = bool(sum_ok and prefix_ok and fresh_ok)
    if valid and seen_nonces is not None:
        seen_nonces.add(pair)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return valid, elapsed_ms


class ArpLab(Topo):
    """2-switch, 3-host topology + helper methods used by scene1..scene6.py."""

    TRUSTED = TRUSTED_BINDINGS

    # ---- 1. Build network topology -----------------------------------

    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        alice = self.addHost('Alice', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        eve = self.addHost('Eve', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        bob = self.addHost('Bob', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

        self.addLink(alice, s1)
        self.addLink(eve, s1)
        self.addLink(bob, s2)
        self.addLink(s1, s2)

    # ---- 2. Host ARP / ping commands (via host.cmd) ------------------

    def flush_arp(self, *hosts):
        """Clear the ARP cache on each given host and enable arp_accept."""
        for h in hosts:
            intf = h.defaultIntf().name
            h.cmd('sysctl -w net.ipv4.conf.all.arp_accept=1 >/dev/null 2>&1')
            h.cmd(f'sysctl -w net.ipv4.conf.{intf}.arp_accept=1 >/dev/null 2>&1')
            h.cmd('sysctl -w net.ipv4.conf.all.arp_ignore=0 >/dev/null 2>&1')
            h.cmd(f'sysctl -w net.ipv4.conf.{intf}.arp_ignore=0 >/dev/null 2>&1')
            h.cmd('sysctl -w net.ipv4.neigh.default.locktime=0 >/dev/null 2>&1')
            h.cmd(f'sysctl -w net.ipv4.neigh.{intf}.locktime=0 >/dev/null 2>&1')
            h.cmd('ip neigh flush all')

    def dump_arp(self, *hosts):
        """Print the ARP cache of each given host."""
        for h in hosts:
            text = h.cmd('ip -color=never neigh show').strip()
            print('---', h.name, '---')
            print(text if text else '(empty)')

    def arp_table(self, host):
        """Return host's ARP cache as a dict: {ip: mac}."""
        table = {}
        for line in host.cmd('ip -color=never neigh show').splitlines():
            parts = line.split()
            if 'lladdr' in parts:
                ip = parts[0]
                mac = parts[parts.index('lladdr') + 1].lower()
                table[ip] = mac
        return table

    def set_neigh(self, host, ip, mac, state='reachable'):
        """Install/update a dynamic neighbor entry in the host kernel table."""
        intf = host.defaultIntf().name
        host.cmd(f'ip neigh replace {ip} lladdr {mac} nud {state} dev {intf}')

    def pin(self, host, ip, mac):
        """Add a permanent static ARP entry on `host`."""
        intf = host.defaultIntf().name
        host.cmd(f'ip neigh replace {ip} lladdr {mac} nud permanent dev {intf}')

    def unpin_all(self, *hosts):
        """Flush permanent and dynamic entries on given hosts."""
        for h in hosts:
            intf = h.defaultIntf().name
            for ip in TRUSTED_BINDINGS:
                if ip != h.IP():
                    h.cmd(f'ip neigh del {ip} dev {intf} >/dev/null 2>&1')
            h.cmd('ip neigh flush all')

    def forward(self, host, on=1):
        """Enable (1) or disable (0) IPv4 packet forwarding on `host`."""
        host.cmd(f'sysctl -w net.ipv4.ip_forward={int(on)} >/dev/null')
        host.cmd('sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1')
        intf = host.defaultIntf().name
        host.cmd(f'sysctl -w net.ipv4.conf.{intf}.send_redirects=0 >/dev/null 2>&1')

    def ping(self, src, dst, count=2):
        """Send ICMP ping from `src` host to `dst` host."""
        out = src.cmd(f'ping -c {count} -W 2 {dst.IP()}')
        time.sleep(0.15)
        print(out.strip())
        return out

    # ---- 3. ARP packet actions (runs Scapy inside the host) ----------

    def as_host(self, host, *args):
        """Run this script inside `host` so Scapy uses that host's NIC."""
        quoted = ' '.join(f'"{a}"' for a in args)
        return host.cmd(f'python3 "{SELF}" {quoted}')

    def get_mac(self, host, ip):
        """Ask `host` to send an ARP request for `ip`, update kernel cache, and return MAC."""
        output = self.as_host(host, 'get_mac', ip).strip()
        if not output:
            return None
        mac = output.splitlines()[-1].strip().lower()
        if ':' in mac:
            self.set_neigh(host, ip, mac, state='stale')
            return mac
        return None

    def spoof(self, host, target_ip, spoofed_ip, target_mac=None):
        """Scene 2: Send unsolicited unicast ARP reply (op=2) telling `target_ip` that `spoofed_ip` is at `host`'s MAC."""
        if target_mac is None:
            target_mac = TRUSTED_BINDINGS.get(target_ip, 'ff:ff:ff:ff:ff:ff')
        self.raw_send_arp(
            host,
            eth_dst=target_mac,
            op=2,
            psrc=spoofed_ip,
            hwsrc=host.MAC(),
            pdst=target_ip,
            hwdst=target_mac,
            count=1,
        )

    def spoof_one_victim(self, host, victim_ip, claimed_ip, victim_mac=None):
        """Scene 3: Forged ARP who-has (op=1) sent unicast to `victim_ip` claiming `claimed_ip` is at `host`'s MAC."""
        if victim_mac is None:
            victim_mac = TRUSTED_BINDINGS[victim_ip]
        self.raw_send_arp(
            host,
            eth_dst=victim_mac,
            op=1,
            psrc=claimed_ip,
            hwsrc=host.MAC(),
            pdst=victim_ip,
            hwdst='00:00:00:00:00:00',
            count=1,
        )

    def spoof_gratuitous(self, host, claimed_ip):
        """Scene 4: Broadcast Gratuitous ARP claim (psrc=pdst=claimed_ip, hwsrc=host's MAC, Ether dst=ff:ff:ff:ff:ff:ff)."""
        self.raw_send_arp(
            host,
            eth_dst='ff:ff:ff:ff:ff:ff',
            op=2,
            psrc=claimed_ip,
            hwsrc=host.MAC(),
            pdst=claimed_ip,
            hwdst='ff:ff:ff:ff:ff:ff',
            count=1,
        )

    def raw_send_arp(self, host, eth_dst, op, psrc, hwsrc, pdst, hwdst, payload_bytes=b'', count=1, inter=0.0):
        """Send Ethernet+ARP frame(s) from `host`'s default interface using stdlib AF_PACKET (60-byte padded)."""
        intf = host.defaultIntf().name
        eth_src = host.MAC() if hwsrc is None else hwsrc
        payload_hex = payload_bytes.hex()
        code = (
            "import socket, struct, time\n"
            "m = lambda x: bytes(int(b, 16) for b in x.split(':'))\n"
            f"frame = struct.pack('!6s6sHHHBBH6s4s6s4s', "
            f"m('{eth_dst}'), m('{eth_src}'), 0x0806, 1, 0x0800, 6, 4, {int(op)}, "
            f"m('{hwsrc}'), socket.inet_aton('{psrc}'), m('{hwdst}'), socket.inet_aton('{pdst}')) "
            f"+ bytes.fromhex('{payload_hex}')\n"
            "if len(frame) < 60: frame += b'\\x00' * (60 - len(frame))\n"
            "s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
            f"s.bind(('{intf}', 0))\n"
            f"for _ in range({int(count)}):\n"
            "    s.send(frame)\n"
            f"    if {float(inter)} > 0: time.sleep({float(inter)})\n"
            "s.close()\n"
        )
        host.cmd(f'python3 -c "{code}"')

    def send_corrective_arp(self, defender_host, claimed_ip, true_mac, victim_ip, victim_mac, copies=5):
        """Scene 5: Send `copies` corrective is-at (op=2) frames from `defender_host` via stdlib raw socket (<35ms)."""
        intf = defender_host.defaultIntf().name
        code = (
            "import socket, struct, time\n"
            "m = lambda x: bytes(int(b, 16) for b in x.split(':'))\n"
            f"sm = m('{true_mac}')\n"
            f"si = socket.inet_aton('{claimed_ip}')\n"
            "s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
            f"s.bind(('{intf}', 0))\n"
            f"for i in range({copies}):\n"
            f"    dm = m('ff:ff:ff:ff:ff:ff' if i == {copies - 1} else '{victim_mac}')\n"
            f"    di = socket.inet_aton('{claimed_ip}' if i == {copies - 1} else '{victim_ip}')\n"
            "    frame = struct.pack('!6s6sHHHBBH6s4s6s4s', dm, sm, 0x0806, 1, 0x0800, 6, 4, 2, sm, si, dm, di) + b'\\x00'*18\n"
            "    s.send(frame)\n"
            "    time.sleep(0.004)\n"
            "s.close()\n"
        )
        defender_host.cmd(f'python3 -c "{code}"')

    def send_arp_flood(self, host, target_ip, count=40):
        """Scene 6: Send a burst of `count` ARP who-has (op=1) requests with no binding conflict."""
        self.raw_send_arp(
            host,
            eth_dst='ff:ff:ff:ff:ff:ff',
            op=1,
            psrc=host.IP(),
            hwsrc=host.MAC(),
            pdst=target_ip,
            hwdst='00:00:00:00:00:00',
            count=count,
            inter=0.005,
        )

    def broadcast_puzzle_challenge(self, defender_host, k=16, seed=None, target_sum=None):
        """Scene 6: Broadcast ARP puzzle challenge carrying k, seed_hash H(s), and target sum S."""
        if seed is None:
            seed = secrets.token_hex(8)
        seed_hash = hashlib.sha256(seed.encode('utf-8')).hexdigest()
        if target_sum is None:
            target_sum = int(seed_hash[:4], 16) % (1 << k)
        challenge = {
            'type': 'JEV_ARP_PUZZLE_CHALLENGE',
            'k': int(k),
            'seed_hash': seed_hash,
            'S': int(target_sum),
        }
        self.raw_send_arp(
            defender_host,
            eth_dst='ff:ff:ff:ff:ff:ff',
            op=1,
            psrc=defender_host.IP(),
            hwsrc=defender_host.MAC(),
            pdst=defender_host.IP(),
            hwdst='ff:ff:ff:ff:ff:ff',
            payload_bytes=json.dumps(challenge).encode('utf-8'),
        )
        return challenge

    def send_solved_arp_request(self, host, target_ip, x1, x2, seed_hash, k=16):
        """Scene 6: Honest host sends one ARP who-has carrying valid (x1, x2) solution."""
        payload = {
            'type': 'JEV_ARP_PUZZLE_SOLUTION',
            'k': int(k),
            'seed_hash': seed_hash,
            'x1': x1,
            'x2': x2,
        }
        self.raw_send_arp(
            host,
            eth_dst='ff:ff:ff:ff:ff:ff',
            op=1,
            psrc=host.IP(),
            hwsrc=host.MAC(),
            pdst=target_ip,
            hwdst='00:00:00:00:00:00',
            payload_bytes=json.dumps(payload).encode('utf-8'),
        )

    def send_puzzle_verified_reply(self, defender_host, requester_ip, requester_mac, target_ip, target_mac):
        """Scene 6: Defender sends the single ARP is-at reply after verifying (x1, x2)."""
        self.raw_send_arp(
            defender_host,
            eth_dst=requester_mac,
            op=2,
            psrc=target_ip,
            hwsrc=target_mac,
            pdst=requester_ip,
            hwdst=requester_mac,
        )
        return target_mac

    # ---- 4. Jev-Guard Window & Classifier (Scenes 5 & 6) -------------

    def jev_window(self, packets, window_sec=1.0):
        """Analyze ARP frames (EtherType 0x0806) in a 1-second window and return telemetry dict."""
        arp_pkts = [p for p in packets if p.haslayer(ARP)]
        req_count = 0
        rep_count = 0
        unsolicited_gratuitous = 0
        ether_arp_mismatch = 0
        conflicts = []
        seen_requests = set()
        unique_targets = set()
        sender_counts = Counter()
        sender_ips = {}
        macs_by_ip = defaultdict(set)
        timestamps = []

        for p in arp_pkts:
            a = p[ARP]
            eth_src = p[Ether].src.lower() if p.haslayer(Ether) else a.hwsrc.lower()
            hwsrc = a.hwsrc.lower()
            psrc = a.psrc
            pdst = a.pdst
            op = int(a.op)

            timestamps.append(float(getattr(p, 'time', 0.0)))
            sender_counts[eth_src] += 1
            sender_ips[eth_src] = psrc
            if psrc != '0.0.0.0':
                macs_by_ip[psrc].add(hwsrc)
                macs_by_ip[psrc].add(eth_src)

            if eth_src != hwsrc:
                ether_arp_mismatch += 1

            if op == 1:
                req_count += 1
                unique_targets.add(pdst)
                seen_requests.add((psrc, pdst))
                if psrc == pdst:
                    unsolicited_gratuitous += 1
            elif op == 2:
                rep_count += 1
                if psrc == pdst or (pdst, psrc) not in seen_requests:
                    unsolicited_gratuitous += 1

            expected_mac = TRUSTED_BINDINGS.get(psrc)
            if expected_mac:
                exp = expected_mac.lower()
                if hwsrc != exp or eth_src != exp:
                    conflicts.append({
                        'src_mac': hwsrc if hwsrc != exp else eth_src,
                        'eth_src': eth_src,
                        'claimed_ip': psrc,
                        'expected_mac': exp,
                        'op': op,
                        'pdst': pdst,
                        'reason': 'ether_arp_mismatch' if hwsrc == exp else 'trusted_binding_mismatch',
                    })

        # Catch MAC-flapping on dynamic/unpinned IPs not in TRUSTED_BINDINGS
        for ip, macs in macs_by_ip.items():
            if ip not in TRUSTED_BINDINGS and len(macs) > 1:
                ordered = sorted(macs)
                conflicts.append({
                    'src_mac': ordered[-1],
                    'eth_src': ordered[-1],
                    'claimed_ip': ip,
                    'expected_mac': ordered[0],
                    'op': 0,
                    'pdst': ip,
                    'reason': 'ip_mac_flap',
                })

        total_arp = req_count + rep_count
        dur = max(window_sec, 0.001)
        arp_pps = round(total_arp / dur, 2)
        ratio = round(req_count / float(rep_count if rep_count > 0 else 1), 2)

        # 100ms sliding-window micro-burst detector (triggers only on >=10 frames / 100ms)
        timestamps.sort()
        max_100ms = 0
        j = 0
        for i, ts in enumerate(timestamps):
            while ts - timestamps[j] > 0.1:
                j += 1
            if i - j + 1 > max_100ms:
                max_100ms = i - j + 1
        peak_burst_pps = round(max_100ms / 0.1, 2) if max_100ms >= 10 else arp_pps

        top_sender_mac, top_count = sender_counts.most_common(1)[0] if sender_counts else (None, 0)
        top_sender_ip = sender_ips.get(top_sender_mac) if top_sender_mac else None
        has_conflict = len(conflicts) > 0
        ddos_anomaly = (not has_conflict) and (
            arp_pps > 20
            or ratio > 20
            or peak_burst_pps >= 100
            or (len(unique_targets) >= 8 and rep_count == 0)
        )

        return {
            'window_sec': window_sec,
            'total_arp_packets': total_arp,
            'arp_pps': arp_pps,
            'peak_burst_pps': peak_burst_pps,
            'request_count': req_count,
            'reply_count': rep_count,
            'request_to_reply_ratio': ratio,
            'unique_targets': len(unique_targets),
            'top_sender_mac': top_sender_mac,
            'top_sender_ip': top_sender_ip,
            'top_sender_pps': round(top_count / dur, 2),
            'mac_ip_conflict': has_conflict,
            'ddos_anomaly': ddos_anomaly,
            'unsolicited_gratuitous': unsolicited_gratuitous,
            'ether_arp_mac_mismatch_count': ether_arp_mismatch,
            'conflicts': conflicts,
        }

    @staticmethod
    def _local_classify(window):
        """Sub-millisecond deterministic Jev classifier used for fast-path and offline fallback."""
        if window.get('mac_ip_conflict'):
            return 'ARP_SPOOFING', 1.0, 'RESTORE_BINDINGS'
        if (
            window.get('ddos_anomaly')
            or window.get('arp_pps', 0) > 20
            or window.get('request_to_reply_ratio', 0) > 20
        ):
            return 'ARP_DDOS_FLOOD', 0.99, 'ENABLE_ARP_HASH_PUZZLE'
        return 'NORMAL_ARP', 0.99, 'NO_ACTION'

    def jev_decide(self, window, call_api=True):
        """Classify a 1-second ARP window via cached OpenRouter Decisions API (typesafe/jev-1.14) with local fallback."""
        load_env()
        key = os.environ.get('OPENROUTER_API_KEY', '').strip()
        model = os.environ.get('OPENROUTER_MODEL', 'typesafe/jev-1.14').strip()

        local_class, local_conf, local_action = self._local_classify(window)
        first = window['conflicts'][0] if window.get('conflicts') else None
        if first:
            src_mac, claimed_ip = first['src_mac'], first['claimed_ip']
        elif local_class == 'ARP_DDOS_FLOOD':
            src_mac = window.get('top_sender_mac')
            claimed_ip = window.get('top_sender_ip')
        else:
            src_mac = claimed_ip = None

        action_map = {
            'NORMAL_ARP': 'NO_ACTION',
            'ARP_SPOOFING': 'RESTORE_BINDINGS',
            'ARP_DDOS_FLOOD': 'ENABLE_ARP_HASH_PUZZLE',
        }

        # Fast-path idle windows and memoize repeated attack signatures (# ponytail: in-process dict cache)
        cache = getattr(self, '_jev_cache', None)
        if cache is None:
            cache = self._jev_cache = {}
        sig = (
            bool(window.get('mac_ip_conflict')),
            bool(window.get('ddos_anomaly') or window.get('arp_pps', 0) > 20 or window.get('request_to_reply_ratio', 0) > 20),
            src_mac,
            claimed_ip,
        )
        if window.get('total_arp_packets', 0) == 0 or not (call_api and key):
            decision = {
                'model': 'local-jev-guard' if not (call_api and key) else model,
                'class': local_class,
                'confidence': local_conf,
                'src_mac': src_mac,
                'claimed_ip': claimed_ip,
                'action': local_action,
            }
            if local_action == 'ENABLE_ARP_HASH_PUZZLE':
                decision['difficulty_k'] = 16 if window.get('arp_pps', 0) <= 500 else 18
            return decision

        if sig in cache:
            return dict(cache[sig])

        body = {
            'model': model,
            'state': {
                'trusted_bindings': TRUSTED_BINDINGS,
                'arp_window_1s': window,
            },
            'questions': {
                'traffic_class': {
                    'type': 'choice',
                    'instructions': (
                        'Classify this 1-second ARP window into NORMAL_ARP, ARP_SPOOFING, or ARP_DDOS_FLOOD. '
                        'If mac_ip_conflict is true (trusted binding mismatch, Ether/ARP MAC split, or IP-MAC flap), '
                        'choose ARP_SPOOFING. If mac_ip_conflict is false and ddos_anomaly is true '
                        '(arp_pps > 20, request_to_reply_ratio > 20, peak_burst_pps >= 100, or subnet scan), '
                        'choose ARP_DDOS_FLOOD. Otherwise choose NORMAL_ARP.'
                    ),
                    'criteria': {
                        'NORMAL_ARP': 'Request/reply match the trusted table, low sustained and burst rate.',
                        'ARP_SPOOFING': 'mac_ip_conflict is true: claimed IP->MAC or Ether.src disagrees with ground truth.',
                        'ARP_DDOS_FLOOD': 'mac_ip_conflict is false and volumetric/burst/scan ARP flood detected.',
                    },
                },
                'action': {
                    'type': 'choice',
                    'instructions': 'Select the required mitigation action for this ARP window.',
                    'criteria': {
                        'NO_ACTION': 'Traffic is normal ARP.',
                        'RESTORE_BINDINGS': 'ARP spoofing conflict detected; pin permanent entries, send 5 corrective is-at frames, and enforce DAI port filter on switch.',
                        'ENABLE_ARP_HASH_PUZZLE': 'ARP DDoS flood detected without binding conflict; broadcast SHA-256 hash puzzle.',
                    },
                },
            },
        }

        try:
            req = urllib.request.Request(
                JEV_URL,
                data=json.dumps(body).encode('utf-8'),
                headers={
                    'Authorization': f'Bearer {key}',
                    'Content-Type': 'application/json',
                    'X-Title': 'netlab-jev-guard',
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                payload = json.loads(resp.read().decode('utf-8'))

            def _extract_choice(entry, valid_keys):
                if isinstance(entry, dict):
                    for subkey in ('probabilities', 'scores', 'values', 'choices', 'result', 'answer'):
                        sub = entry.get(subkey)
                        if isinstance(sub, dict) and sub:
                            num_items = {k: float(v) for k, v in sub.items() if isinstance(v, (int, float))}
                            if num_items:
                                best = max(num_items, key=num_items.get)
                                return best, round(num_items[best], 4)
                    num_items = {
                        k: float(v) for k, v in entry.items()
                        if k in valid_keys and isinstance(v, (int, float))
                    }
                    if num_items:
                        best = max(num_items, key=num_items.get)
                        return best, round(num_items[best], 4)
                return None, 0.0

            answers = payload.get('answers') or payload
            chosen_class, confidence = _extract_choice(
                answers.get('traffic_class', {}),
                {'NORMAL_ARP', 'ARP_SPOOFING', 'ARP_DDOS_FLOOD'},
            )
            chosen_action, _ = _extract_choice(
                answers.get('action', {}),
                {'NO_ACTION', 'RESTORE_BINDINGS', 'ENABLE_ARP_HASH_PUZZLE'},
            )
            if not chosen_class:
                chosen_class, confidence = local_class, local_conf
            if not chosen_action:
                chosen_action = action_map.get(chosen_class, local_action)
            used_model = payload.get('model', model)
        except Exception:
            chosen_class, confidence, chosen_action = local_class, local_conf, local_action
            answers = {'fallback': 'local_deterministic'}
            used_model = f'{model}+fallback'

        decision = {
            'model': used_model,
            'class': chosen_class,
            'confidence': confidence,
            'src_mac': src_mac,
            'claimed_ip': claimed_ip,
            'action': chosen_action,
            'jev_api_raw': answers,
        }
        if chosen_action == 'ENABLE_ARP_HASH_PUZZLE':
            decision['difficulty_k'] = 16 if window.get('arp_pps', 0) <= 500 else 18
        cache[sig] = dict(decision)
        return decision

    # ---- 5. Jev-Guard Actions (RESTORE_BINDINGS & HASH_PUZZLE) -------

    def restore_bindings(self, net, alice, bob, eve, conflicts, install_ovs_drop=True):
        """Execute all 3 steps of RESTORE_BINDINGS within 500 ms:
        1. Pin true neighbor entries on Alice and Bob for every trusted IP (nud permanent).
        2. Send 5 corrective is-at (op=2) frames mapping each conflicted IP back to its true MAC.
        3. Enforce Dynamic ARP Inspection (DAI) port allowlist on the attacker's switch port.
        """
        t0 = time.perf_counter()

        # Step 1: Pin true neighbor entries on Alice and Bob for every trusted IP (batched per host)
        for host in (alice, bob):
            intf = host.defaultIntf().name
            cmds = [
                f'ip neigh replace {ip} lladdr {true_mac} nud permanent dev {intf}'
                for ip, true_mac in TRUSTED_BINDINGS.items()
                if ip != host.IP()
            ]
            host.cmd(' && '.join(cmds))

        # Step 2: Send 5 corrective is-at frames per conflicted IP
        seen_ips = dict.fromkeys(
            c['claimed_ip'] for c in conflicts if c['claimed_ip'] in TRUSTED_BINDINGS
        )
        for claimed_ip in seen_ips:
            true_mac = TRUSTED_BINDINGS[claimed_ip]
            defender, victim = (bob, alice) if claimed_ip == bob.IP() else (alice, bob)
            self.send_corrective_arp(
                defender, claimed_ip, true_mac, victim.IP(), victim.MAC(), copies=5
            )

        # Step 3: Enforce positive DAI port allowlist on offending switch port(s)
        if install_ovs_drop:
            attacker_macs = {
                c.get('eth_src') or c.get('src_mac')
                for c in conflicts
                if c.get('eth_src') or c.get('src_mac')
            } or {eve.MAC().lower()}
            for mac in attacker_macs:
                self.install_eve_spoof_drop_rules(net, attacker_mac=mac)

        return (time.perf_counter() - t0) * 1000.0

    def install_eve_spoof_drop_rules(self, net, attacker_mac=None):
        """Enforce positive Dynamic ARP Inspection (DAI) on the offending switch port:
        allow ARP only when dl_src, arp_sha, and arp_spa match that port's trusted host; drop all other ARP.
        """
        target_mac = (attacker_mac or TRUSTED_BINDINGS.get('10.0.0.2', '00:00:00:00:00:02')).lower()
        ip_by_mac = {mac.lower(): ip for ip, mac in TRUSTED_BINDINGS.items()}
        allowed_ip = ip_by_mac.get(target_mac)

        target_sw, target_port = net.get('s1'), 's1-eth2'
        for sw_name in ('s1', 's2'):
            sw = net.get(sw_name)
            for intf in sw.intfList():
                if intf.link:
                    other = intf.link.intf1 if intf.link.intf2 == intf else intf.link.intf2
                    if other.node.name in ('Alice', 'Bob', 'Eve') and other.MAC().lower() == target_mac:
                        target_sw, target_port = sw, intf.name
                        break

        rules = []
        if allowed_ip:
            rules.append(
                f'priority=210,arp,in_port={target_port},dl_src={target_mac},'
                f'arp_sha={target_mac},arp_spa={allowed_ip},actions=NORMAL'
            )
        rules.append(f'priority=200,arp,in_port={target_port},actions=drop')
        flow_blob = '\\n'.join(rules)
        target_sw.cmd(f'printf "{flow_blob}\\n" | ovs-ofctl add-flows {target_sw.name} -')
        return target_port

    def clear_switch_custom_flows(self, net):
        """Restore default normal switching on s1 and s2."""
        for sw_name in ('s1', 's2'):
            sw = net.get(sw_name)
            sw.cmd(f'ovs-ofctl del-flows {sw_name}')
            sw.cmd(f'ovs-ofctl add-flow {sw_name} "priority=0,actions=NORMAL"')

    def enable_ddos_gate(self, net, bob):
        """Drop unsolved who-has frames at s2 so flood frames receive no is-at reply."""
        s2 = net.get('s2')
        intf = bob.defaultIntf().name
        bob.cmd(f'sysctl -w net.ipv4.conf.{intf}.arp_ignore=8 >/dev/null 2>&1')
        bob.cmd('sysctl -w net.ipv4.conf.all.arp_ignore=8 >/dev/null 2>&1')
        s2.cmd('ovs-ofctl add-flow s2 "priority=180,arp,arp_op=1,actions=drop"')

    def disable_ddos_gate(self, net, bob):
        """Re-enable normal ARP handling on s2 and Bob."""
        s2 = net.get('s2')
        intf = bob.defaultIntf().name
        bob.cmd(f'sysctl -w net.ipv4.conf.{intf}.arp_ignore=0 >/dev/null 2>&1')
        bob.cmd('sysctl -w net.ipv4.conf.all.arp_ignore=0 >/dev/null 2>&1')
        s2.cmd('ovs-ofctl del-flows s2')
        s2.cmd('ovs-ofctl add-flow s2 "priority=0,actions=NORMAL"')

    # ---- 6. Packet capture (tcpdump on hosts) ------------------------

    def pcap_start(self, path, *hosts, bpf='arp or icmp'):
        """Start background tcpdump on each given host."""
        self.pcap_path = os.path.abspath(path)
        self.pcap_hosts = hosts
        for h in hosts:
            tmp = f'/tmp/{h.name}.pcap'
            h.cmd(f'rm -f {tmp}')
            h.cmd(f'tcpdump -n -i {h.defaultIntf()} --immediate-mode -U -w {tmp} "{bpf}" >/dev/null 2>&1 &')
        time.sleep(0.8)
        print('    capturing to', self.pcap_path)

    def pcap_read_live(self, start_counts=None):
        """Read currently captured packets from active tcpdump files after `start_counts` per host."""
        pkts = []
        for h in getattr(self, 'pcap_hosts', ()):
            tmp = f'/tmp/{h.name}.pcap'
            h.cmd('sync')
            if os.path.exists(tmp) and os.path.getsize(tmp) > 24:
                host_pkts = list(rdpcap(tmp))
                offset = start_counts.get(h.name, 0) if start_counts else 0
                for p in host_pkts[offset:]:
                    p._host = h.name
                    pkts.append(p)
        pkts.sort(key=lambda p: float(p.time))
        # O(N) cross-host frame deduplication within 5ms window
        deduped = []
        recent = defaultdict(list)
        for p in pkts:
            raw = bytes(p)
            t = float(p.time)
            hname = getattr(p, '_host', '')
            entries = [e for e in recent[raw] if t - e[0] < 0.005]
            if not any(eh != hname for _, eh in entries):
                deduped.append(p)
                entries.append((t, hname))
            recent[raw] = entries
        return deduped

    def pcap_counts(self):
        """Return current packet count per host capture file."""
        counts = {}
        for h in getattr(self, 'pcap_hosts', ()):
            tmp = f'/tmp/{h.name}.pcap'
            h.cmd('sync')
            if os.path.exists(tmp) and os.path.getsize(tmp) > 24:
                counts[h.name] = len(rdpcap(tmp))
            else:
                counts[h.name] = 0
        return counts

    def pcap_stop(self):
        """Stop tcpdump on each host and combine deduplicated packets into one pcap."""
        time.sleep(0.3)
        for h in self.pcap_hosts:
            h.cmd('pkill -INT tcpdump >/dev/null 2>&1; wait')
        time.sleep(0.2)
        deduped = self.pcap_read_live()
        wrpcap(self.pcap_path, deduped)
        os.chmod(self.pcap_path, 0o644)
        print('    wrote', self.pcap_path)
        print('   ', os.path.getsize(self.pcap_path), 'bytes,', len(deduped), 'packets')
        return deduped


# ---- Host-side Scapy functions (run when as_host calls this file) ----

def who_has(ip):
    """Broadcast ARP who-has for `ip` and return the answered MAC."""
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip)
    answered, _ = srp(packet, timeout=5, verbose=False)
    return answered[0][1].hwsrc if answered else ''


def host_side(argv):
    """Run the requested Scapy action inside a host namespace."""
    if argv[0] == 'get_mac':
        return who_has(argv[1])
    return ''


def self_test():
    """Fast unit self-check for Jev spoofing, DDoS, burst/split-header vectors, and hash puzzle."""
    lab = ArpLab()

    def pkt(eth_src, hwsrc, psrc, pdst, op=1, t=0.0):
        f = Ether(src=eth_src, dst='ff:ff:ff:ff:ff:ff') / ARP(op=op, hwsrc=hwsrc, psrc=psrc, pdst=pdst)
        f.time = t
        return f

    # 1. Normal ARP -> NORMAL_ARP
    w_norm = lab.jev_window([
        pkt('00:00:00:00:00:01', '00:00:00:00:00:01', '10.0.0.1', '10.0.0.3', op=1, t=0.01),
        pkt('00:00:00:00:00:03', '00:00:00:00:00:03', '10.0.0.3', '10.0.0.1', op=2, t=0.02),
    ])
    d_norm = lab.jev_decide(w_norm, call_api=False)
    assert d_norm['class'] == 'NORMAL_ARP' and d_norm['action'] == 'NO_ACTION', d_norm

    # 2. Header-split spoof (ARP.hwsrc == true Bob MAC, Ether.src == Eve MAC) -> ARP_SPOOFING
    w_split = lab.jev_window([
        pkt('00:00:00:00:00:02', '00:00:00:00:00:03', '10.0.0.3', '10.0.0.1', op=2, t=0.10),
    ])
    d_split = lab.jev_decide(w_split, call_api=False)
    assert d_split['class'] == 'ARP_SPOOFING' and d_split['src_mac'] == '00:00:00:00:00:02', d_split

    # 3. Unknown-IP MAC-flapping spoof (10.0.0.99 claimed by two MACs) -> ARP_SPOOFING
    w_flap = lab.jev_window([
        pkt('00:00:00:00:00:aa', '00:00:00:00:00:aa', '10.0.0.99', '10.0.0.1', op=1, t=0.10),
        pkt('00:00:00:00:00:bb', '00:00:00:00:00:bb', '10.0.0.99', '10.0.0.1', op=2, t=0.20),
    ])
    assert lab.jev_decide(w_flap, call_api=False)['class'] == 'ARP_SPOOFING'

    # 4. Micro-burst DDoS (12 packets in 24ms -> 12.0 pps avg, 120.0 pps burst) -> ARP_DDOS_FLOOD
    w_burst = lab.jev_window([
        pkt('00:00:00:00:00:02', '00:00:00:00:00:02', '10.0.0.2', '10.0.0.3', op=1, t=i * 0.002)
        for i in range(12)
    ])
    d_burst = lab.jev_decide(w_burst, call_api=False)
    assert d_burst['class'] == 'ARP_DDOS_FLOOD' and d_burst['src_mac'] == '00:00:00:00:00:02', d_burst

    # 5. Hash puzzle solve + constant-time verify + anti-replay (< 0.3 ms)
    seed_hash = hashlib.sha256(b'jev-test-seed').hexdigest()
    target_s = 42424
    t0 = time.perf_counter()
    x1, x2 = solve_hash_puzzle(seed_hash, target_s, k=16, client_id='10.0.0.1')
    solve_ms = (time.perf_counter() - t0) * 1000.0
    used = set()
    ok1, ver_ms = verify_hash_puzzle(x1, x2, target_s, k=16, seed_hash=seed_hash, seen_nonces=used)
    ok_replay, _ = verify_hash_puzzle(x1, x2, target_s, k=16, seed_hash=seed_hash, seen_nonces=used)
    assert ok1 is True and ok_replay is False and ver_ms < 0.3, (ok1, ok_replay, ver_ms)
    print(f'[SELF-TEST PASS] solve={solve_ms:.2f}ms verify={ver_ms:.4f}ms (<0.3ms) replay_blocked=True')


# ---- Startup ---------------------------------------------------------

def start():
    """Start the Mininet lab and return (net, lab, alice, bob, eve)."""
    if os.geteuid() != 0:
        sys.exit('Run as root: sudo python3 scene1.py')

    os.system('service openvswitch-switch status >/dev/null 2>&1 || service openvswitch-switch start >/dev/null 2>&1')
    lab = ArpLab()
    net = Mininet(topo=lab, switch=OVSBridge, controller=None)
    net.start()
    lab.clear_switch_custom_flows(net)
    return net, lab, net.get('Alice'), net.get('Bob'), net.get('Eve')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == '--self-test':
            self_test()
        else:
            print(host_side(sys.argv[1:]))
        sys.exit(0)

    net, lab, alice, bob, eve = start()
    try:
        CLI(net)
    finally:
        net.stop()
    print('lab done')
