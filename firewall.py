#!/usr/bin/env python3
"""
Personal Firewall - rule-based packet filtering for Linux.

Two modes:
  monitor  Sniff live traffic (scapy), evaluate each packet against rules.json
           and log what WOULD be allowed/blocked. Does not drop packets.
  enforce  Translate rules.json into iptables rules (custom chains) so the
           kernel actually filters traffic. Requires root.

Usage:
  sudo python3 firewall.py monitor [-r rules.json] [-i eth0]
  sudo python3 firewall.py enforce [-r rules.json] [--dry-run]
  sudo python3 firewall.py flush
  python3 firewall.py test        # run the built-in rule-engine self test

Use only on machines you own or administer.
"""
import argparse
import ipaddress
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

LOG_FILE = "firewall.log"
CHAIN_IN = "PERSONAL_FW_IN"
CHAIN_OUT = "PERSONAL_FW_OUT"
VALID_ACTIONS = {"allow", "block"}
VALID_DIRS = {"in", "out", "any"}
VALID_PROTOS = {"tcp", "udp", "icmp", "any"}


# --------------------------------------------------------------------------
# Rule engine (pure Python, no root or scapy needed)
# --------------------------------------------------------------------------
@dataclass
class Rule:
    action: str
    direction: str = "any"
    protocol: str = "any"
    src: Optional[str] = None      # IP or CIDR
    dst: Optional[str] = None      # IP or CIDR
    port: Optional[int] = None     # destination port (tcp/udp only)
    comment: str = ""

    def validate(self):
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"bad action: {self.action}")
        if self.direction not in VALID_DIRS:
            raise ValueError(f"bad direction: {self.direction}")
        if self.protocol not in VALID_PROTOS:
            raise ValueError(f"bad protocol: {self.protocol}")
        if self.port is not None:
            if self.protocol not in ("tcp", "udp"):
                raise ValueError("port requires protocol tcp or udp")
            if not 0 < int(self.port) < 65536:
                raise ValueError(f"bad port: {self.port}")
        for ip in (self.src, self.dst):
            if ip:
                ipaddress.ip_network(ip, strict=False)

    def matches(self, pkt: "Packet") -> bool:
        if self.direction != "any" and self.direction != pkt.direction:
            return False
        if self.protocol != "any" and self.protocol != pkt.protocol:
            return False
        if self.src and not _ip_in(pkt.src, self.src):
            return False
        if self.dst and not _ip_in(pkt.dst, self.dst):
            return False
        if self.port is not None and self.port != pkt.dport:
            return False
        return True


@dataclass
class Packet:
    direction: str            # "in" or "out"
    protocol: str             # tcp / udp / icmp / other
    src: str
    dst: str
    sport: Optional[int] = None
    dport: Optional[int] = None


def _ip_in(ip: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


class RuleSet:
    def __init__(self, rules: List[Rule], default_in: str, default_out: str):
        self.rules = rules
        self.default = {"in": default_in, "out": default_out}

    @classmethod
    def load(cls, path: str) -> "RuleSet":
        with open(path) as f:
            data = json.load(f)
        policy = data.get("default_policy", {})
        rules = []
        for raw in data.get("rules", []):
            r = Rule(
                action=raw["action"],
                direction=raw.get("direction", "any"),
                protocol=raw.get("protocol", "any"),
                src=raw.get("src"),
                dst=raw.get("dst"),
                port=raw.get("port"),
                comment=raw.get("comment", ""),
            )
            r.validate()
            rules.append(r)
        d_in, d_out = policy.get("in", "block"), policy.get("out", "allow")
        for d in (d_in, d_out):
            if d not in VALID_ACTIONS:
                raise ValueError(f"bad default policy: {d}")
        return cls(rules, d_in, d_out)

    def evaluate(self, pkt: Packet):
        """First matching rule wins; otherwise the default policy applies."""
        for rule in self.rules:
            if rule.matches(pkt):
                return rule.action, rule.comment or "rule match"
        return self.default[pkt.direction], "default policy"


class ConnTracker:
    """Remembers allowed outgoing flows so their replies count as 'established'
    (mirrors the conntrack ESTABLISHED rule used in enforce mode)."""

    def __init__(self, timeout: float = 120.0):
        self.timeout = timeout
        self.flows = {}

    def record(self, pkt: Packet, now: Optional[float] = None):
        now = time.time() if now is None else now
        self.flows[(pkt.protocol, pkt.src, pkt.sport, pkt.dst, pkt.dport)] = now
        if len(self.flows) > 5000:  # prune stale entries
            self.flows = {k: t for k, t in self.flows.items() if now - t < self.timeout}

    def is_reply(self, pkt: Packet, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        seen = self.flows.get((pkt.protocol, pkt.dst, pkt.dport, pkt.src, pkt.sport))
        if seen is None or now - seen > self.timeout:
            return False
        self.flows[(pkt.protocol, pkt.dst, pkt.dport, pkt.src, pkt.sport)] = now
        return True


# --------------------------------------------------------------------------
# Monitor mode (scapy)
# --------------------------------------------------------------------------
def local_addresses():
    addrs = {"127.0.0.1"}
    try:
        from scapy.all import get_if_addr, get_if_list
        for iface in get_if_list():
            addrs.add(get_if_addr(iface))
    except Exception:
        pass
    return addrs


def run_monitor(rules: RuleSet, iface: Optional[str]):
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        sys.exit("scapy is required for monitor mode: pip install scapy")

    local = local_addresses()
    tracker = ConnTracker()
    log = logging.getLogger("fw")

    def handle(p):
        if IP not in p:
            return
        ip = p[IP]
        direction = "out" if ip.src in local else "in"
        proto, sport, dport = "other", None, None
        if TCP in p:
            proto, sport, dport = "tcp", p[TCP].sport, p[TCP].dport
        elif UDP in p:
            proto, sport, dport = "udp", p[UDP].sport, p[UDP].dport
        elif ICMP in p:
            proto = "icmp"
        pkt = Packet(direction, proto, ip.src, ip.dst, sport, dport)
        if direction == "in" and tracker.is_reply(pkt):
            action, why = "allow", "established connection"
        else:
            action, why = rules.evaluate(pkt)
            if direction == "out" and action == "allow":
                tracker.record(pkt)
        log.info("%-5s %-3s %-5s %s:%s -> %s:%s (%s)", action.upper(), direction,
                 proto, ip.src, sport or "-", ip.dst, dport or "-", why)

    print("Monitoring... press Ctrl+C to stop. Log:", LOG_FILE)
    sniff(prn=handle, store=False, iface=iface)


# --------------------------------------------------------------------------
# Enforce mode (iptables)
# --------------------------------------------------------------------------
def build_iptables_commands(rules: RuleSet) -> List[List[str]]:
    cmds = []
    for chain, parent in ((CHAIN_IN, "INPUT"), (CHAIN_OUT, "OUTPUT")):
        cmds.append(["iptables", "-N", chain])
        cmds.append(["iptables", "-I", parent, "1", "-j", chain])

    # Always allow loopback; allow replies to connections we started.
    cmds.append(["iptables", "-A", CHAIN_IN, "-i", "lo", "-j", "ACCEPT"])
    cmds.append(["iptables", "-A", CHAIN_OUT, "-o", "lo", "-j", "ACCEPT"])
    cmds.append(["iptables", "-A", CHAIN_IN, "-m", "conntrack",
                 "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    for r in rules.rules:
        chains = {"in": [CHAIN_IN], "out": [CHAIN_OUT], "any": [CHAIN_IN, CHAIN_OUT]}[r.direction]
        for chain in chains:
            base = ["iptables", "-A", chain]
            if r.protocol != "any":
                base += ["-p", r.protocol]
            if r.src:
                base += ["-s", r.src]
            if r.dst:
                base += ["-d", r.dst]
            if r.port is not None:
                base += ["--dport", str(r.port)]
            if r.action == "block":
                cmds.append(base + ["-m", "limit", "--limit", "5/min",
                                    "-j", "LOG", "--log-prefix", "PFW-BLOCK: "])
                cmds.append(base + ["-j", "DROP"])
            else:
                cmds.append(base + ["-j", "ACCEPT"])

    for chain, key in ((CHAIN_IN, "in"), (CHAIN_OUT, "out")):
        if rules.default[key] == "block":
            cmds.append(["iptables", "-A", chain, "-m", "limit", "--limit", "5/min",
                         "-j", "LOG", "--log-prefix", "PFW-BLOCK: "])
            cmds.append(["iptables", "-A", chain, "-j", "DROP"])
        else:
            cmds.append(["iptables", "-A", chain, "-j", "ACCEPT"])
    return cmds


def run_cmds(cmds, dry_run=False, ignore_errors=False):
    for c in cmds:
        print(" ".join(c))
        if dry_run:
            continue
        res = subprocess.run(c, capture_output=True, text=True)
        if res.returncode != 0 and not ignore_errors:
            sys.exit(f"command failed: {res.stderr.strip()}\nRun 'flush' to clean up.")


def flush():
    cmds = []
    for chain, parent in ((CHAIN_IN, "INPUT"), (CHAIN_OUT, "OUTPUT")):
        cmds += [["iptables", "-D", parent, "-j", chain],
                 ["iptables", "-F", chain],
                 ["iptables", "-X", chain]]
    run_cmds(cmds, ignore_errors=True)
    print("Firewall chains removed.")


# --------------------------------------------------------------------------
# Self test
# --------------------------------------------------------------------------
def self_test():
    rs = RuleSet(
        [Rule("allow", "in", "tcp", port=22, comment="ssh"),
         Rule("block", "out", "any", dst="203.0.113.0/24", comment="bad net"),
         Rule("block", "any", "icmp", comment="no ping")],
        default_in="block", default_out="allow")
    cases = [
        (Packet("in", "tcp", "1.2.3.4", "10.0.0.5", 5555, 22), "allow"),
        (Packet("in", "tcp", "1.2.3.4", "10.0.0.5", 5555, 80), "block"),
        (Packet("out", "udp", "10.0.0.5", "203.0.113.9", 4000, 53), "block"),
        (Packet("out", "tcp", "10.0.0.5", "8.8.8.8", 4000, 443), "allow"),
        (Packet("out", "icmp", "10.0.0.5", "8.8.8.8"), "block"),
    ]
    for pkt, expected in cases:
        got, _ = rs.evaluate(pkt)
        assert got == expected, (pkt, got, expected)
    assert len(build_iptables_commands(rs)) > 10

    # connection tracking: reply to an allowed outgoing flow is 'established'
    t = ConnTracker()
    out = Packet("out", "tcp", "10.0.0.5", "8.8.8.8", 4000, 443)
    reply = Packet("in", "tcp", "8.8.8.8", "10.0.0.5", 443, 4000)
    stranger = Packet("in", "tcp", "8.8.8.8", "10.0.0.5", 443, 4001)
    assert not t.is_reply(reply, now=0)
    t.record(out, now=0)
    assert t.is_reply(reply, now=10)
    assert not t.is_reply(stranger, now=10)
    assert not t.is_reply(reply, now=500)  # timed out
    print("All self tests passed.")


def main():
    ap = argparse.ArgumentParser(description="Personal firewall")
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("monitor", "enforce"):
        p = sub.add_parser(name)
        p.add_argument("-r", "--rules", default="rules.json")
        if name == "monitor":
            p.add_argument("-i", "--iface")
        else:
            p.add_argument("--dry-run", action="store_true")
    sub.add_parser("flush")
    sub.add_parser("test")
    args = ap.parse_args()

    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format="%(asctime)s %(message)s")

    if args.mode == "test":
        return self_test()
    if args.mode == "flush":
        return flush()
    rules = RuleSet.load(args.rules)
    if args.mode == "monitor":
        run_monitor(rules, args.iface)
    else:
        run_cmds(build_iptables_commands(rules), dry_run=args.dry_run)


if __name__ == "__main__":
    main()
