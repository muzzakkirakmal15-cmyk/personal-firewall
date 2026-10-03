# Personal Firewall

A small rule-based personal firewall for Linux, written in Python. It reads filtering rules from a JSON file and can either **monitor** traffic (log what would be allowed or blocked) or **enforce** the rules in the kernel through `iptables`.

## Features
- JSON rules: action, direction (in/out/any), protocol (tcp/udp/icmp), source/destination IP or CIDR, destination port
- First-match-wins evaluation with a default policy per direction
- Monitor mode using scapy packet sniffing, with logging to `firewall.log`
- Enforce mode that builds dedicated `iptables` chains (`PERSONAL_FW_IN`, `PERSONAL_FW_OUT`), allows loopback and established connections, and logs blocked packets
- `--dry-run` to preview iptables commands, and `flush` to cleanly remove everything
- Built-in self test for the rule engine

## Requirements
- Linux, Python 3.8+, root privileges for monitor/enforce
- `pip install scapy` (monitor mode only)

## Usage
```bash
python3 firewall.py test                 # self test, no root needed
sudo python3 firewall.py monitor -r rules.json
sudo python3 firewall.py enforce -r rules.json --dry-run
sudo python3 firewall.py enforce -r rules.json
sudo python3 firewall.py flush           # undo
```

## Rule format
```json
{ "action": "block", "direction": "out", "protocol": "tcp", "port": 23, "dst": "203.0.113.0/24", "comment": "example" }
```

## Sample output

Self test:
```
$ python3 firewall.py test
All self tests passed.
```

Monitor mode (`firewall.log`, from a real run on macOS). Outgoing traffic is allowed, replies to it are recognised as established connections, and unsolicited incoming broadcasts from another device on the LAN are blocked by the default policy:
```
ALLOW out udp   192.168.1.17:1537 -> 192.168.1.1:53 (default policy)
ALLOW in  udp   192.168.1.1:53 -> 192.168.1.17:1537 (established connection)
ALLOW out tcp   192.168.1.17:49247 -> 140.82.114.25:443 (default policy)
ALLOW in  tcp   140.82.114.25:443 -> 192.168.1.17:49247 (established connection)
ALLOW out icmp  192.168.1.17:- -> 142.251.223.238:- (default policy)
ALLOW in  icmp  142.251.223.238:- -> 192.168.1.17:- (established connection)
BLOCK in  udp   192.168.1.3:46129 -> 192.168.1.255:15600 (default policy)
```

Enforce mode, `--dry-run` (generated iptables commands, excerpt):
```
iptables -N PERSONAL_FW_IN
iptables -I INPUT 1 -j PERSONAL_FW_IN
iptables -A PERSONAL_FW_IN -i lo -j ACCEPT
iptables -A PERSONAL_FW_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A PERSONAL_FW_IN -p tcp --dport 22 -j ACCEPT
iptables -A PERSONAL_FW_OUT -p tcp --dport 23 -j DROP
```

## How it works
Packets are matched against rules in order. In enforce mode the same rules are translated into iptables commands so the kernel drops or accepts packets. Monitor mode only observes; it cannot drop packets.

## Limitations
IPv4 only, no GUI, no application-level filtering. Windows (WinAPI/WFP) is not covered.

## Disclaimer
For learning and use on systems you own or administer. Test with `--dry-run` first, and keep console access in case a rule locks you out.
