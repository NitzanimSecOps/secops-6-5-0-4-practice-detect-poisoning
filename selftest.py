"""selftest.py — run your switch locally and watch it handle ARP.

    python selftest.py          # run the example scenarios below
    VS Code: open this file, press F5 (Run and Debug), set breakpoints in switch.py.

No real network is needed: this fakes the raw sockets so your Switch constructs anywhere.
It builds ARP frames, sends them into your switch with send(), and prints what your code
printed and which ports it forwarded to. Edit the scenarios at the bottom, or call send()
with your own frames.
"""
import socket
import struct

from switch import Switch   # your solution (bring switch.py + ethernet.py + your ARP parser arp.py)

PORTS = ["p_gw", "p_victim", "p_attacker"]   # referenced by index (0,1,2), matching this order

# (ip, mac) hosts to play with
GW = ("10.0.0.1", "02:00:00:00:00:01")
VICTIM = ("10.0.0.2", "02:00:00:00:00:02")
ATTACKER = ("10.0.0.66", "02:00:00:00:00:66")
BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"
ARP_REQUEST, ARP_REPLY = 1, 2


def _mac(m):
    return bytes.fromhex(m.replace(":", ""))


def _ip(ip):
    return bytes(int(o) for o in ip.split("."))


def arp_frame(opcode, sender, target_ip, *, eth_dst=BROADCAST, eth_src=None, target_mac=ZERO):
    """Build an Ethernet+ARP frame. `sender` is an (ip, mac) tuple. `eth_src` defaults to the
    ARP sender's MAC — pass a different one to forge the Ethernet header."""
    sender_ip, sender_mac = sender
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, opcode,
                      _mac(sender_mac), _ip(sender_ip), _mac(target_mac), _ip(target_ip))
    eth = _mac(eth_dst) + _mac(eth_src or sender_mac) + struct.pack("!H", 0x0806)
    return eth + arp


class _FakeSock:
    def __init__(self, *a, **k):
        self.sent = []

    def bind(self, *a, **k):
        pass

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def setsockopt(self, *a, **k):
        pass

    def close(self):
        pass


def new_switch():
    """A Switch whose ports use fake sockets, so it runs with no real interfaces."""
    for name, val in (("AF_PACKET", 17), ("SOCK_RAW", 3)):
        if not hasattr(socket, name):
            setattr(socket, name, val)
    if not hasattr(socket, "htons"):
        socket.htons = lambda x: x
    socket.socket = lambda *a, **k: _FakeSock()
    return Switch(PORTS)


def send(sw, frame, port_index, label=""):
    """Send one frame into the switch on a port (by index), and show what happened."""
    before = [len(p.sock.sent) for p in sw.ports]
    print(f"\n>>> {label or 'send'}  (in on port {port_index} = {PORTS[port_index]})")
    sw._process_frame(frame, sw.ports[port_index])     # <-- your code runs here; breakpoint it
    forwarded = [PORTS[i] for i, p in enumerate(sw.ports) if len(p.sock.sent) > before[i]]
    print(f"    forwarded to: {forwarded or 'nobody (dropped)'}")


if __name__ == "__main__":
    sw = new_switch()

    # 1) a normal request — the switch should remember the question and forward it.
    send(sw, arp_frame(ARP_REQUEST, VICTIM, GW[0]), 1, "victim asks 'who has the gateway?'")

    # 2) the gateway's reply to that request — solicited, so NOT poisoning.
    send(sw, arp_frame(ARP_REPLY, GW, VICTIM[0], eth_dst=VICTIM[1]), 0,
         "gateway replies (solicited)")

    # 3) a reply nobody asked for — the poisoning your switch must catch.
    send(sw, arp_frame(ARP_REPLY, (GW[0], ATTACKER[1]), VICTIM[0], eth_dst=VICTIM[1]), 2,
         "attacker forges a gateway reply (unsolicited)")

    print("\nExpected: #1 and #2 forward with no alert; #3 prints ARP-POISONING and is dropped.")
    print("Edit the scenarios above, or call send(sw, arp_frame(...), 0, 'label').")
