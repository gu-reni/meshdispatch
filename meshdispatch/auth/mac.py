"""Optional LAN MAC-address whitelist check.

Only meaningful when client and server share a broadcast domain: the server
reads the client's MAC from its ARP/neighbour table (``ip neigh``).  Public
traffic is *always* skipped, because once a packet crosses a router the server
can only see an IP address (see DESIGN.md, "On MAC-address binding").
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Callable

# iproute2: "<ip> dev <if> lladdr <mac> <state>"
# Linux   : "<ip> dev <if> lladdr <mac> REACHABLE/STALE/DELAY ..."
_MAC_LINE = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{17})"
)
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")

# Private/loopback/link-local ranges that indicate an on-LAN client.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip: str) -> bool:
    """True for loopback, link-local, and RFC1918/ULA addresses."""
    if not isinstance(ip, str) or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


ArpReader = Callable[[], str]


def default_arp_reader(command: str = "ip neigh") -> ArpReader:
    """Return an ARP reader that shells out to ``ip neigh``."""

    def read() -> str:
        try:
            proc = subprocess.run(
                command.split(), capture_output=True, text=True, timeout=5
            )
            return proc.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    return read


def parse_arp_table(output: str) -> dict[str, str]:
    """Map ip -> mac from ``ip neigh`` output."""
    table: dict[str, str] = {}
    for line in (output or "").splitlines():
        m = _MAC_LINE.match(line.strip())
        if m:
            table[m.group("ip")] = m.group("mac").lower()
    return table


def normalize_mac(mac: str) -> str | None:
    if not isinstance(mac, str):
        return None
    mac = mac.strip().lower().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def check_mac_whitelist(
    principal: str,
    client_ip: str,
    whitelist: dict[str, list[str]],
    *,
    arp_reader: ArpReader | None = None,
) -> bool:
    """Return True iff the client passes the (optional) MAC whitelist.

    Public/non-LAN addresses always pass (the check is skipped -- MAC binding is
    impossible over the internet).  For LAN addresses, the client's MAC is read
    from the ARP table and compared against the principal's whitelist; a match
    (case-normalised, constant-time) passes.
    """
    if not whitelist:
        return True
    if not is_private_ip(client_ip):
        return True  # public: skip
    allowed = [normalize_mac(m) for m in whitelist.get(principal, [])]
    allowed = [m for m in allowed if m is not None]
    if not allowed:
        return False
    reader = arp_reader or default_arp_reader()
    table = parse_arp_table(reader())
    observed = normalize_mac(table.get(client_ip, ""))
    if observed is None:
        return False
    import hmac

    for candidate in allowed:
        if hmac.compare_digest(observed, candidate):
            return True
    return False


__all__ = [
    "is_private_ip",
    "parse_arp_table",
    "normalize_mac",
    "check_mac_whitelist",
    "default_arp_reader",
]
