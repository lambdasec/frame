"""Can an address range be reached from the internet? Decided with Z3 over bit-vectors.

An address is reachable when the most specific block of IANA's special-purpose registries that
contains it says so (`data/special-addresses.toml`); outside every block an IPv4 address is
reachable (multicast aside) and an IPv6 address only inside the global unicast space. A CIDR may
let the internet in when some address in it is reachable:

    exists ip. (ip & mask) == network  and  reachable(ip)

with `reachable` the registry as nested if-then-else from the most specific block out. A CIDR
Terraform or AWS would refuse is not a range, so it lets nothing in.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import List, Tuple

import z3

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

DATA = Path(__file__).parent / "data" / "special-addresses.toml"


@lru_cache(maxsize=1)
def _registry():
    data = tomllib.loads(DATA.read_text(encoding="utf-8"))
    out = {}
    for family, bits in (("ipv4", 32), ("ipv6", 128)):
        section = data[family]
        blocks: List[Tuple[int, int, bool]] = []
        for b in section["blocks"]:
            net = ipaddress.ip_network(b["cidr"], strict=True)
            blocks.append((net.prefixlen, int(net.network_address), bool(b["reachable"])))
        blocks.sort(key=lambda t: t[0])            # least specific first; the formula nests outward
        out[bits] = (bool(section["outside"]), blocks)
    return out


def _within(ip, bits: int, prefixlen: int, network: int):
    if prefixlen == 0:
        return z3.BoolVal(True)
    mask = ((1 << prefixlen) - 1) << (bits - prefixlen)
    return (ip & z3.BitVecVal(mask, bits)) == z3.BitVecVal(network, bits)


def _reachable(ip, bits: int):
    outside, blocks = _registry()[bits]
    formula = z3.BoolVal(outside)
    for prefixlen, network, flag in blocks:        # a more specific block wraps the less specific
        formula = z3.If(_within(ip, bits, prefixlen, network), z3.BoolVal(flag), formula)
    return formula


@lru_cache(maxsize=4096)
def may_reach(cidr: str, family: int = 0):
    """Does `cidr` (an IPv4 or IPv6 CIDR, or a single address; of IP version `family` when
    that is 4 or 6) contain an address the internet can send from? None for a CIDR with host
    bits set (`192.168.1.0/0`): whether the service rejects it or takes its network
    (0.0.0.0/0) is not documented, so it is not decided."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False
    if family and net.version != family:
        return False
    try:
        ipaddress.ip_network(cidr.strip(), strict=True)
    except ValueError:
        return None
    bits = 32 if net.version == 4 else 128
    ip = z3.BitVec("ip", bits)
    s = z3.Solver()
    s.add(_within(ip, bits, net.prefixlen, int(net.network_address)), _reachable(ip, bits))
    return s.check() == z3.sat


__all__ = ["may_reach"]
