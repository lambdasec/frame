"""Can the internet reach an EC2 instance on a TCP port? Decided with Z3 over a Terraform root
module's VPC resources, as AWS documents the path (IPv4):

* the instance has a public address: `associate_public_ip_address`, else its subnet's
  `map_public_ip_on_launch` (default false), or an Elastic IP (`aws_eip.instance`,
  `aws_eip_association.instance_id`);
* its subnet's route table sends the client's address to an internet gateway attached to the
  VPC, by longest prefix match (vpc/latest/userguide/route-tables-priority.html). The table is
  the one explicitly associated, else the VPC's main table: `aws_main_route_table_association`
  or `aws_default_route_table` when the configuration sets it, else, for a VPC this
  configuration creates, a table with only the local route ("By default, when you create a
  nondefault VPC, the main route table contains only a local route", subnet-route-tables.html);
* the subnet's network ACL lets the request in and the reply out, rules taken lowest number
  first, the first match deciding, anything unmatched denied (nacl-rules.html). A subnet with no
  ACL in the configuration has its VPC's default ACL, which allows all traffic
  (default-network-acl.html) unless `aws_default_network_acl` sets its rules;
* one of its security groups allows the port from the client's address (an instance with none
  listed gets its VPC's default group, whose only inbound rule admits the group itself).

The question is `exists src, sport: internet(src) and path(src, port, sport)`: the client's
address must be one the internet can send from (frame/iac/addresses.py) and its source port is
the client's to choose. A value the files do not give (a subnet from a data source, a VPC this
configuration does not create, a module output) is a free Z3 variable: the answer is True when
every assignment admits a path, False when none does, else None. An instance without
`subnet_id` lands in the account's default VPC, which the files do not describe: None.
"""

from __future__ import annotations

import ipaddress
import itertools
from typing import Any, Dict, List, Optional

import z3

from .addresses import _reachable
from .engine import Unknown, _z3_const

_fresh = itertools.count()


class _Ctx:
    def __init__(self, related: Dict[str, List[Any]], constraints: List[Any]):
        self.r = related
        self.constraints = constraints
        self.src = z3.BitVec("src", 32)
        self.port = z3.Int("port")
        self.sport = z3.Int("sport")
        self.unknown_vars: List[Any] = []

    def docs(self, rtype: str) -> List[Dict[str, Any]]:
        return [d for d in self.r.get(rtype, []) if isinstance(d, dict)]

    def fresh(self, what: str):
        b = z3.Bool(f"?net:{what}#{next(_fresh)}")
        self.unknown_vars.append(b)
        return b


def _eq(a, b):
    """Equality of two configuration values, an unknown being a Z3 string."""
    if a is None or b is None:
        return z3.BoolVal(False)
    if isinstance(a, Unknown) or isinstance(b, Unknown):
        x = _z3_const(a, z3.StringSort()) if isinstance(a, Unknown) else (z3.StringVal(a) if isinstance(a, str) else None)
        y = _z3_const(b, z3.StringSort()) if isinstance(b, Unknown) else (z3.StringVal(b) if isinstance(b, str) else None)
        if x is None or y is None:
            return z3.BoolVal(False)
        return x == y
    return z3.BoolVal(a == b)


def _member(x, coll, ctx: _Ctx, what: str):
    if isinstance(coll, Unknown):
        return ctx.fresh(what)
    if not isinstance(coll, list):
        return z3.BoolVal(False)
    return z3.Or([_eq(x, c) for c in coll]) if coll else z3.BoolVal(False)


def _bool(v, default: bool, ctx: _Ctx, what: str):
    if v is None:
        return z3.BoolVal(default)
    if isinstance(v, bool):
        return z3.BoolVal(v)
    if isinstance(v, Unknown):
        return ctx.fresh(what)
    return z3.BoolVal(default)


def _contains(cidr, ip, ctx: _Ctx, what: str):
    """src within cidr (canonicalised, as EC2 does for routes and ACL rules)."""
    if isinstance(cidr, Unknown):
        return ctx.fresh(what)
    if not isinstance(cidr, str):
        return z3.BoolVal(False)
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return z3.BoolVal(False)
    if net.version != 4:
        return z3.BoolVal(False)
    if net.prefixlen == 0:
        return z3.BoolVal(True)
    mask = ((1 << net.prefixlen) - 1) << (32 - net.prefixlen)
    return (ip & z3.BitVecVal(mask, 32)) == z3.BitVecVal(int(net.network_address), 32)


def _int(v, ctx: _Ctx, what: str):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return z3.IntVal(v)
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return z3.IntVal(int(v))
    if isinstance(v, Unknown):
        x = z3.Int(f"?net:{what}#{next(_fresh)}")
        ctx.unknown_vars.append(x)
        return x
    return None


def _proto_tcp_port(proto, from_port, to_port, port, ctx: _Ctx, what: str):
    """A rule's protocol and port range admit TCP `port` (-1 / all: every protocol and port)."""
    if isinstance(proto, Unknown):
        return ctx.fresh(what + ".protocol")
    p = str(proto).lower() if proto is not None else ""
    if p in ("-1", "all"):
        return z3.BoolVal(True)
    if p not in ("tcp", "6"):
        return z3.BoolVal(False)
    lo, hi = _int(from_port, ctx, what + ".from"), _int(to_port, ctx, what + ".to")
    if lo is None or hi is None:
        return z3.BoolVal(False)
    return z3.And(lo <= port, port <= hi)


# --- security groups -------------------------------------------------------------------------

def _sg_rules(ctx: _Ctx, g) -> List[Dict[str, Any]]:
    rules = [r for r in (g.get("ingress") or []) if isinstance(r, dict)] if isinstance(g.get("ingress"), list) else []
    out = [(z3.BoolVal(True), r, "cidr_blocks", "protocol") for r in rules]
    if isinstance(g.get("ingress"), Unknown):
        out.append((ctx.fresh("dynamic ingress"), None, None, None))
    for r in ctx.docs("aws_security_group_rule"):
        if r.get("type") == "ingress":
            out.append((_eq(r.get("security_group_id"), g.get("id")), r, "cidr_blocks", "protocol"))
    for r in ctx.docs("aws_vpc_security_group_ingress_rule"):
        out.append((_eq(r.get("security_group_id"), g.get("id")), r, "cidr_ipv4", "ip_protocol"))
    return out


def _sg_allows(ctx: _Ctx, g, port):
    terms = []
    for applies, r, cidr_key, proto_key in _sg_rules(ctx, g):
        if r is None:
            terms.append(applies)
            continue
        cidrs = r.get(cidr_key)
        cidrs = [cidrs] if cidr_key == "cidr_ipv4" else cidrs
        if isinstance(cidrs, Unknown):
            src_ok = ctx.fresh("sg cidrs")
        elif isinstance(cidrs, list):
            src_ok = z3.Or([_sg_cidr(c, ctx) for c in cidrs]) if cidrs else z3.BoolVal(False)
        else:
            src_ok = z3.BoolVal(False)
        terms.append(z3.And(applies, src_ok,
                            _proto_tcp_port(r.get(proto_key), r.get("from_port"), r.get("to_port"), port, ctx, "sg")))
    return z3.Or(terms) if terms else z3.BoolVal(False)


def _sg_cidr(cidr, ctx: _Ctx):
    """A security group CIDR with host bits set is not decided (frame/iac/addresses.py)."""
    if isinstance(cidr, str):
        try:
            ipaddress.ip_network(cidr.strip(), strict=True)
        except ValueError:
            return ctx.fresh(f"cidr {cidr}") if "/" in cidr else z3.BoolVal(False)
    return _contains(cidr, ctx.src, ctx, "sg cidr")


def _instance_sgs_allow(ctx: _Ctx, inst, vpc_of_subnet, port):
    ids = inst.get("vpc_security_group_ids")
    if ids is None:
        ids = inst.get("security_groups")
    if ids is None or ids == []:
        # the VPC's default group: rules from aws_default_security_group, else self-only
        terms = []
        for d in ctx.docs("aws_default_security_group"):
            terms.append(z3.And(_eq(d.get("vpc_id"), vpc_of_subnet), _sg_allows(ctx, d, port)))
        created = _vpc_created(ctx, vpc_of_subnet)
        managed = z3.Or([_eq(d.get("vpc_id"), vpc_of_subnet) for d in ctx.docs("aws_default_security_group")]) \
            if ctx.docs("aws_default_security_group") else z3.BoolVal(False)
        return z3.Or(z3.Or(terms) if terms else z3.BoolVal(False),
                     z3.And(z3.Not(managed), z3.Not(created), ctx.fresh("the VPC's default security group")))
    if isinstance(ids, Unknown):
        return ctx.fresh("security groups")
    terms = []
    groups = ctx.docs("aws_security_group")
    for sid in ids:
        known = [z3.And(_eq(sid, g.get("id")), _sg_allows(ctx, g, port)) for g in groups]
        outside = z3.And([z3.Not(_eq(sid, g.get("id"))) for g in groups]) if groups else z3.BoolVal(True)
        terms.append(z3.Or(z3.Or(known) if known else z3.BoolVal(False),
                           z3.And(outside, ctx.fresh("a security group outside the configuration"))))
    return z3.Or(terms) if terms else z3.BoolVal(False)


# --- routes ----------------------------------------------------------------------------------

def _vpc_created(ctx: _Ctx, vpc_id):
    vpcs = ctx.docs("aws_vpc")
    return z3.Or([_eq(vpc_id, v.get("id")) for v in vpcs]) if vpcs else z3.BoolVal(False)


def _igw_target(ctx: _Ctx, target, vpc_id):
    gws = ctx.docs("aws_internet_gateway")
    terms = []
    for g in gws:
        attached = z3.Or(_eq(g.get("vpc_id"), vpc_id),
                         z3.Or([z3.And(_eq(a.get("internet_gateway_id"), g.get("id")), _eq(a.get("vpc_id"), vpc_id))
                                for a in ctx.docs("aws_internet_gateway_attachment")] or [z3.BoolVal(False)]))
        terms.append(z3.And(_eq(target, g.get("id")), attached))
    if isinstance(target, Unknown):
        outside = z3.And([z3.Not(_eq(target, g.get("id"))) for g in gws]) if gws else z3.BoolVal(True)
        terms.append(z3.And(outside, ctx.fresh("a gateway outside the configuration")))
    return z3.Or(terms) if terms else z3.BoolVal(False)


def _routes_to_igw(ctx: _Ctx, routes, vpc_id, vpc_cidr):
    """Longest prefix match over (cidr, target, applies) routes, plus the local route."""
    entries = [(vpc_cidr, "local", z3.BoolVal(True))] + routes
    known, unknown = [], []
    for cidr, target, applies in entries:
        if isinstance(cidr, str):
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                continue
            if net.version == 4:
                known.append((net.prefixlen, cidr, target, applies))
        elif cidr is not None:
            unknown.append(cidr)
    if unknown:
        return ctx.fresh("a route whose destination is not known")
    decided = z3.BoolVal(False)                     # no route: the packet is dropped
    for _, cidr, target, applies in sorted(known, key=lambda t: t[0]):
        hit = z3.And(applies, _contains(cidr, ctx.src, ctx, "route"))
        via_igw = z3.BoolVal(False) if target == "local" else _igw_target(ctx, target, vpc_id)
        decided = z3.If(hit, via_igw, decided)
    return decided


def _table_routes(ctx: _Ctx, table) -> List:
    routes = []
    inline = table.get("route")
    if isinstance(inline, Unknown):
        routes.append((Unknown("route", "route"), None, z3.BoolVal(True)))
    elif isinstance(inline, list):
        for r in inline:
            if isinstance(r, dict) and r.get("cidr_block") is not None:
                routes.append((r.get("cidr_block"), r.get("gateway_id"), z3.BoolVal(True)))
    for r in ctx.docs("aws_route"):
        if r.get("destination_cidr_block") is not None:
            routes.append((r.get("destination_cidr_block"), r.get("gateway_id"), _eq(r.get("route_table_id"), table.get("id"))))
    return routes


def _subnet_routes_to_igw(ctx: _Ctx, s):
    vpc_id = s.get("vpc_id")
    vpcs = ctx.docs("aws_vpc")
    vpc_cidr_terms = [(v, _eq(vpc_id, v.get("id"))) for v in vpcs]
    tables = ctx.docs("aws_route_table")
    assocs = ctx.docs("aws_route_table_association")
    explicit, any_explicit = [], []
    for a in assocs:
        mine = _eq(a.get("subnet_id"), s.get("id"))
        any_explicit.append(mine)
        for t in tables:
            explicit.append((z3.And(mine, _eq(a.get("route_table_id"), t.get("id"))), t))
        outside = z3.And([z3.Not(_eq(a.get("route_table_id"), t.get("id"))) for t in tables]) if tables else z3.BoolVal(True)
        explicit.append((z3.And(mine, outside), None))
    implicit = z3.Not(z3.Or(any_explicit)) if any_explicit else z3.BoolVal(True)

    def via(table):
        if table is None:
            return ctx.fresh("a route table outside the configuration")
        out = []
        for v, in_vpc in vpc_cidr_terms:
            out.append(z3.And(in_vpc, _routes_to_igw(ctx, _table_routes(ctx, table), vpc_id, v.get("cidr_block"))))
        if not vpc_cidr_terms:
            return ctx.fresh("the subnet's VPC")
        return z3.Or(out + [z3.And(z3.Not(_vpc_created(ctx, vpc_id)), ctx.fresh("the subnet's VPC"))])

    paths = [z3.And(cond, via(t)) for cond, t in explicit]
    # the main table: set by this configuration, else (a VPC it creates) only the local route
    mains = []
    for m in ctx.docs("aws_main_route_table_association"):
        for t in tables:
            mains.append((z3.And(_eq(m.get("vpc_id"), vpc_id), _eq(m.get("route_table_id"), t.get("id"))), t))
    for d in ctx.docs("aws_default_route_table"):
        ref = d.get("default_route_table_id")
        owner = Unknown(ref.key.rsplit(".", 1)[0] + ".id") if isinstance(ref, Unknown) else None
        mains.append((_eq(owner, vpc_id) if owner else ctx.fresh("default route table"), d))
    main_set = z3.Or([c for c, _ in mains]) if mains else z3.BoolVal(False)
    main_paths = [z3.And(c, via(t)) for c, t in mains]
    unset = z3.And(z3.Not(main_set), z3.Not(_vpc_created(ctx, vpc_id)), ctx.fresh("the VPC's main route table"))
    paths.append(z3.And(implicit, z3.Or(main_paths + [unset])))
    return z3.Or(paths)


# --- network ACLs ----------------------------------------------------------------------------

def _acl_rules(ctx: _Ctx, acl, egress: bool):
    rules = []
    inline = acl.get("egress" if egress else "ingress")
    if isinstance(inline, Unknown):
        return None
    for r in inline or []:
        if isinstance(r, dict):
            rules.append((r.get("rule_no"), r.get("action"), r.get("protocol"), r.get("from_port"), r.get("to_port"),
                          r.get("cidr_block"), z3.BoolVal(True)))
    for r in ctx.docs("aws_network_acl_rule"):
        if bool(r.get("egress", False)) == egress:
            rules.append((r.get("rule_number"), r.get("rule_action"), r.get("protocol"), r.get("from_port"),
                          r.get("to_port"), r.get("cidr_block"), _eq(r.get("network_acl_id"), acl.get("id"))))
    return rules


def _acl_allows(ctx: _Ctx, acl, egress: bool, port):
    rules = _acl_rules(ctx, acl, egress)
    if rules is None or any(not isinstance(r[0], int) or isinstance(r[0], bool) for r in rules):
        return ctx.fresh("a network ACL rule")
    decided = z3.BoolVal(False)                     # the * rule: deny
    for number, action, proto, lo, hi, cidr, applies in sorted(rules, key=lambda r: r[0], reverse=True):
        match = z3.And(applies, _contains(cidr, ctx.src, ctx, "acl"),
                       _proto_tcp_port(proto, lo, hi, port, ctx, "acl"))
        if isinstance(action, Unknown):
            allow = ctx.fresh("acl action")
        else:
            allow = z3.BoolVal(str(action).lower() == "allow")
        decided = z3.If(match, allow, decided)
    return decided


def _subnet_acl_allows(ctx: _Ctx, s, port):
    acls = ctx.docs("aws_network_acl")
    terms, any_acl = [], []
    for a in acls:
        member = z3.Or(_member(s.get("id"), a.get("subnet_ids"), ctx, "acl subnets"),
                       z3.Or([z3.And(_eq(x.get("subnet_id"), s.get("id")), _eq(x.get("network_acl_id"), a.get("id")))
                              for x in ctx.docs("aws_network_acl_association")] or [z3.BoolVal(False)]))
        any_acl.append(member)
        terms.append(z3.And(member, _acl_allows(ctx, a, False, port), _acl_allows(ctx, a, True, ctx.sport)))
    none = z3.Not(z3.Or(any_acl)) if any_acl else z3.BoolVal(True)
    defaults = ctx.docs("aws_default_network_acl")
    managed = []
    for d in defaults:
        ref = d.get("default_network_acl_id")
        owner = Unknown(ref.key.rsplit(".", 1)[0] + ".id") if isinstance(ref, Unknown) else None
        same = _eq(owner, s.get("vpc_id")) if owner else ctx.fresh("default network ACL")
        managed.append(same)
        terms.append(z3.And(none, same, _acl_allows(ctx, d, False, port), _acl_allows(ctx, d, True, ctx.sport)))
    unmanaged = z3.Not(z3.Or(managed)) if managed else z3.BoolVal(True)
    created = _vpc_created(ctx, s.get("vpc_id"))
    # an unmanaged default ACL allows all traffic in a VPC this configuration creates
    terms.append(z3.And(none, unmanaged, z3.Or(created, ctx.fresh("the VPC's default network ACL"))))
    return z3.Or(terms)


# --- the instance ------------------------------------------------------------------------------

def _path(ctx: _Ctx, inst, s, port):
    public = z3.Or(
        _bool(inst.get("associate_public_ip_address"), False, ctx, "public address")
        if inst.get("associate_public_ip_address") is not None
        else _bool(s.get("map_public_ip_on_launch"), False, ctx, "map public address"),
        z3.Or([_eq(e.get("instance"), inst.get("id")) for e in ctx.docs("aws_eip")] or [z3.BoolVal(False)]),
        z3.Or([_eq(a.get("instance_id"), inst.get("id")) for a in ctx.docs("aws_eip_association")]
              or [z3.BoolVal(False)]))
    if inst.get("network_interface"):
        public = z3.Or(public, ctx.fresh("an attached network interface"))
    return z3.And(public, _subnet_routes_to_igw(ctx, s), _subnet_acl_allows(ctx, s, port),
                  _instance_sgs_allow(ctx, inst, s.get("vpc_id"), port))


def instance_reach(inst: Dict[str, Any], related: Dict[str, List[Any]], constraints: List[Any],
                   port: int) -> Optional[bool]:
    """True: the internet can reach `port` on the instance whatever the unknowns are; False: it
    cannot; None: it depends on values the files do not give."""
    if inst.get("subnet_id") is None:
        return None                                  # the default VPC: not in the files
    ctx = _Ctx(related, constraints)
    p = z3.IntVal(port)
    terms = []
    subnets = ctx.docs("aws_subnet")
    for s in subnets:
        terms.append(z3.And(_eq(inst.get("subnet_id"), s.get("id")), _path(ctx, inst, s, p)))
    outside = z3.And([z3.Not(_eq(inst.get("subnet_id"), s.get("id"))) for s in subnets]) if subnets else z3.BoolVal(True)
    terms.append(z3.And(outside, ctx.fresh("a subnet outside the configuration")))
    body = z3.And(_reachable(ctx.src, 32), ctx.sport >= 0, ctx.sport <= 65535, z3.Or(terms))
    s = z3.Solver()
    s.set("timeout", 10000)
    s.add(*constraints)
    s.add(body)
    if s.check() == z3.unsat:
        return False
    s = z3.Solver()
    s.set("timeout", 10000)
    s.add(*constraints)
    s.add(z3.Not(z3.Exists([ctx.src, ctx.sport], body)))
    return True if s.check() == z3.unsat else None


__all__ = ["instance_reach"]
