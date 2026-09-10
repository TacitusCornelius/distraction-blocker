"""Privileged network enforcement: nftables UID fence and SafeSearch resolver.

This module owns exactly two kernel-side resources and one local resolver:

* the nftables table ``inet distraction_blocker`` (identified by
  :data:`OWNERSHIP_COMMENT`; foreign tables with the same name are collisions
  and are never touched),
* the dedicated dnsmasq configuration ``/etc/distraction-blocker-network.conf``
  (identified by :data:`RESOLVER_BEGIN`), and
* the systemd unit ``distraction-blocker-dns.service`` (owned by packaging;
  this module only starts, stops, and health-probes it).

Scope and explicit boundaries (do not over-claim):

* Enforcement state scope is the protected UID's originating socket
  (``meta skuid``) on the host's own output path. Root, processes with
  equivalent network capabilities, local proxies, system daemons, and
  arbitrary tunnels remain outside the boundary; this is not exhaustive
  enforcement.
* ``whole_internet`` drops all of the protected UID's non-loopback IPv4 and
  IPv6 traffic, including already-established flows. Loopback (and therefore
  the local RPC socket) always works.
* ``alternate_dns`` blocks the protected UID's non-local TCP/UDP 53 and
  TCP/UDP 853. Loopback DNS to the system stub resolver stays reachable.
* ``safe_search`` implies the DNS restrictions above and, in addition,
  redirects the protected UID's loopback-bound TCP/UDP 53 (including the
  systemd stub resolver) to the dedicated dnsmasq on 127.0.0.54:1053 (IPv4)
  and [::1]:1053 (IPv6). The redirect is NAT on *new* flows only; already
  established port-53 flows are dropped by filter rules placed BEFORE the
  general loopback accept, because conntrack never re-evaluates output NAT
  rules for existing flows. The dedicated resolver itself is explicit and
  reachable directly on port 1053 (its answers are filtered).
* ``safe_search`` is a resolver-path control, not encrypted-content
  inspection. When DNS is carried inside arbitrary HTTPS, a proxy, or a VPN
  tunnel, nftables cannot distinguish the inner query from ordinary traffic
  or safely apply a search-provider mapping. No network-layer exhaustive
  SafeSearch guarantee is made for those paths.
* ``doh`` drops protected-UID TCP and UDP port 443 traffic to the
  versioned, code-owned catalog of documented public DoH resolver addresses.
  It is an exact-address block, not hostname or protocol inspection. A
  provider can rotate addresses before a package update, and shared addresses
  can cause collateral blocking; arbitrary DoH remains outside the claim.
* ``proxy`` drops protected-UID TCP and UDP traffic to a versioned catalog of
  common proxy listener ports. It does not identify proxy payloads, hosts, or
  non-catalogued ports; local loopback proxies remain outside the boundary.
* ``vpn`` drops protected-UID TCP and UDP traffic to a versioned catalog of
  common VPN transport ports and drops GRE and ESP packets. It does not
  identify tunnels on arbitrary ports, encrypted protocols hidden in ordinary
  traffic, or local VPN/proxy processes; it is not exhaustive.
* The controls combine additively: ``whole_internet`` contributes the final
  non-loopback deny, ``safe_search`` contributes the port-53/853 drops and
  the redirect chain, ``alternate_dns`` contributes the non-local 53/853
  restrictions, ``doh`` contributes catalog-address 443 drops, ``proxy``
  contributes common proxy-port drops, and ``vpn`` contributes common
  VPN-port plus GRE/ESP drops. Any combination is the union of its members;
  no control subsumes another.
* ``safe_search`` forces the documented provider DNS mappings below
  (versioned policy data). For each mapped hostname dnsmasq is made locally
  authoritative (``local=/host/``) so AAAA/HTTPS/SVCB cannot answer with an
  unfiltered provider address; only the enforced A record is served.
* Failure policy is fail-closed: when an active state cannot be verified the
  enforcer installs the emergency fence before reporting, and a stale fence
  remains after a crash until a successful reconcile or explicit root
  recovery. ``recover`` removes only owned resources and removes the opt-in
  marker only after every other step succeeded; any failure keeps the marker
  (and therefore the boot fence) in place.

The global system resolver is never modified: no changes to
``/etc/resolv.conf`` or systemd-resolved configuration; the dedicated
dnsmasq forwards to the existing stub resolver at 127.0.0.53.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from .model import NETWORK_CONTROLS
TABLE_FAMILY = "inet"
TABLE_NAME = "distraction_blocker"
OWNERSHIP_COMMENT = "distraction-blocker-network-enforcer"
CHAIN_ORDER = ("output", "dns_redirect")

# Versioned static DoH endpoint catalog. Addresses are copied from provider
# documentation and intentionally do not come from runtime DNS: a poisoned
# answer must not decide which addresses the root firewall blocks. Sources:
# https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
# https://developers.google.com/speed/public-dns/docs/doh
# https://quad9.net/service/service-addresses-and-features/
# Update the catalog and its version in a release when a supported provider
# changes its documented resolver addresses. This is a named endpoint catalog,
# not an exhaustive list of DoH services.
DOH_CATALOG_VERSION = 1
DOH_ENDPOINT_CATALOG: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "https://cloudflare-dns.com/dns-query",
        (
            "1.0.0.1",
            "1.1.1.1",
            "2606:4700:4700::1001",
            "2606:4700:4700::1111",
        ),
    ),
    (
        "https://dns.google/dns-query",
        (
            "8.8.4.4",
            "8.8.8.8",
            "2001:4860:4860::8844",
            "2001:4860:4860::8888",
        ),
    ),
    (
        "https://dns.quad9.net/dns-query",
        (
            "9.9.9.9",
            "149.112.112.112",
            "2620:fe::9",
            "2620:fe::fe",
        ),
    ),
)
DOH_ENDPOINT_ADDRESSES: tuple[str, ...] = tuple(
    sorted({address for _endpoint, addresses in DOH_ENDPOINT_CATALOG for address in addresses})
)
# Versioned common transport catalogs for best-effort proxy/VPN endpoint
# controls. These are port/protocol controls rather than hostname or payload
# inspection; arbitrary endpoints can use different ports and remain outside
# the guarantee. Port conventions:
# * SOCKS5 is specified by https://www.rfc-editor.org/rfc/rfc1928; common HTTP
#   proxy and Tor listener ports are 1080, 3128, 8000, 8080, 8118, 8888,
#   9050, and 9150.
# * IKE/IPsec uses UDP 500/4500 (RFCs 7296 and 3948), OpenVPN commonly uses
#   1194, L2TP 1701 (RFC 2661), PPTP 1723 (RFC 2637), and WireGuard commonly
#   uses 51820.
PROXY_CATALOG_VERSION = 1
PROXY_ENDPOINT_PORTS: tuple[int, ...] = (
    1080,
    3128,
    8000,
    8080,
    8118,
    8888,
    9050,
    9150,
)
VPN_CATALOG_VERSION = 1
VPN_ENDPOINT_PORTS: tuple[int, ...] = (500, 1194, 1701, 1723, 4500, 51820)
VPN_TUNNEL_PROTOCOLS: tuple[str, ...] = ("esp", "gre")

# Versioned SafeSearch policy data: (provider, source hostname, forced
# hostname). The source hostname is made locally authoritative and its A
# answer is replaced by the forced hostname's current A record, which every
# provider documents as its SafeSearch-forced endpoint:
#
# * Google (support.google.com/websearch/answer/186669): network-level
#   SafeSearch maps the Google domains to forcesafesearch.google.com.
# * YouTube (Google Workspace admin help "Control YouTube content available
#   to users"): strict restriction CNAMEs the YouTube domains to
#   restrict.youtube.com.
# * Bing (Microsoft SafeSearch network guidance): the Bing domain CNAMEs to
#   strict.bing.com.
#
# When a provider changes its documented mapping, update this table.
SAFESEARCH_MAPPINGS: tuple[tuple[str, str, str], ...] = (
    ("google", "google.com", "forcesafesearch.google.com"),
    ("google", "www.google.com", "forcesafesearch.google.com"),
    ("google", "m.google.com", "forcesafesearch.google.com"),
    ("youtube", "youtube.com", "restrict.youtube.com"),
    ("youtube", "www.youtube.com", "restrict.youtube.com"),
    ("youtube", "m.youtube.com", "restrict.youtube.com"),
    ("bing", "bing.com", "strict.bing.com"),
    ("bing", "www.bing.com", "strict.bing.com"),
)
SAFESEARCH_TARGETS: tuple[str, ...] = tuple(
    sorted({target for _provider, _source, target in SAFESEARCH_MAPPINGS})
)


class NetworkError(Exception):
    """A network enforcement operation failed."""


class NetworkUnavailable(NetworkError):
    """Network enforcement is not enabled for this host."""


class CollisionError(NetworkError):
    """The named resource is owned by another process; nothing was changed."""


class ResolverError(NetworkError):
    """The dedicated SafeSearch resolver could not be prepared or probed."""


class ApplyError(NetworkError):
    """The nftables ruleset could not be applied or verified."""


def marker_path(data_dir: Any) -> str:
    return os.path.join(os.fspath(data_dir), NETWORK_ENABLED_MARKER)


def _file_is_ours(path: str, expected_owner: int) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if (st.st_mode & 0o170000) != 0o100000:
        return False
    if st.st_uid != expected_owner or (st.st_mode & 0o7777) != 0o600:
        return False
    return True


def is_network_enabled(data_dir: Any, *, expected_owner: int | None = None) -> bool:
    """True only for an owner 0600 marker file with the fixed content."""
    owner = 0 if expected_owner is None else expected_owner
    path = marker_path(data_dir)
    if not _file_is_ours(path, owner):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        with os.fdopen(fd, "rb") as stream:
            return stream.read(len(NETWORK_MARKER_CONTENT) + 1) == NETWORK_MARKER_CONTENT
    except OSError:
        return False


def write_network_marker(
    data_dir: Any, *, chown: bool = True, expected_owner: int | None = None
) -> None:
    """Create the enablement marker without clobbering a foreign file.

    The marker is deliberately tiny and has a fixed owner/mode/content.  An
    existing marker is accepted only when it is exactly ours; otherwise this
    operation fails before changing anything.  Creation uses ``O_EXCL`` so a
    concurrent installer cannot win a race and then be overwritten.
    """
    owner = 0 if expected_owner is None else expected_owner
    directory = os.fspath(data_dir)
    path = marker_path(directory)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        fd = None
    except OSError as exc:
        raise CollisionError(f"cannot inspect network enablement marker: {exc}") from exc
    if fd is not None:
        try:
            st = os.fstat(fd)
            if (
                (st.st_mode & 0o170000) != 0o100000
                or st.st_uid != owner
                or (st.st_mode & 0o7777) != 0o600
            ):
                raise CollisionError("network enablement marker exists and is not owned")
            with os.fdopen(fd, "rb") as stream:
                if stream.read() != NETWORK_MARKER_CONTENT:
                    raise CollisionError("network enablement marker content does not match")
            return
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise CollisionError("network enablement marker appeared concurrently") from exc
    except OSError as exc:
        raise CollisionError(f"cannot create network enablement marker: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(NETWORK_MARKER_CONTENT)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
        if chown:
            os.chown(path, 0, 0)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def remove_network_marker(data_dir: Any, *, expected_owner: int | None = None) -> None:
    """Remove the marker only if it is still exactly ours; never foreign files."""
    owner = 0 if expected_owner is None else expected_owner
    path = marker_path(data_dir)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise NetworkError(f"cannot read network enablement marker: {exc}") from exc
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(len(NETWORK_MARKER_CONTENT) + 1)
    if data != NETWORK_MARKER_CONTENT or not _file_is_ours(path, owner):
        raise CollisionError("network enablement marker is not owned; refusing to remove")
    os.unlink(path)


def read_owner_uid(data_dir: Any, *, expected_owner: int | None = None) -> int:
    """Read the protected UID from the install-time owner.uid file."""
    owner = 0 if expected_owner is None else expected_owner
    path = os.path.join(os.fspath(data_dir), OWNER_UID_FILE)
    if not _file_is_ours(path, owner):
        raise NetworkUnavailable(f"owner.uid file missing or not owned: {path}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise NetworkUnavailable(f"cannot read owner.uid: {exc}") from exc
    try:
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(129)
        if len(raw) > 128:
            raise NetworkUnavailable("owner.uid is too large")
        text = raw.decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise NetworkUnavailable(f"cannot read owner.uid: {exc}") from exc
    if not text.endswith("\n") or not text[:-1].isdigit():
        raise NetworkUnavailable(f"owner.uid is not a number: {text!r}")
    text = text[:-1]
    uid = int(text)
    if not 0 < uid < 2**31:
        raise NetworkUnavailable(f"owner.uid out of range: {uid}")
    return uid



FENCE_CONTROLS = frozenset({"whole_internet"})

DATA_DIR = "/var/lib/distraction-blocker"
OWNER_UID_FILE = "owner.uid"
NETWORK_ENABLED_MARKER = "network.enabled"
NETWORK_MARKER_CONTENT = b"distraction-blocker/network-enabled/v1\n"

RESOLVER_UNIT = "distraction-blocker-dns.service"
BOOT_FENCE_UNIT = "distraction-blocker-network-restore.service"
RESOLVER_CONFIG = "/etc/distraction-blocker-network.conf"
RESOLVER_BEGIN = "# distraction-blocker-network-owned-v1"
RESOLVER_ADDR_V4 = "127.0.0.54"
RESOLVER_ADDR_V6 = "::1"
RESOLVER_PORT = 1053
# The only trusted upstream is the systemd-resolved stub. No other
# (untrusted, user-writable) address may be used as a fallback.
UPSTREAM_ADDRESSES = ((socket.AF_INET, "127.0.0.53"),)
UPSTREAM_PORT = 53

_QTYPE_A = 1
_QTYPE_AAAA = 28
_QTYPE_SVCB = 64
_QTYPE_HTTPS = 65
_HEALTH_NAME = "distraction-blocker-health.invalid"

# ---------------------------------------------------------------------------
# Desired ruleset construction
#
# Expressions are canonical tuples in exactly the shape _parse_expr derives
# from `nft -j list table`, so observed and desired states compare without
# translation:
#
#   ("meta", "skuid", uid) / ("meta", "oifname", "lo")
#   ("dport", "tcp" | "udp", port)
#   ("daddr", "ip" | "ip6", address or "prefix/len")
#   ("dnat", "ip" | "ip6", address, port)
#   ("drop",) / ("accept",)
#
# Rule order is chain order: the first matching rule wins.  SafeSearch port
# 53 drops sit BEFORE the general loopback accept (established port-53 flows
# never re-enter the NAT redirect) and the whole-internet deny is last.
_Expr = tuple


def _desired_ruleset(uid: int, controls: frozenset[str]) -> dict[str, Any]:
    """Return {"comment", "chains", "rules"} for the active control set."""
    whole = "whole_internet" in controls
    alt = "alternate_dns" in controls
    safe = "safe_search" in controls
    doh = "doh" in controls
    proxy = "proxy" in controls
    vpn = "vpn" in controls
    owner: _Expr = ("meta", "skuid", uid)
    output: list[_Expr] = []
    if safe:
        # Existing port-53 flows cannot be re-evaluated by output NAT.
        output.append((owner, ("dport", "tcp", 53), ("drop",)))
        output.append((owner, ("dport", "udp", 53), ("drop",)))
    if alt or safe:
        # Local DoT remains usable; SafeSearch's DNS path is port 1053.
        output.append((owner, ("dport", "tcp", 853), ("meta", "oifname", "lo"), ("accept",)))
        output.append((owner, ("dport", "udp", 853), ("meta", "oifname", "lo"), ("accept",)))
    if alt and not safe:
        output.append((owner, ("dport", "tcp", 53), ("meta", "oifname", "lo"), ("accept",)))
        output.append((owner, ("dport", "udp", 53), ("meta", "oifname", "lo"), ("accept",)))
        output.append((owner, ("dport", "tcp", 53), ("drop",)))
        output.append((owner, ("dport", "udp", 53), ("drop",)))
    if alt or safe:
        output.append((owner, ("dport", "tcp", 853), ("drop",)))
        output.append((owner, ("dport", "udp", 853), ("drop",)))
    if doh:
        # Port 443 is shared with ordinary HTTPS/HTTP3. Address-only drops
        # intentionally accept that collateral for catalogued endpoints.
        for address in DOH_ENDPOINT_ADDRESSES:
            family = "ip6" if ":" in address else "ip"
            for protocol in ("tcp", "udp"):
                output.append(
                    (
                        owner,
                        ("daddr", family, address),
                        ("dport", protocol, 443),
                        ("drop",),
                    )
                )
    if proxy:
        # Common proxy ports are shared with legitimate services; this is
        # intentionally a best-effort transport-port catalog.
        for port in PROXY_ENDPOINT_PORTS:
            for protocol in ("tcp", "udp"):
                output.append((owner, ("dport", protocol, port), ("drop",)))
    if vpn:
        # Port controls catch common VPN configurations; protocol controls
        # cover IPsec ESP and PPTP GRE regardless of their control port.
        for port in VPN_ENDPOINT_PORTS:
            for protocol in ("tcp", "udp"):
                output.append((owner, ("dport", protocol, port), ("drop",)))
        for protocol in VPN_TUNNEL_PROTOCOLS:
            output.append((owner, ("meta", "l4proto", protocol), ("drop",)))
    output.append((owner, ("meta", "oifname", "lo"), ("accept",)))
    if whole:
        output.append((owner, ("drop",)))

    desired: dict[str, Any] = {"comment": OWNERSHIP_COMMENT, "chains": {}, "rules": {}}
    if whole or alt or safe or doh or proxy or vpn:
        desired["chains"]["output"] = ("filter", "output", 0, "accept")
        desired["rules"]["output"] = tuple(output)
    if safe:
        # Redirect only loopback-bound new port-53 flows.
        desired["chains"]["dns_redirect"] = ("nat", "output", -100, "accept")
        desired["rules"]["dns_redirect"] = (
            (owner, ("daddr", "ip", "127.0.0.0/8"), ("dport", "udp", 53),
             ("dnat", "ip", RESOLVER_ADDR_V4, RESOLVER_PORT)),
            (owner, ("daddr", "ip", "127.0.0.0/8"), ("dport", "tcp", 53),
             ("dnat", "ip", RESOLVER_ADDR_V4, RESOLVER_PORT)),
            (owner, ("daddr", "ip6", RESOLVER_ADDR_V6), ("dport", "udp", 53),
             ("dnat", "ip6", RESOLVER_ADDR_V6, RESOLVER_PORT)),
            (owner, ("daddr", "ip6", RESOLVER_ADDR_V6), ("dport", "tcp", 53),
             ("dnat", "ip6", RESOLVER_ADDR_V6, RESOLVER_PORT)),
        )
    return desired


def _render_expr(expr: _Expr) -> str:
    kind = expr[0]
    if kind in ("drop", "accept"):
        return kind
    if kind == "meta":
        return f"meta {expr[1]} {expr[2]}"
    if kind == "dport":
        return f"{expr[1]} dport {expr[2]}"
    if kind == "daddr":
        return f"{expr[1]} daddr {expr[2]}"
    if kind == "dnat":
        _kind, family, addr, port = expr
        target = f"[{addr}]:{port}" if family == "ip6" else f"{addr}:{port}"
        return f"dnat {family} to {target}"
    raise ApplyError(f"unrenderable expression {expr!r}")


def _render_batch(desired: Mapping[str, Any], delete_existing: bool) -> bytes:
    """One atomic nft batch: delete owned table (if present) + create."""
    lines = []
    if delete_existing:
        lines.append(f"delete table {TABLE_FAMILY} {TABLE_NAME}")
    chains = desired["chains"]
    if chains:
        lines.append(f"table {TABLE_FAMILY} {TABLE_NAME} {{")
        lines.append(f'\tcomment "{desired["comment"]}"')
        for name in CHAIN_ORDER:
            if name not in chains:
                continue
            ctype, hook, prio, policy = chains[name]
            lines.append(f"\tchain {name} {{")
            lines.append(f"\t\ttype {ctype} hook {hook} priority {prio};")
            lines.append(f"\t\tpolicy {policy};")
            for exprs in desired["rules"].get(name, ()):
                lines.append("\t\t" + " ".join(_render_expr(expr) for expr in exprs))
            lines.append("\t}")
        lines.append("}")
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


# ---------------------------------------------------------------------------
# Observed kernel state (parsed from `nft -j list table`)
#
# nft 1.0.x JSON form: {"nftables": [{"metainfo": ...}, {"table": {...}},
# {"chain": {..., "prio": N, "policy": ...}}, {"rule": {..., "expr":
# [single-key objects]}}]}. Match expressions carry "left"/"right"; payload
# protocols are strings ("tcp", "udp", "ip", "ip6"); prefix address matches
# are {"prefix": {"addr", "len"}} objects while host addresses are bare
# strings.
# ---------------------------------------------------------------------------


@dataclass
class _Observed:
    comment: str | None
    chains: dict[str, tuple[str, str, int, str]]
    rules: dict[str, list[tuple]]


def _parse_expr(entry: Any) -> tuple:
    """One native nft JSON expression -> our canonical expression tuple."""
    if not isinstance(entry, dict) or len(entry) != 1:
        raise ValueError("expression is not a single-key object")
    (key, value), = entry.items()
    if key == "match":
        if not isinstance(value, dict) or value.get("op") != "==":
            raise ValueError("unsupported match expression")
        left = value.get("left")
        right = value.get("right")
        if not isinstance(left, dict) or len(left) != 1:
            raise ValueError("unsupported match left-hand side")
        if "meta" in left:
            meta = left["meta"]
            if not isinstance(meta, dict) or meta.get("key") not in {"skuid", "oifname", "l4proto"}:
                raise ValueError("unsupported meta key")
            kind = meta["key"]
            if kind == "skuid" and (not isinstance(right, int) or isinstance(right, bool)):
                raise ValueError("invalid skuid match")
            if kind in {"oifname", "l4proto"} and not isinstance(right, str):
                raise ValueError(f"invalid {kind} match")
            return ("meta", kind, right)
        if "payload" in left:
            payload = left["payload"]
            if not isinstance(payload, dict) or len(payload) != 2:
                raise ValueError("invalid payload match")
            protocol = payload.get("protocol")
            field = payload.get("field")
            if protocol not in {"tcp", "udp", "ip", "ip6"}:
                raise ValueError("unsupported payload protocol")
            if field == "dport":
                if protocol not in {"tcp", "udp"} or not isinstance(right, int) or isinstance(right, bool):
                    raise ValueError("invalid destination port match")
                if not 0 <= right <= 65535:
                    raise ValueError("destination port out of range")
                return ("dport", protocol, right)
            if field == "daddr":
                if protocol not in {"ip", "ip6"} or not isinstance(right, (str, dict)):
                    raise ValueError("invalid destination address match")
                if isinstance(right, dict):
                    prefix = right.get("prefix")
                    if not isinstance(prefix, dict) or set(prefix) != {"addr", "len"}:
                        raise ValueError("invalid address prefix")
                    addr, length = prefix["addr"], prefix["len"]
                    if not isinstance(addr, str) or not isinstance(length, int):
                        raise ValueError("invalid address prefix")
                    try:
                        network = ipaddress.ip_network(f"{addr}/{length}", strict=False)
                    except ValueError as exc:
                        raise ValueError("invalid address prefix") from exc
                    if (protocol == "ip" and network.version != 4) or (
                        protocol == "ip6" and network.version != 6
                    ):
                        raise ValueError("address family mismatch")
                    right = f"{addr}/{length}"
                else:
                    try:
                        address = ipaddress.ip_address(right)
                    except ValueError as exc:
                        raise ValueError("invalid destination address") from exc
                    if (protocol == "ip" and address.version != 4) or (
                        protocol == "ip6" and address.version != 6
                    ):
                        raise ValueError("address family mismatch")
                return ("daddr", protocol, right)
            raise ValueError(f"unsupported payload field {field!r}")
        raise ValueError("unsupported match left-hand side")
    if key in {"drop", "accept"}:
        if value is not None:
            raise ValueError(f"invalid {key} verdict")
        return (key,)
    if key == "dnat":
        if not isinstance(value, dict) or set(value) != {"family", "addr", "port"}:
            raise ValueError("bad dnat expression")
        family, addr, port = value["family"], value["addr"], value["port"]
        if family not in {"ip", "ip6"} or not isinstance(addr, str):
            raise ValueError("bad dnat target")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("bad dnat port")
        try:
            address = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ValueError("bad dnat address") from exc
        if (family == "ip" and address.version != 4) or (family == "ip6" and address.version != 6):
            raise ValueError("dnat family mismatch")
        return ("dnat", family, addr, port)
    raise ValueError(f"unsupported expression {key!r}")


def _parse_listing(stdout: bytes) -> _Observed:
    try:
        doc = json.loads(stdout.decode("utf-8"))
        entries = doc.get("nftables") if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            raise ValueError("listing has no nftables entries")
        observed = _Observed(comment=None, chains={}, rules={})
        table_seen = False
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("entry is not an object")
            if "metainfo" in entry:
                continue
            if "table" in entry:
                if table_seen or not isinstance(entry["table"], dict):
                    raise ValueError("invalid table entry")
                table_seen = True
                observed.comment = entry["table"].get("comment")
            elif "chain" in entry:
                chain = entry["chain"]
                if not isinstance(chain, dict):
                    raise ValueError("invalid chain entry")
                observed.chains[chain["name"]] = (
                    chain["type"],
                    chain["hook"],
                    int(chain["prio"]),
                    chain.get("policy", "accept"),
                )
            elif "rule" in entry:
                rule = entry["rule"]
                if not isinstance(rule, dict):
                    raise ValueError("invalid rule entry")
                exprs = tuple(_parse_expr(expr) for expr in rule["expr"])
                observed.rules.setdefault(rule["chain"], []).append(exprs)
            else:
                raise ValueError("unsupported nftables entry")
        if not table_seen:
            raise ValueError("listing has no table entry")
        return observed
    except (ValueError, KeyError, TypeError) as exc:
        raise ApplyError(f"could not parse nftables state: {exc}") from exc


def _comparable_observed(observed: _Observed) -> tuple:
    return (
        observed.comment,
        tuple(sorted(observed.chains.items())),
        tuple((name, tuple(rules)) for name, rules in sorted(observed.rules.items())),
    )


def _comparable_desired(desired: Mapping[str, Any]) -> tuple:
    return (
        desired["comment"],
        tuple(sorted(desired["chains"].items())),
        tuple((name, tuple(rules)) for name, rules in sorted(desired["rules"].items())),
    )


# ---------------------------------------------------------------------------
# Minimal DNS wire format (stdlib only) for resolver preparation/health
# ---------------------------------------------------------------------------


def _encode_query(txn: bytes, name: str, qtype: int) -> bytes:
    if len(txn) != 2:
        raise ValueError("DNS transaction id must be two bytes")
    if not isinstance(name, str) or not name or len(name.rstrip(".")) > 253:
        raise ValueError("invalid DNS name")
    labels = name.rstrip(".").split(".")
    try:
        encoded_labels = [label.encode("ascii") for label in labels]
    except UnicodeEncodeError as exc:
        raise ValueError("DNS name must be ASCII") from exc
    if any(not label or len(label) > 63 for label in encoded_labels):
        raise ValueError("invalid DNS label")
    if not 0 <= qtype <= 0xFFFF:
        raise ValueError("invalid DNS query type")
    name_bytes = b"".join(bytes([len(label)]) + label for label in encoded_labels) + b"\x00"
    return (
        txn
        + b"\x01\x00"  # flags: RD (recursion desired)
        + struct.pack(">HHHH", 1, 0, 0, 0)
        + name_bytes
        + struct.pack(">HH", qtype, 1)
    )


def _skip_name(payload: bytes, pos: int) -> int:
    """Skip an encoded DNS name, returning the first byte after it."""
    while True:
        if pos >= len(payload):
            raise ValueError("truncated DNS name")
        length = payload[pos]
        pos += 1
        if length == 0:
            return pos
        if (length & 0xC0) == 0xC0:
            if pos >= len(payload):
                raise ValueError("truncated DNS compression pointer")
            return pos + 1
        if length & 0xC0:
            raise ValueError("invalid DNS label length")
        end = pos + length
        if end > len(payload):
            raise ValueError("truncated DNS label")
        pos = end


def _parse_dns(payload: bytes) -> tuple[bytes, int, list[tuple[int, int, bytes]]]:
    """Return (txid, rcode, [(rtype, rclass, rdata), ...]) for the answer."""
    if len(payload) < 12:
        raise ValueError("short DNS response")
    flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        ">HHHHH", payload[2:12]
    )
    if not flags & 0x8000:
        raise ValueError("DNS response bit is not set")
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(payload, pos)
        if pos + 4 > len(payload):
            raise ValueError("truncated DNS question")
        pos += 4
    answers: list[tuple[int, int, bytes]] = []
    for _ in range(ancount):
        pos = _skip_name(payload, pos)
        if pos + 10 > len(payload):
            raise ValueError("truncated DNS answer")
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", payload[pos : pos + 10])
        pos += 10
        if pos + rdlength > len(payload):
            raise ValueError("truncated DNS rdata")
        answers.append((rtype, rclass, payload[pos : pos + rdlength]))
        pos += rdlength
    return payload[:2], flags & 0x000F, answers


def _dns_query(
    family: int,
    addr: str,
    port: int,
    name: str,
    qtype: int,
    timeout: float = 2.0,
) -> tuple[int, list[str]]:
    """One DNS query; returns (rcode, matching rdata as addresses)."""
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((addr, port))
        txid = os.urandom(2)
        payload = _encode_query(txid, name, qtype)
        sock.send(payload)
        data = sock.recv(4096)
        resp_txid, rcode, answers = _parse_dns(data)
        if resp_txid != txid:
            raise ValueError("DNS transaction id mismatch")
        values: list[str] = []
        for rtype, rclass, rdata in answers:
            if rtype != qtype or rclass != 1:
                continue
            if qtype == _QTYPE_A and len(rdata) == 4:
                values.append(socket.inet_ntoa(rdata))
            elif qtype == _QTYPE_AAAA and len(rdata) == 16:
                values.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif qtype in (_QTYPE_SVCB, _QTYPE_HTTPS):
                # Health checks only need to know whether any record exists;
                # preserve a stable non-empty marker without parsing RDATA.
                values.append(rdata.hex())
        return rcode, values
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Dedicated SafeSearch resolver (dnsmasq on 1053, forwarding to 53)
# ---------------------------------------------------------------------------


def render_resolver_config(resolved: Mapping[str, tuple[str, ...]]) -> str:
    """Render the owned dnsmasq config.

    Every mapped source hostname is locally authoritative: only the enforced
    A answer exists, so AAAA/HTTPS/SVCB get NOERROR-NODATA.
    """
    try:
        normalized = {
            target: tuple(sorted(set(ips)))
            for target, ips in resolved.items()
        }
        if set(normalized) != set(SAFESEARCH_TARGETS):
            raise ValueError("resolved targets do not match SafeSearch policy")
        for target, ips in normalized.items():
            if not ips:
                raise ValueError(f"no A records for {target}")
            if any(
                not isinstance(ip, str) or ipaddress.ip_address(ip).version != 4
                for ip in ips
            ):
                raise ValueError(f"non-IPv4 A record for {target}")
    except (AttributeError, TypeError, ValueError) as exc:
        raise ResolverError(f"invalid SafeSearch addresses: {exc}") from exc
    lines = [
        RESOLVER_BEGIN,
        "# Owned by the distraction-blocker network enforcer. Do not edit.",
        f"port={RESOLVER_PORT}",
        f"listen-address={RESOLVER_ADDR_V4}",
        f"listen-address={RESOLVER_ADDR_V6}",
        "bind-interfaces",
        "no-hosts",
        "no-resolv",
        "server=127.0.0.53",
        "user=distraction-blocker-dns",
        "group=distraction-blocker-dns",
        "local-ttl=0",
        "auth-ttl=0",
    ]
    for _provider, source, _target in SAFESEARCH_MAPPINGS:
        lines.append(f"local=/{source}/")
    for _provider, source, target in SAFESEARCH_MAPPINGS:
        for ip in normalized[target]:
            lines.append(f"address=/{source}/{ip}")
    return "\n".join(lines) + "\n"


def _parse_resolver_config(data: bytes) -> dict[str, tuple[str, ...]] | None:
    """Recover canonical forced-target A records from an owned config."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.startswith(RESOLVER_BEGIN + "\n"):
        return None
    sources: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("local=/") and line.endswith("/"):
            source = line[len("local=/") : -1]
            if source in sources:
                return None
            sources[source] = []
        elif line.startswith("address=/"):
            body = line[len("address=/") :]
            host, separator, ip = body.rpartition("/")
            if not separator or host not in sources or not ip:
                return None
            try:
                if ipaddress.ip_address(ip).version != 4:
                    return None
            except ValueError:
                return None
            sources[host].append(ip)
    targets: dict[str, set[str]] = {}
    for _provider, source, target in SAFESEARCH_MAPPINGS:
        if source not in sources or not sources[source]:
            return None
        targets.setdefault(target, set()).update(sources[source])
    if set(targets) != set(SAFESEARCH_TARGETS):
        return None
    normalized = {target: tuple(sorted(ips)) for target, ips in sorted(targets.items())}
    # Require the complete deterministic file, not merely a trusted-looking
    # sentinel plus a subset of directives that dnsmasq might interpret.
    try:
        if render_resolver_config(normalized).encode("utf-8") != data:
            return None
    except ResolverError:
        return None
    return normalized


def resolver_health(
    expected: Mapping[str, tuple[str, ...]],
    query: Callable[..., tuple[int, list[str]]] = _dns_query,
) -> bool:
    """Probe the dedicated resolver; True only if enforcement is verifiable.
    ``expected`` maps source hostname -> enforced A records. Checks both the
    IPv4 and IPv6 dedicated listeners.  It verifies that mapped names have
    no AAAA, SVCB, or HTTPS records, preventing alternate-address metadata
    from bypassing the locally authoritative A mapping.
    """
    for host, ips in sorted(expected.items()):
        for family, addr in (
            (socket.AF_INET, RESOLVER_ADDR_V4),
            (socket.AF_INET6, RESOLVER_ADDR_V6),
        ):
            rcode, got = query(family, addr, RESOLVER_PORT, host, _QTYPE_A)
            if rcode != 0 or sorted(got) != sorted(ips):
                return False
            for qtype in (_QTYPE_AAAA, _QTYPE_SVCB, _QTYPE_HTTPS):
                rcode, other = query(family, addr, RESOLVER_PORT, host, qtype)
                if rcode != 0 or other:
                    return False
    return True


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------


def _default_runner(argv: list[str], data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=data, capture_output=True, timeout=30)


class NetworkEnforcer:
    """Owns this host's protected-UID network state (run as root).

    The enforcer is the single owner of one nftables table, one dnsmasq
    unit, one resolver config file, and the boot-fence unit enablement.
    Every public operation is fail-closed: on any failure the owned state
    is fenced (protected UID denied the whole internet) and the error
    raised; the enforcer reports ``healthy`` only after a verified apply.
    Boot-fence unit *enablement* is install-time packaging work: reconcile
    never enables or disables it (it stays enabled for the whole opt-in
    lifetime); only ``recover`` disables it, and only as part of the final
    full teardown.
    """

    def __init__(
        self,
        owner_uid: int,
        data_dir: str = DATA_DIR,
        *,
        runner: Callable[[list[str], bytes | None], subprocess.CompletedProcess] = _default_runner,
        query: Callable[[str, str, int, str, int], tuple[int, list[str]]] = _dns_query,
        resolver_config: str = RESOLVER_CONFIG,
    ) -> None:
        if not isinstance(owner_uid, int) or not 0 < owner_uid < 2**31:
            raise ValueError("owner_uid must be a positive int")
        self.owner_uid = owner_uid
        self.data_dir = data_dir
        self._runner = runner
        self._query = query
        self.resolver_config = resolver_config
        self._marker_owner = 0
        self._healthy = False

    @property
    def available(self) -> bool:
        """True only when the root-owned opt-in marker is present and valid."""
        return is_network_enabled(self.data_dir, expected_owner=self._marker_owner)

    @property
    def healthy(self) -> bool:
        return self.available and self._healthy

    # -- subprocess boundary -------------------------------------------------

    def _run(self, argv: list[str], data: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            return self._runner(list(argv), data)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ApplyError(f"command failed: {exc}") from exc

    def _nft(self, *argv: str, data: bytes | None = None) -> subprocess.CompletedProcess:
        return self._run(["nft", *argv], data)

    def _systemctl(self, *argv: str) -> subprocess.CompletedProcess:
        return self._run(["systemctl", *argv])

    # -- nftables state ------------------------------------------------------

    def _inspect(self) -> tuple[bool, _Observed | None]:
        """Return (present, parsed) for the owned table; raise on any other error."""
        cp = self._nft("-j", "list", "table", TABLE_FAMILY, TABLE_NAME)
        if cp.returncode == 0:
            return True, _parse_listing(cp.stdout)
        stderr = cp.stderr or b""
        if b"No such file or directory" in stderr or b"no such table" in stderr.lower():
            return False, None
        raise ApplyError(
            f"cannot inspect nftables table: {stderr.decode('utf-8', 'replace').strip()}"
        )

    def _commit(self, desired: dict[str, Any]) -> bool:
        """Atomically converge the owned table to ``desired``; True when verified.

        The batch is always checked first (``nft -c``), so a collision with a
        foreign table or a kernel error aborts before any owned rule changes.
        """
        exists, observed = self._inspect()
        if exists:
            if observed is None or observed.comment != desired["comment"]:
                raise CollisionError(f"table {TABLE_NAME} is owned by another process")
            if desired["chains"] and _comparable_observed(observed) == _comparable_desired(desired):
                return True
        if not exists and not desired["chains"]:
            return True
        batch = _render_batch(desired, delete_existing=exists)
        cp = self._nft("-c", "-f", "-", data=batch)
        if cp.returncode != 0:
            raise ApplyError(
                f"nftables check failed: {cp.stderr.decode('utf-8', 'replace').strip()}"
            )
        cp = self._nft("-f", "-", data=batch)
        if cp.returncode != 0:
            raise ApplyError(
                f"nftables apply failed: {cp.stderr.decode('utf-8', 'replace').strip()}"
            )
        return self._verify(desired)

    def _verify(self, desired: dict[str, Any]) -> bool:
        exists, observed = self._inspect()
        if not desired["chains"]:
            return not exists
        if not exists or observed is None:
            return False
        return _comparable_observed(observed) == _comparable_desired(desired)

    def _apply_ruleset(self, desired: dict[str, Any], *, fence: bool = False) -> None:
        try:
            if not self._commit(desired):
                raise ApplyError("nftables state does not match the requested ruleset")
        except CollisionError:
            raise
        except NetworkError:
            if not fence:
                self._fence_quietly()
            raise

    def _fence_quietly(self) -> None:
        try:
            self.fence()
        except NetworkError:
            pass

    def fence(self) -> None:
        """Install the emergency whole-internet deny for the protected UID."""
        self._apply_ruleset(_desired_ruleset(self.owner_uid, FENCE_CONTROLS), fence=True)
        self._healthy = False

    def _disable_boot_fence(self) -> None:
        cp = self._systemctl("disable", BOOT_FENCE_UNIT)
        if cp.returncode != 0 and b"not loaded" not in (cp.stderr or b""):
            raise ApplyError(
                f"cannot disable {BOOT_FENCE_UNIT}: {cp.stderr.decode('utf-8', 'replace').strip()}"
            )

    # -- public operations ---------------------------------------------------

    def reconcile(self, controls: frozenset[str]) -> None:
        """Converge the owned state to ``controls`` (the signed active set).

        Ordering invariants: resolver preparation/health happens before any
        SafeSearch redirect is installed; a failure before the verified
        table apply leaves the previous (stronger) enforcement in place and
        fences; an empty reconciliation deletes the table first and only
        then tears the resolver down.  Any teardown failure also fences.
        reconcile never enables or disables the boot fence unit.
        """
        controls = frozenset(controls)
        unknown = controls - NETWORK_CONTROLS
        if unknown:
            raise ValueError(f"unknown network controls: {sorted(unknown)!r}")
        if not self.available:
            if controls:
                raise NetworkUnavailable("network enforcement is not enabled")
            return
        try:
            if "safe_search" in controls:
                self._prepare_resolver()
            self._apply_ruleset(_desired_ruleset(self.owner_uid, controls))
        except CollisionError:
            self._healthy = False
            raise
        except NetworkError:
            self._healthy = False
            self._fence_quietly()
            raise
        if not controls:
            try:
                self._teardown_resolver()
            except NetworkError:
                self._healthy = False
                self._fence_quietly()
                raise
        self._healthy = True

    def recover(self) -> None:
        """Remove every owned network resource (local root console recovery).

        Order matters: resolver stopped, then config removed, then the table
        deleted, then the boot-fence unit disabled, and only after all of
        those succeed is the opt-in marker removed (full opt-out). A failure
        at any step raises and leaves the marker in place, so the machine
        stays fenced (the boot fence re-secures on the next boot) and the
        operator can retry.
        """
        self._teardown_resolver()
        self._remove_owned_table()
        self._disable_boot_fence()
        remove_network_marker(self.data_dir, expected_owner=self._marker_owner)
        self._healthy = False

    def _remove_owned_table(self) -> None:
        exists, observed = self._inspect()
        if not exists:
            return
        if observed is None or observed.comment != OWNERSHIP_COMMENT:
            raise CollisionError(f"table {TABLE_NAME} is owned by another process")
        self._apply_ruleset({"comment": OWNERSHIP_COMMENT, "chains": {}, "rules": {}})

    # -- dedicated resolver ---------------------------------------------------

    def _prepare_resolver(self) -> None:
        """Ensure the dedicated resolver is healthy before redirects point at it.

        Steady state (owned config + active unit + passing health) costs only
        local health probes: no upstream DNS lookup, no config rewrite, no
        unit restart.
        """
        cached = self._read_owned_config_ips()
        if cached is not None and self._unit_active(RESOLVER_UNIT):
            expected = {
                source: cached[target]
                for _provider, source, target in SAFESEARCH_MAPPINGS
            }
            try:
                if self._probe_resolver_health(expected):
                    return
            except ResolverError:
                # A live unit can be between activation and bind; the
                # bounded post-start probe below handles that race.
                pass
        resolved = self._resolve_target_ips()
        changed = self._write_resolver_config(render_resolver_config(resolved))
        active = self._unit_active(RESOLVER_UNIT)
        if changed or not active:
            verb = "restart" if active else "start"
            cp = self._systemctl(verb, RESOLVER_UNIT)
            if cp.returncode != 0:
                raise ResolverError(
                    f"cannot {verb} {RESOLVER_UNIT}: {cp.stderr.decode('utf-8', 'replace').strip()}"
                )
        if not self._unit_becomes_active(RESOLVER_UNIT):
            raise ResolverError(f"{RESOLVER_UNIT} did not become active")
        expected = {
            source: resolved[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        deadline = time.monotonic() + 5.0
        while True:
            try:
                if self._probe_resolver_health(expected):
                    break
            except ResolverError:
                if time.monotonic() >= deadline:
                    raise
            if time.monotonic() >= deadline:
                raise ResolverError("dedicated resolver health check failed")
            time.sleep(0.1)

    def _probe_resolver_health(self, expected: Mapping[str, tuple[str, ...]]) -> bool:
        """resolver_health with socket/parse failures mapped to ResolverError."""
        try:
            return resolver_health(expected, query=self._query)
        except (OSError, ValueError, TypeError) as exc:
            raise ResolverError(f"dedicated resolver health probe failed: {exc}") from exc

    def _teardown_resolver(self) -> None:
        """Stop the resolver unit and remove the owned config.

        Ownership is verified BEFORE any state changes: a foreign config
        file (wrong type, owner, or content) collides while the unit and the
        file are still untouched.
        """
        owned = False
        try:
            st = os.lstat(self.resolver_config)
        except FileNotFoundError:
            st = None
        except OSError as exc:
            raise ResolverError(f"cannot stat resolver config: {exc}") from exc
        if st is not None:
            if (
                (st.st_mode & 0o170000) != 0o100000
                or st.st_uid != self._marker_owner
                or (st.st_mode & 0o7777) != 0o644
            ):
                raise CollisionError(f"resolver config {self.resolver_config} is not owned")
            try:
                fd = os.open(self.resolver_config, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                raise ResolverError(f"cannot open resolver config: {exc}") from exc
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                raise ResolverError(f"resolver config {self.resolver_config} is too large")
            if not data.decode("utf-8", "replace").startswith(RESOLVER_BEGIN + "\n"):
                raise CollisionError(f"resolver config {self.resolver_config} is not owned")
            owned = True
        cp = self._systemctl("stop", RESOLVER_UNIT)
        if cp.returncode != 0 and b"not loaded" not in (cp.stderr or b""):
            raise ResolverError(
                f"cannot stop {RESOLVER_UNIT}: {cp.stderr.decode('utf-8', 'replace').strip()}"
            )
        if owned:
            try:
                os.unlink(self.resolver_config)
            except OSError as exc:
                raise ResolverError(f"cannot remove resolver config: {exc}") from exc

    def _read_owned_config_ips(self) -> dict[str, tuple[str, ...]] | None:
        """Parse the owned config as {target: A records}; None when absent."""
        try:
            st = os.lstat(self.resolver_config)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if (
            (st.st_mode & 0o170000) != 0o100000
            or st.st_uid != self._marker_owner
            or (st.st_mode & 0o7777) != 0o644
        ):
            raise CollisionError(f"resolver config {self.resolver_config} is not owned")
        try:
            fd = os.open(self.resolver_config, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ResolverError(f"cannot open resolver config: {exc}") from exc
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ResolverError(f"resolver config {self.resolver_config} is too large")
        return _parse_resolver_config(data)

    def _write_resolver_config(self, config: str) -> bool:
        """Atomically replace the owned config; returns True when changed.

        An existing file that is not an owner regular file carrying our
        ownership sentinel is a collision and aborts before any change.
        """
        path = self.resolver_config
        new = config.encode("utf-8")
        existing: bytes | None
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ResolverError(f"cannot stat resolver config: {exc}") from exc
        else:
            if (
                (st.st_mode & 0o170000) != 0o100000
                or st.st_uid != self._marker_owner
                or (st.st_mode & 0o7777) != 0o644
            ):
                raise CollisionError(f"resolver config {path} is not owned")
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                raise ResolverError(f"cannot open resolver config: {exc}") from exc
            with os.fdopen(fd, "rb") as stream:
                existing = stream.read(65537)
            if len(existing) > 65536:
                raise ResolverError(f"resolver config {path} is too large")
        if existing is not None and not existing.decode("utf-8", "replace").startswith(
            RESOLVER_BEGIN + "\n"
        ):
            raise CollisionError(f"resolver config {path} is not owned")
        if existing == new:
            return False
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".dbnet-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(new)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True

    def _resolve_target_ips(self) -> dict[str, tuple[str, ...]]:
        try:
            resolved: dict[str, tuple[str, ...]] = {}
            for target in SAFESEARCH_TARGETS:
                ips = self._lookup_a(target)
                if not ips:
                    raise ResolverError(f"no A record for SafeSearch target {target}")
                resolved[target] = tuple(sorted(ips))
            return resolved
        except NetworkError:
            cached = self._read_owned_config_ips()
            if cached is not None:
                return cached
            raise

    def _lookup_a(self, name: str) -> list[str]:
        last_exc: Exception | None = None
        for family, addr in UPSTREAM_ADDRESSES:
            try:
                rcode, values = self._query(family, addr, UPSTREAM_PORT, name, _QTYPE_A)
                if rcode != 0:
                    last_exc = NetworkError(f"upstream DNS rcode {rcode} for {name}")
                    continue
                return values
            except (OSError, ValueError, TypeError) as exc:
                last_exc = exc
        raise ResolverError(f"cannot resolve {name} via trusted upstream: {last_exc}")

    def _unit_active(self, unit: str) -> bool:
        cp = self._systemctl("is-active", unit)
        return cp.returncode == 0 and (cp.stdout or b"").strip() == b"active"

    def _unit_becomes_active(self, unit: str) -> bool:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._unit_active(unit):
                return True
            time.sleep(0.25)
        return self._unit_active(unit)


def main(argv: list[str]) -> int:
    """Boot-console entry point: ``boot-fence`` or ``recover``.

    Runs as root from the boot-fence unit (``boot-fence``) or the local
    recovery script (``recover``). Reads the protected owner uid itself from
    ``/var/lib/distraction-blocker/owner.uid``. ``boot-fence`` installs the
    emergency fence when network enforcement was enabled at shutdown (the
    marker survives ``recover``-less operation, so a stale fence may remain
    after a crash). ``recover`` tears down the resolver, the table, the
    boot-fence unit enablement, and finally the opt-in marker.
    """
    if len(argv) != 1 or argv[0] not in ("boot-fence", "recover"):
        print("usage: network_entry boot-fence|recover", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("network_entry: must run as root", file=sys.stderr)
        return 1
    try:
        owner_uid = read_owner_uid(DATA_DIR)
    except NetworkError as exc:
        print(f"network_entry: {exc}", file=sys.stderr)
        return 1
    enforcer = NetworkEnforcer(owner_uid, DATA_DIR)
    try:
        if argv[0] == "boot-fence":
            if not enforcer.available:
                print("network_entry: network enforcement not enabled")
                return 0
            enforcer.fence()
            print("network_entry: boot fence installed")
        else:
            stopped = enforcer._systemctl(
                "stop", "distraction-blocker.service", BOOT_FENCE_UNIT
            )
            if stopped.returncode:
                raise NetworkError("cannot stop policy and boot-fence services for recovery")
            enforcer.recover()
            print("network_entry: network enforcement state removed")
    except (NetworkError, OSError) as exc:
        print(f"network_entry: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))