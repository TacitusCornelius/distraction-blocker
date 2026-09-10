"""Tests for the privileged network-enforcement module.

Everything is in-memory: FakeKernel emulates the owned nftables table and
the two systemd units, and FakeDns emulates the dedicated resolver plus the
trusted upstream. No nft/systemd/package command runs on the workstation.

The fakes speak the *real* wire formats: apply batches are parsed by a
strict text parser (any syntax drift in the module's rendering raises),
listings are rendered as the actual `nft -j list table` JSON schema
(nft 1.0.x) and parsed back by the module, and DNS traffic uses real wire
bytes. The semantic expected states come from _desired_ruleset, so the
round trip (desired -> batch text -> fake kernel -> listing JSON ->
module parse -> compare) is verified end to end.
"""
from __future__ import annotations

import copy
import json
import os
import re
import socket
import struct
import tempfile
import unittest
from unittest import mock

import distraction_blocker.network_enforcement as ne
from distraction_blocker.network_enforcement import (
    BOOT_FENCE_UNIT,
    ApplyError,
    CollisionError,
    DOH_CATALOG_VERSION,
    DOH_ENDPOINT_ADDRESSES,
    DOH_ENDPOINT_CATALOG,
    FENCE_CONTROLS,
    PROXY_CATALOG_VERSION,
    PROXY_ENDPOINT_PORTS,
    VPN_CATALOG_VERSION,
    VPN_ENDPOINT_PORTS,
    VPN_TUNNEL_PROTOCOLS,
    NetworkEnforcer,
    NetworkError,
    NetworkUnavailable,
    OWNERSHIP_COMMENT,
    OWNER_UID_FILE,
    RESOLVER_BEGIN,
    RESOLVER_PORT,
    SAFESEARCH_MAPPINGS,
    SAFESEARCH_TARGETS,
    TABLE_FAMILY,
    TABLE_NAME,
    _desired_ruleset,
    _parse_dns,
    _parse_listing,
    _parse_resolver_config,
    _render_batch,
    _comparable_desired,
    _comparable_observed,
    is_network_enabled,
    main,
    read_owner_uid,
    remove_network_marker,
    render_resolver_config,
    resolver_health,
    write_network_marker,
)

UID = 1000
A_QTYPE = 1
AAAA_QTYPE = 28
SVCB_QTYPE = 64
HTTPS_QTYPE = 65

FENCE_DESIRED = _desired_ruleset(UID, frozenset(FENCE_CONTROLS))
ALT_DESIRED = _desired_ruleset(UID, frozenset({"alternate_dns"}))
SAFE_DESIRED = _desired_ruleset(UID, frozenset({"safe_search"}))
DOH_DESIRED = _desired_ruleset(UID, frozenset({"doh"}))
PROXY_DESIRED = _desired_ruleset(UID, frozenset({"proxy"}))
VPN_DESIRED = _desired_ruleset(UID, frozenset({"vpn"}))
WHOLE_SAFE_DESIRED = _desired_ruleset(
    UID, frozenset({"whole_internet", "safe_search"})
)


class _Result:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _expr_to_json(expr: tuple) -> dict:
    """Canonical tuple -> the real nft 1.0.x JSON expression form."""
    kind = expr[0]
    if kind == "meta":
        return {
            "match": {"op": "==", "left": {"meta": {"key": expr[1]}}, "right": expr[2]}
        }
    if kind == "dport":
        return {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": expr[1], "field": "dport"}},
                "right": expr[2],
            }
        }
    if kind == "daddr":
        text = str(expr[2])
        if "/" in text:
            addr, _, length = text.partition("/")
            right = {"prefix": {"addr": addr, "len": int(length)}}
        else:
            right = text
        return {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": expr[1], "field": "daddr"}},
                "right": right,
            }
        }
    if kind == "dnat":
        return {"dnat": {"family": expr[1], "addr": expr[2], "port": expr[3]}}
    if kind in ("drop", "accept"):
        return {kind: None}
    raise AssertionError(f"unrenderable expression {expr!r}")


def _render_listing(comment, chains, rules) -> bytes:
    """Render kernel state as real `nft -j list table` JSON (nft 1.0.x)."""
    entries = [
        {
            "metainfo": {
                "version": "1.0.9",
                "release_name": "Old Doc Yak #3",
                "json_schema_version": 1,
            }
        },
        {"table": {"family": TABLE_FAMILY, "name": TABLE_NAME, "handle": 5, "comment": comment}},
    ]
    handle = 1
    for name, (ctype, hook, prio, policy) in chains.items():
        entries.append(
            {
                "chain": {
                    "family": TABLE_FAMILY,
                    "table": TABLE_NAME,
                    "name": name,
                    "handle": handle,
                    "type": ctype,
                    "hook": hook,
                    "prio": prio,
                    "policy": policy,
                }
            }
        )
        handle += 1
    for name in chains:
        for exprs in rules.get(name, []):
            entries.append(
                {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": name,
                        "handle": handle,
                        "expr": [_expr_to_json(e) for e in exprs],
                    }
                }
            )
            handle += 1
    return json.dumps({"nftables": entries}).encode("utf-8")


_META_SKUID_RE = re.compile(r"^meta skuid (\d+)")
_META_OIF_RE = re.compile(r"^meta oifname (\S+)")
_META_L4_RE = re.compile(r"^meta l4proto (\S+)")
_DPORT_RE = re.compile(r"^(tcp|udp) dport (\d+)")
_DADDR_RE = re.compile(r"^(ip|ip6) daddr (\S+)")
_DNAT_V4_RE = re.compile(r"^dnat ip to ([^:\s]+):(\d+)")
_DNAT_V6_RE = re.compile(r"^dnat ip6 to \[([^\]]+)\]:(\d+)")


def _parse_rule_line(line: str) -> list:
    """Parse one rule statement: several expressions, then the verdict.

    The module renders each rule as a single space-joined line (real nft
    batch syntax); this strict left-to-right matcher is an independent
    reimplementation of that grammar.
    """
    exprs = []
    rest = line
    while True:
        rest = rest.lstrip()
        if not rest:
            break
        m = _META_SKUID_RE.match(rest)
        if m:
            exprs.append(("meta", "skuid", int(m.group(1))))
            rest = rest[m.end():]
            continue
        m = _META_OIF_RE.match(rest)
        if m:
            exprs.append(("meta", "oifname", m.group(1)))
            rest = rest[m.end():]
            continue
        m = _META_L4_RE.match(rest)
        if m:
            exprs.append(("meta", "l4proto", m.group(1)))
            rest = rest[m.end():]
            continue
        m = _DPORT_RE.match(rest)
        if m:
            exprs.append(("dport", m.group(1), int(m.group(2))))
            rest = rest[m.end():]
            continue
        m = _DADDR_RE.match(rest)
        if m:
            exprs.append(("daddr", m.group(1), m.group(2)))
            rest = rest[m.end():]
            continue
        m = _DNAT_V4_RE.match(rest)
        if m:
            exprs.append(("dnat", "ip", m.group(1), int(m.group(2))))
            rest = rest[m.end():]
            continue
        m = _DNAT_V6_RE.match(rest)
        if m:
            exprs.append(("dnat", "ip6", m.group(1), int(m.group(2))))
            rest = rest[m.end():]
            continue
        if rest in ("drop", "accept"):
            exprs.append((rest,))
            break
        raise ValueError(f"unparseable rule line: {line!r}")
    if not exprs:
        raise ValueError(f"empty rule line: {line!r}")
    return exprs


def _parse_batch(batch: bytes):
    """Parse our exact nft batch syntax into canonical kernel state.

    Returns None for a delete-only batch. Raises ValueError on any drift
    from the format the module is allowed to emit, so a broken render in
    the module surfaces as a failed check/apply in the fake kernel.
    """
    lines = [line.strip() for line in batch.decode("utf-8").splitlines()]
    state = None
    current_chain = None
    for line in lines:
        if line == f"delete table {TABLE_FAMILY} {TABLE_NAME}":
            continue
        if line == f"table {TABLE_FAMILY} {TABLE_NAME} {{":
            state = {"comment": None, "chains": {}, "rules": {}}
            continue
        if line == "}":
            current_chain = None
            continue
        if state is None:
            raise ValueError(f"unexpected line outside table: {line!r}")
        if current_chain is None:
            if line.startswith("comment "):
                comment = line[len("comment "):]
                if not (comment.startswith('"') and comment.endswith('"')):
                    raise ValueError(f"bad comment: {line!r}")
                state["comment"] = comment[1:-1]
            elif line.startswith("chain ") and line.endswith("{"):
                current_chain = line[len("chain "):-1].strip()
                state["chains"][current_chain] = None
                state["rules"][current_chain] = []
            else:
                raise ValueError(f"unexpected table line: {line!r}")
        else:
            m = re.match(r"^type (\S+) hook (\S+) priority (-?\d+);$", line)
            if m:
                state["chains"][current_chain] = (
                    m.group(1),
                    m.group(2),
                    int(m.group(3)),
                    "accept",
                )
                continue
            if line == "policy accept;":
                continue
            state["rules"][current_chain].append(tuple(_parse_rule_line(line)))
    if state is None:
        return None
    for name, spec in state["chains"].items():
        if spec is None:
            raise ValueError(f"chain {name} has no spec")
    return state


def _canon(state: dict) -> tuple:
    """Comparable form of a batch-parsed or desired state."""
    return (
        state["comment"],
        tuple(sorted(state["chains"].items())),
        tuple(sorted((name, tuple(rules)) for name, rules in state["rules"].items())),
    )


class FakeKernel:
    """Emulates the owned nftables table and the two systemd units.

    Table state is stored in canonical kernel form, re-rendered as real
    `nft -j list table` JSON; apply batches are parsed strictly.
    """

    def __init__(self) -> None:
        self.state = None
        self.fail_check = False
        self.fail_apply = False
        self.dns_unit_active = False
        self.boot_fence_disabled = False
        self.calls = []
        self.checks = []
        self.applies = []
        self.failed = []

    def __call__(self, argv, data):
        self.calls.append(tuple(argv))
        if argv[0] == "nft":
            return self._nft(tuple(argv[1:]), data)
        if argv[0] == "systemctl":
            return self._systemctl(tuple(argv[1:]))
        return _Result(1, stderr=b"unexpected binary: " + argv[0].encode())

    def _nft(self, args, data):
        if args == ("-j", "list", "table", TABLE_FAMILY, TABLE_NAME):
            if self.state is None:
                return _Result(1, stderr=b"Error: No such file or directory")
            return _Result(0, stdout=self._listing())
        if args == ("-c", "-f", "-"):
            self.checks.append(data)
            if self.fail_check:
                self.fail_check = False
                self.failed.append("check")
                return _Result(1, stderr=b"Error: Collision at line 1")
            try:
                _parse_batch(data)
            except ValueError as exc:
                return _Result(1, stderr=f"Error: bad batch: {exc}".encode())
            return _Result(0)
        if args == ("-f", "-"):
            self.applies.append(data)
            if self.fail_apply:
                self.fail_apply = False
                self.failed.append("apply")
                return _Result(1, stderr=b"Error: failed to process the ruleset")
            try:
                self.state = _parse_batch(data)
            except ValueError as exc:
                return _Result(1, stderr=f"Error: bad batch: {exc}".encode())
            return _Result(0)
        return _Result(1, stderr=b"unexpected nft args: " + b" ".join(a.encode() for a in args))

    def _listing(self):
        return _render_listing(self.state["comment"], self.state["chains"], self.state["rules"])

    def _systemctl(self, args):
        verb = args[0] if args else ""
        unit = args[1] if len(args) > 1 else None
        if verb in ("start", "restart") and unit == ne.RESOLVER_UNIT:
            self.dns_unit_active = True
            return _Result(0)
        if verb == "stop" and unit == ne.RESOLVER_UNIT:
            self.dns_unit_active = False
            return _Result(0)
        if verb == "is-active" and unit == ne.RESOLVER_UNIT:
            out = b"active\n" if self.dns_unit_active else b"inactive\n"
            return _Result(0, stdout=out)
        if verb == "disable" and unit == BOOT_FENCE_UNIT:
            self.boot_fence_disabled = True
            return _Result(0)
        return _Result(1, stderr=b"unexpected unit: " + (unit or b"?").encode())


class FakeDns:
    """Emulates the dedicated resolver (port 1053) and trusted upstream (53)."""

    def __init__(self) -> None:
        self.upstream_a = {
            target: (f"203.0.113.{10 + i}",)
            for i, target in enumerate(SAFESEARCH_TARGETS)
        }
        self.enforced = {
            source: self.upstream_a[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        self.fail_upstream = False
        self.health_error = None
        self.metadata_records = set()
        self.calls = []

    def __call__(self, family, addr, port, name, qtype, timeout=2.0):
        self.calls.append((addr, port, name, qtype))
        if self.health_error is not None:
            raise self.health_error
        if port == RESOLVER_PORT:
            if qtype in (SVCB_QTYPE, HTTPS_QTYPE):
                return 0, ["metadata"] if name in self.metadata_records else []
            if qtype == AAAA_QTYPE:
                return 0, []
            ips = self.enforced.get(name)
            if ips is None:
                return 3, []  # NXDOMAIN for unknown names
            return 0, list(ips)
        if port == 53:
            if self.fail_upstream:
                raise OSError("connection refused")
            if family != socket.AF_INET:
                raise OSError("no v6 upstream")
            return 0, list(self.upstream_a.get(name, ()))
        raise ValueError(f"unexpected port {port}")

    def upstream_calls(self):
        return [c for c in self.calls if c[1] == 53]

    def health_calls(self):
        return [c for c in self.calls if c[1] == RESOLVER_PORT]


def _first_index(calls, prefix):
    for i, call in enumerate(calls):
        if call[: len(prefix)] == prefix:
            return i
    return -1


def _write_marker(data_dir: str) -> None:
    write_network_marker(data_dir, expected_owner=os.geteuid(), chown=False)


def _write_owner_uid(data_dir: str, uid: int = UID) -> None:
    path = os.path.join(data_dir, OWNER_UID_FILE)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(f"{uid}\n".encode("ascii"))


class EnforcerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = self.tmp.name
        self.kernel = FakeKernel()
        self.dns = FakeDns()
        self.conf = os.path.join(self.data, "resolver.conf")
        _write_marker(self.data)
        _write_owner_uid(self.data)
        self.enforcer = NetworkEnforcer(
            UID,
            self.data,
            runner=self.kernel,
            query=self.dns,
            resolver_config=self.conf,
        )
        self.enforcer._marker_owner = os.geteuid()

    def _conf_bytes(self) -> bytes | None:
        try:
            with open(self.conf, "rb") as stream:
                return stream.read()
        except FileNotFoundError:
            return None


class WireFormatTests(unittest.TestCase):
    def test_encode_query_wire_format(self):
        payload = ne._encode_query(b"\x12\x34", "google.com", A_QTYPE)
        expected = (
            b"\x12\x34"
            + b"\x01\x00"  # RD set, RA clear
            + struct.pack(">HHHH", 1, 0, 0, 0)
            + b"\x06google\x03com\x00"
            + struct.pack(">HH", A_QTYPE, 1)
        )
        self.assertEqual(payload, expected)

    def test_parse_dns_response_with_compression_pointer(self):
        name = b"\x06google\x03com\x00"
        question = name + struct.pack(">HH", A_QTYPE, 1)
        answer = (
            name  # first answer repeats the name
            + struct.pack(">HHIH", A_QTYPE, 1, 60, 4)
            + bytes([1, 2, 3, 4])
            + b"\xc0\x0c"  # compression pointer back to the question name
            + struct.pack(">HHIH", A_QTYPE, 1, 60, 4)
            + bytes([5, 6, 7, 8])
        )
        payload = b"\x0d\x03" + b"\x81\x80" + struct.pack(">HHHH", 1, 2, 0, 0) + question + answer
        txid, rcode, answers = _parse_dns(payload)
        self.assertEqual(txid, b"\x0d\x03")
        self.assertEqual(rcode, 0)
        self.assertEqual(answers, [(1, 1, b"\x01\x02\x03\x04"), (1, 1, b"\x05\x06\x07\x08")])

    def test_parse_dns_rcode(self):
        name = b"\x01a\x00"
        question = name + struct.pack(">HH", A_QTYPE, 1)
        payload = b"\x00\x01" + b"\x81\x83" + struct.pack(">HHHH", 1, 0, 0, 0) + question
        _txid, rcode, answers = _parse_dns(payload)
        self.assertEqual(rcode, 3)
        self.assertEqual(answers, [])



class ResolverConfigTests(unittest.TestCase):
    def _resolved(self):
        return {
            target: (f"203.0.113.{20 + i}",) for i, target in enumerate(SAFESEARCH_TARGETS)
        }

    def test_render_and_parse_round_trip(self):
        resolved = self._resolved()
        config = render_resolver_config(resolved)
        self.assertTrue(config.startswith(RESOLVER_BEGIN + "\n"))
        self.assertEqual(
            _parse_resolver_config(config.encode("utf-8")),
            {target: ips for target, ips in sorted(resolved.items())},
        )

    def test_parse_rejects_foreign_or_incomplete(self):
        resolved = self._resolved()
        good = render_resolver_config(resolved)
        self.assertIsNone(_parse_resolver_config(b"port=53\n"))
        missing_source = "\n".join(
            line for line in good.splitlines() if "www.google.com" not in line
        )
        self.assertIsNone(_parse_resolver_config(missing_source.encode("utf-8")))
        empty_source = good.replace("address=/google.com/203.0.113.10\n", "")
        # google.com still has its address line? remove all google.com addresses
        empty_source = "\n".join(
            line
            for line in good.splitlines()
            if not line.startswith("address=/google.com/")
        )
        self.assertIsNone(_parse_resolver_config(empty_source.encode("utf-8")))

    def test_parse_rejects_split_targets(self):
        resolved = self._resolved()
        config = render_resolver_config(resolved)
        # Give the google sources an extra IP not shared by all google sources.
        doctored = config + "address=/www.google.com/198.51.100.99\n"
        self.assertIsNone(_parse_resolver_config(doctored.encode("utf-8")))

    def test_resolver_health_requires_exact_mapping(self):
        resolved = self._resolved()
        expected = {
            source: resolved[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        dns = FakeDns()
        # FakeDns.upstream_a differs from `resolved`; point it at resolved.
        dns.upstream_a = dict(resolved)
        dns.enforced = {
            source: resolved[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        self.assertTrue(resolver_health(expected, query=dns))
        dns.enforced["bing.com"] = ("198.51.100.7",)
        self.assertFalse(resolver_health(expected, query=dns))

    def test_resolver_health_rejects_service_metadata_records(self):
        resolved = self._resolved()
        expected = {
            source: resolved[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        dns = FakeDns()
        dns.enforced = {
            source: resolved[target]
            for _provider, source, target in SAFESEARCH_MAPPINGS
        }
        dns.metadata_records.add("google.com")
        self.assertFalse(resolver_health(expected, query=dns))


class MarkerGateTests(EnforcerTestCase):
    def test_no_marker_rejects_with_no_side_effects(self):
        os.unlink(ne.marker_path(self.data))
        self.assertFalse(self.enforcer.available)
        self.assertFalse(self.enforcer.healthy)
        with self.assertRaises(NetworkUnavailable):
            self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertEqual(self.kernel.calls, [])
        self.assertEqual(self.dns.calls, [])

    def test_unknown_control_rejected_before_any_side_effect(self):
        with self.assertRaises(ValueError):
            self.enforcer.reconcile(frozenset({"whole_internet", "nope"}))
        self.assertEqual(self.kernel.calls, [])
        self.assertEqual(self.dns.calls, [])

    def test_marker_validity_checks(self):
        marker = ne.marker_path(self.data)
        self.assertTrue(is_network_enabled(self.data, expected_owner=os.geteuid()))
        with open(marker, "wb") as stream:
            stream.write(b"foreign content\n")
        self.assertFalse(is_network_enabled(self.data, expected_owner=os.geteuid()))
        os.unlink(marker)
        _write_marker(self.data)
        os.chmod(marker, 0o644)
        self.assertFalse(is_network_enabled(self.data, expected_owner=os.geteuid()))
        os.chmod(marker, 0o600)
        self.assertTrue(is_network_enabled(self.data, expected_owner=os.geteuid()))
        os.unlink(marker)
        os.symlink("/etc/hostname", marker)
        self.assertFalse(is_network_enabled(self.data, expected_owner=os.geteuid()))

    def test_write_marker_refuses_foreign_existing(self):
        marker = ne.marker_path(self.data)
        with open(marker, "wb") as stream:
            stream.write(b"someone else's marker\n")
        os.chmod(marker, 0o600)
        with self.assertRaises(CollisionError):
            write_network_marker(self.data, expected_owner=os.geteuid(), chown=False)
        with open(marker, "rb") as stream:
            self.assertEqual(stream.read(), b"someone else's marker\n")

    def test_remove_marker_refuses_foreign(self):
        marker = ne.marker_path(self.data)
        with open(marker, "wb") as stream:
            stream.write(b"not ours\n")
        with self.assertRaises(CollisionError):
            remove_network_marker(self.data, expected_owner=os.geteuid())
        self.assertTrue(os.path.exists(marker))

    def test_read_owner_uid(self):
        self.assertEqual(read_owner_uid(self.data, expected_owner=os.geteuid()), UID)
        uid_file = os.path.join(self.data, OWNER_UID_FILE)
        with open(uid_file, "wb") as stream:
            stream.write(b"0\n")
        with self.assertRaises(NetworkUnavailable):
            read_owner_uid(self.data, expected_owner=os.geteuid())
        with open(uid_file, "wb") as stream:
            stream.write(b"abc\n")
        with self.assertRaises(NetworkUnavailable):
            read_owner_uid(self.data, expected_owner=os.geteuid())
        os.unlink(uid_file)
        with self.assertRaises(NetworkUnavailable):
            read_owner_uid(self.data, expected_owner=os.geteuid())


class WholeInternetTests(EnforcerTestCase):
    def test_first_install_order_and_content(self):
        self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertTrue(self.enforcer.healthy)
        calls = self.kernel.calls
        # inspect -> check -> apply -> verify, nothing else
        self.assertEqual(calls[0][:2], ("nft", "-j"))
        self.assertEqual(_first_index(calls, ("nft", "-c")), 1)
        self.assertEqual(_first_index(calls, ("nft", "-f")), 2)
        self.assertEqual(len([c for c in calls if c[:1] == ("nft",)]), 4)
        # no systemd interaction at all: reconcile never touches boot enablement
        self.assertEqual([c for c in calls if c[:1] == ("systemctl",)], [])
        batch = self.kernel.applies[-1]
        self.assertNotIn(b"delete table", batch)
        self.assertEqual(_canon(_parse_batch(batch)), _canon(FENCE_DESIRED))

    def test_steady_state_makes_no_kernel_writes(self):
        self.enforcer.reconcile(frozenset({"whole_internet"}))
        before = len(self.kernel.calls)
        self.enforcer.reconcile(frozenset({"whole_internet"}))
        new = self.kernel.calls[before:]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0][:2], ("nft", "-j"))
        self.assertTrue(self.enforcer.healthy)

    def test_foreign_table_collision_never_touched(self):
        state = copy.deepcopy(FENCE_DESIRED)
        state["comment"] = "foreign-owner"
        self.kernel.state = state
        with self.assertRaises(CollisionError):
            self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertFalse(self.enforcer.healthy)
        self.assertEqual(self.kernel.checks, [])
        self.assertEqual(self.kernel.applies, [])
        self.assertEqual(self.kernel.state["comment"], "foreign-owner")

    def test_drift_repair_rebuilds_owned_table(self):
        drifted = copy.deepcopy(FENCE_DESIRED)
        drifted["rules"]["output"] = drifted["rules"]["output"][:-1]  # lost the deny
        self.kernel.state = drifted
        self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))
        batch = self.kernel.applies[-1]
        self.assertTrue(batch.startswith(f"delete table {TABLE_FAMILY} {TABLE_NAME}".encode()))

    def test_check_failure_fences_without_applying(self):
        self.kernel.state = copy.deepcopy(SAFE_DESIRED)  # an active, stronger-elsewhere state
        self.kernel.fail_check = True
        with self.assertRaises(NetworkError):
            self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertFalse(self.enforcer.healthy)
        # the failed check was the ONLY check; fence succeeded afterwards
        self.assertEqual(self.kernel.failed, ["check"])
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))

    def test_apply_failure_fences(self):
        self.kernel.state = copy.deepcopy(SAFE_DESIRED)
        self.kernel.fail_apply = True
        with self.assertRaises(NetworkError):
            self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.assertFalse(self.enforcer.healthy)
        self.assertEqual(self.kernel.failed, ["apply"])
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))

    def test_empty_reconcile_deletes_table_atomically(self):
        self.enforcer.reconcile(frozenset({"whole_internet"}))
        self.enforcer.reconcile(frozenset())
        self.assertIsNone(self.kernel.state)
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(
            self.kernel.applies[-1],
            f"delete table {TABLE_FAMILY} {TABLE_NAME}\n".encode("utf-8"),
        )
        self.assertEqual(self.dns.calls, [])


class AlternateDnsTests(EnforcerTestCase):
    def test_reconcile_content_and_no_resolver_side_effects(self):
        self.enforcer.reconcile(frozenset({"alternate_dns"}))
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(ALT_DESIRED))
        # alternate_dns must not prepare the dedicated resolver
        self.assertEqual(self.dns.calls, [])
        self.assertIsNone(self._conf_bytes())



class DohTests(EnforcerTestCase):
    def test_catalog_is_static_closed_and_versioned(self):
        self.assertEqual(DOH_CATALOG_VERSION, 1)
        self.assertTrue(DOH_ENDPOINT_CATALOG)
        addresses = {
            address
            for _endpoint, values in DOH_ENDPOINT_CATALOG
            for address in values
        }
        self.assertEqual(tuple(sorted(addresses)), DOH_ENDPOINT_ADDRESSES)
        self.assertTrue(all(ne.ipaddress.ip_address(address).is_global for address in addresses))

    def test_reconcile_drops_catalog_addresses_on_tcp_and_udp_443(self):
        self.enforcer.reconcile(frozenset({"doh"}))
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(DOH_DESIRED))
        rules = DOH_DESIRED["rules"]["output"]
        self.assertEqual(
            sum(1 for rule in rules if rule[-1] == ("drop",)),
            len(DOH_ENDPOINT_ADDRESSES) * 2,
        )
        for address in DOH_ENDPOINT_ADDRESSES:
            family = "ip6" if ":" in address else "ip"
            for protocol in ("tcp", "udp"):
                self.assertIn(
                    (
                        ("meta", "skuid", UID),
                        ("daddr", family, address),
                        ("dport", protocol, 443),
                        ("drop",),
                    ),
                    rules,
                )
        self.assertEqual(self.dns.calls, [])

class ProxyVpnTests(EnforcerTestCase):
    def test_proxy_catalog_drops_common_listener_ports(self):
        self.assertEqual(PROXY_CATALOG_VERSION, 1)
        self.assertEqual(PROXY_ENDPOINT_PORTS, tuple(sorted(set(PROXY_ENDPOINT_PORTS))))
        self.enforcer.reconcile(frozenset({"proxy"}))
        rules = PROXY_DESIRED["rules"]["output"]
        self.assertEqual(sum(1 for rule in rules if rule[-1] == ("drop",)), len(PROXY_ENDPOINT_PORTS) * 2)
        for port in PROXY_ENDPOINT_PORTS:
            for protocol in ("tcp", "udp"):
                self.assertIn((("meta", "skuid", UID), ("dport", protocol, port), ("drop",)), rules)
        self.assertEqual(self.dns.calls, [])

    def test_vpn_catalog_drops_ports_and_tunnel_protocols(self):
        self.assertEqual(VPN_CATALOG_VERSION, 1)
        self.assertEqual(VPN_ENDPOINT_PORTS, tuple(sorted(set(VPN_ENDPOINT_PORTS))))
        self.assertEqual(VPN_TUNNEL_PROTOCOLS, ("esp", "gre"))
        self.enforcer.reconcile(frozenset({"vpn"}))
        rules = VPN_DESIRED["rules"]["output"]
        self.assertEqual(sum(1 for rule in rules if rule[-1] == ("drop",)), len(VPN_ENDPOINT_PORTS) * 2 + len(VPN_TUNNEL_PROTOCOLS))
        for port in VPN_ENDPOINT_PORTS:
            for protocol in ("tcp", "udp"):
                self.assertIn((("meta", "skuid", UID), ("dport", protocol, port), ("drop",)), rules)
        for protocol in VPN_TUNNEL_PROTOCOLS:
            self.assertIn((("meta", "skuid", UID), ("meta", "l4proto", protocol), ("drop",)), rules)
        self.assertEqual(self.dns.calls, [])


class SafeSearchTests(EnforcerTestCase):

    def test_upstream_down_with_no_config_fails_and_fences(self):
        self.dns.fail_upstream = True
        with self.assertRaises(NetworkError):
            self.enforcer.reconcile(frozenset({"safe_search"}))
        self.assertFalse(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))
        self.assertTrue(self.dns.upstream_calls())

    def test_upstream_down_uses_cached_config(self):
        self.enforcer.reconcile(frozenset({"safe_search"}))
        conf_before = self._conf_bytes()
        self.dns.fail_upstream = True
        self.enforcer.reconcile(frozenset({"safe_search"}))
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(self._conf_bytes(), conf_before)


    def test_stuck_resolver_fences_and_keeps_old_table(self):
        self.enforcer.reconcile(frozenset({"safe_search"}))
        conf_before = self._conf_bytes()
        # the dedicated resolver starts answering with unfiltered IPs
        self.dns.enforced["www.youtube.com"] = ("198.51.100.99",)
        with self.assertRaises(NetworkError):
            self.enforcer.reconcile(frozenset({"safe_search"}))
        self.assertFalse(self.enforcer.healthy)
        # fail-closed: whole-internet fence installed; old config untouched
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))
        self.assertEqual(self._conf_bytes(), conf_before)

    def test_health_probe_failure_fences(self):
        self.enforcer.reconcile(frozenset({"safe_search"}))
        self.dns.health_error = OSError("probe refused")
        with self.assertRaises(NetworkError):
            self.enforcer.reconcile(frozenset({"safe_search"}))
        self.assertFalse(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(FENCE_DESIRED))


    def test_whole_plus_safe_is_superset(self):
        self.enforcer.reconcile(frozenset({"whole_internet", "safe_search"}))
        self.assertTrue(self.enforcer.healthy)
        self.assertEqual(_canon(self.kernel.state), _canon(WHOLE_SAFE_DESIRED))
        output = list(WHOLE_SAFE_DESIRED["rules"]["output"])
        self.assertEqual(output[-1], (("meta", "skuid", UID), ("drop",)))
        self.assertIn("dns_redirect", WHOLE_SAFE_DESIRED["chains"])
        # transition safe -> whole+safe adds the final deny without losing the chain
        self.enforcer.reconcile(frozenset({"safe_search", "whole_internet"}))
        self.assertEqual(_canon(self.kernel.state), _canon(WHOLE_SAFE_DESIRED))


class RecoverTests(EnforcerTestCase):
    def test_recover_removes_every_owned_resource(self):
        self.enforcer.reconcile(frozenset({"safe_search"}))
        self.assertTrue(self.kernel.state is not None)
        self.assertTrue(self.kernel.dns_unit_active)
        self.assertTrue(os.path.exists(self.conf))

        self.enforcer.recover()

        self.assertIsNone(self.kernel.state)
        self.assertFalse(self.kernel.dns_unit_active)
        self.assertTrue(self.kernel.boot_fence_disabled)
        self.assertFalse(os.path.exists(self.conf))
        self.assertFalse(is_network_enabled(self.data, expected_owner=os.geteuid()))

    def test_recover_is_idempotent_when_absent(self):
        self.enforcer.recover()
        self.assertFalse(is_network_enabled(self.data, expected_owner=os.geteuid()))
        self.enforcer.recover()  # second pass: nothing left, no error
        self.assertFalse(self.enforcer.healthy)

    def test_recover_refuses_foreign_config_and_keeps_marker(self):
        with open(self.conf, "wb") as stream:
            stream.write(b"port=53\n")
        os.chmod(self.conf, 0o600)
        with self.assertRaises(CollisionError):
            self.enforcer.recover()
        # failed before any teardown: unit untouched, marker intact
        self.assertEqual([c for c in self.kernel.calls if c[0] == "systemctl"], [])
        self.assertTrue(is_network_enabled(self.data, expected_owner=os.geteuid()))

    def test_recover_refuses_symlinked_config(self):
        target = os.path.join(self.data, "real.conf")
        with open(target, "wb") as stream:
            stream.write(RESOLVER_BEGIN.encode("utf-8") + b"\n")
        os.symlink(target, self.conf)
        with self.assertRaises(CollisionError):
            self.enforcer.recover()


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _run_main(self, argv, *, available=True, side_effect=None):
        stub = mock.Mock(spec=NetworkEnforcer)
        if side_effect is not None:
            stub.fence.side_effect = side_effect
            stub.recover.side_effect = side_effect
        stub.available = available
        stub._systemctl.return_value = _Result(0)
        with mock.patch.object(ne, "DATA_DIR", self.tmp.name), mock.patch.object(
            ne, "NetworkEnforcer", return_value=stub
        ), mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(
            ne, "read_owner_uid", return_value=UID
        ):
            rc = main(argv)
        return rc, stub

    def test_bad_usage(self):
        with mock.patch.object(os, "geteuid", return_value=0):
            self.assertEqual(ne.main([]), 2)
            self.assertEqual(ne.main(["nope"]), 2)
            self.assertEqual(ne.main(["boot-fence", "extra"]), 2)
            self.assertEqual(ne.main(["recover", "extra"]), 2)

    def test_not_root_refuses(self):
        with mock.patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(ne.main(["boot-fence"]), 1)

    def test_boot_fence_disabled_marker(self):
        rc, stub = self._run_main(["boot-fence"], available=False)
        self.assertEqual(rc, 0)
        stub.fence.assert_not_called()


    def test_error_reporting(self):
        rc, stub = self._run_main(
            ["recover"], side_effect=NetworkError("table missing")
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
