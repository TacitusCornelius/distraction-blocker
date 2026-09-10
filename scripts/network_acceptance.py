#!/usr/bin/env python3
"""Exercise real protected-user networking in an explicitly marked disposable VM.

Requires Ubuntu 24.04, root, nftables, dnsmasq-base, iproute2, and the existing
/etc/distraction-blocker-test-vm marker. Refuses an existing installation.
Canaries live in a temporary network namespace, not on the workstation or
public Internet. SafeSearch target discovery uses only the trusted upstream;
the DoH catalog is static code-owned data and needs no runtime DNS.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from distraction_blocker.network_enforcement import (
    DOH_ENDPOINT_ADDRESSES,
    PROXY_ENDPOINT_PORTS,
    VPN_ENDPOINT_PORTS,
)
MARKER = Path('/etc/distraction-blocker-test-vm')
STATE = Path('/var/lib/distraction-blocker')
PREFIX = Path('/usr/lib/distraction-blocker')
NS = 'db-network-acceptance'
VETH = 'db-acc-host'
PEER = 'db-acc-peer'
V4 = '10.203.240.2'
V6 = 'fd42:db:ac::2'
DOH_V4 = next(address for address in DOH_ENDPOINT_ADDRESSES if ':' not in address)
DOH_V6 = next(address for address in DOH_ENDPOINT_ADDRESSES if ':' in address)
PROXY_PORT = PROXY_ENDPOINT_PORTS[0]
VPN_PORT = VPN_ENDPOINT_PORTS[0]
FOREIGN = 'db_acceptance_foreign'
RULE_ID = '55555555-5555-4555-8555-555555555555'
SOURCES = {
    'www.google.com': 'forcesafesearch.google.com',
    'www.bing.com': 'strict.bing.com',
    'www.youtube.com': 'restrict.youtube.com',
}


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, check=False, capture_output=True, text=True,
                            timeout=60, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def require_vm():
    if os.geteuid() != 0 or run('systemd-detect-virt', '--vm', '--quiet', check=False).returncode:
        raise RuntimeError('requires root inside a disposable virtual machine')
    if MARKER.is_symlink() or not MARKER.is_file():
        raise RuntimeError('missing protected disposable-VM marker')
    st = MARKER.stat()
    if st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError('VM marker must be root-owned mode 0600')
    marker = json.loads(MARKER.read_text())
    if set(marker) != {'purpose', 'owner_uid'} or marker['purpose'] != 'distraction-blocker-acceptance':
        raise RuntimeError('wrong VM marker purpose')
    uid = marker['owner_uid']
    if type(uid) is not int or uid <= 0:
        raise RuntimeError('invalid protected UID')
    pwd.getpwuid(uid)
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise RuntimeError('requires Ubuntu 24.04')
    return uid


def query_packet(name, qtype=1):
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'
    return struct.pack('!6H', 17341, 0x100, 1, 0, 0, 0) + question + struct.pack('!HH', qtype, 1)


def skip_name(packet, offset):
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xc0 == 0xc0:
            return offset + 1
        offset += length


def addresses(packet):
    _, flags, questions, answers, _, _ = struct.unpack('!6H', packet[:12])
    if not flags & 0x8000 or flags & 15:
        raise RuntimeError('DNS response was not successful')
    offset = 12
    for _ in range(questions):
        offset = skip_name(packet, offset) + 4
    found = []
    for _ in range(answers):
        offset = skip_name(packet, offset)
        kind, _, _, size = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        if kind in (1, 28):
            found.append(str(ipaddress.ip_address(packet[offset:offset + size])))
        elif kind in (64, 65):
            found.append('unexpected service binding')
        offset += size
    return sorted(found)


def receive(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('connection closed')
        data += part
    return data


def dns(sock, name, qtype=1, tcp=False):
    packet = query_packet(name, qtype)
    sock.sendall(struct.pack('!H', len(packet)) + packet if tcp else packet)
    reply = receive(sock, struct.unpack('!H', receive(sock, 2))[0]) if tcp else sock.recv(4096)
    return addresses(reply)


def probe_worker(pipe, uid):
    if uid:
        account = pwd.getpwuid(uid)
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(uid)
    held = {}
    sys.path.insert(0, str(PREFIX))
    from distraction_blocker.rpc import Client
    while True:
        request = pipe.recv()
        if request is None:
            break
        try:
            action = request['action']
            if action == 'rpc':
                result = Client().request(request['command'], **request.get('fields', {}))
            else:
                key = request.get('key')
                sock = held.get(key) if key else None
                if sock is None:
                    address = request['address']
                    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                                         socket.SOCK_STREAM if request.get('tcp', True) else socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    sock.connect((address, request['port']))
                    if key:
                        held[key] = sock
                try:
                    if action == 'dns':
                        result = dns(sock, request['name'], request.get('qtype', 1), request.get('tcp', False))
                    else:
                        sock.sendall(b'canary\n')
                        result = sock.recv(128).decode() == 'canary\n'
                finally:
                    if not key:
                        sock.close()
            pipe.send({'ok': True, 'result': result})
        except Exception as error:
            pipe.send({'ok': False, 'error': str(error)})
    for sock in held.values():
        sock.close()


class Probe:
    def __init__(self, uid):
        self.pipe, child = multiprocessing.Pipe()
        self.process = multiprocessing.get_context('fork').Process(target=probe_worker, args=(child, uid))
        self.process.start()
        child.close()

    def ask(self, **request):
        self.pipe.send(request)
        if not self.pipe.poll(40):
            raise RuntimeError(f'probe timed out: {request}')
        return self.pipe.recv()

    def rpc(self, command, **fields):
        response = self.ask(action='rpc', command=command, fields=fields)
        if not response['ok']:
            raise RuntimeError(f'{command}: {response}')
        return response['result']

    def close(self):
        self.pipe.send(None)
        self.process.join(3)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join()
        self.pipe.close()


def answer(packet):
    end = skip_name(packet, 12) + 4
    qtype = struct.unpack('!H', packet[end - 4:end - 2])[0]
    header = packet[:2] + struct.pack('!5H', 0x8180, 1, int(qtype == 1), 0, 0)
    record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('203.0.113.42')
    return header + packet[12:end] + (record if qtype == 1 else b'')


def serve_connection(sock, is_dns):
    with sock:
        sock.settimeout(60)
        try:
            while True:
                if is_dns:
                    packet = receive(sock, struct.unpack('!H', receive(sock, 2))[0])
                    reply = answer(packet)
                    sock.sendall(struct.pack('!H', len(reply)) + reply)
                else:
                    packet = sock.recv(1024)
                    if not packet:
                        return
                    sock.sendall(packet)
        except (OSError, RuntimeError):
            return


def listener(address, port, tcp=True):
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                         socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if ':' in address:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    if tcp:
        sock.listen()
    def loop():
        while True:
            if tcp:
                connection, _ = sock.accept()
                threading.Thread(target=serve_connection, args=(connection, port == 53), daemon=True).start()
            else:
                packet, peer = sock.recvfrom(4096)
                sock.sendto(answer(packet) if port == 53 else packet, peer)
    threading.Thread(target=loop, daemon=True).start()
    return sock


def serve():
    canary_ports = (53, 853, 18080, *PROXY_ENDPOINT_PORTS, *VPN_ENDPOINT_PORTS)
    sockets = [listener(address, port, tcp) for address in (V4, V6)
               for port in canary_ports for tcp in (True, False)]
    sockets.extend(listener(DOH_V4, 443, tcp) for tcp in (True, False))
    sockets.extend(listener(DOH_V6, 443, tcp) for tcp in (True, False))
    print('canaries ready', flush=True)
    threading.Event().wait()


def controls(owner, *names):
    if not names:
        return owner.rpc('set_enabled', rule_id=RULE_ID, enabled=False)
    if any(rule["id"] == RULE_ID and rule["enabled"] for rule in owner.rpc("list_rules")["rules"]):
        owner.rpc("set_enabled", rule_id=RULE_ID, enabled=False)
    return owner.rpc('put_rule', rule={
        'id': RULE_ID, 'name': 'Network acceptance', 'enabled': True,
        'targets': [{'kind': 'network', 'value': name} for name in names],
        'schedule': {'kind': 'indefinite'}, 'revision': 0,
    })


def expect(probe, allowed, **request):
    result = probe.ask(**request)
    success = result['ok'] and bool(result.get('result'))
    if success != allowed:
        raise RuntimeError(f'expected allowed={allowed}: {request}: {result}')
    return result.get('result')


def wait_for(predicate, label):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise RuntimeError(f'timed out waiting for {label}')


def install(uid, network):
    flags = ['--enable-network-controls', '--accept-network-risk'] if network else []
    result = run(sys.executable, str(ROOT / 'scripts/install.py'), '--confirm', '--owner-uid', str(uid), *flags)
    print(result.stdout, end='', flush=True)


def uninstall():
    result = run(sys.executable, str(ROOT / 'scripts/uninstall.py'), '--confirm', '--remove-policy')
    print(result.stdout, end='', flush=True)


def main(keep_installed):
    uid = require_vm()
    if PREFIX.exists() or STATE.exists():
        raise RuntimeError('refusing to replace an existing installation or protected state')
    if run('ip', 'link', 'show', VETH, check=False).returncode == 0:
        raise RuntimeError('canary veth already exists')
    if NS in run('ip', 'netns', 'list').stdout.split():
        raise RuntimeError('canary namespace already exists')
    if run('nft', 'list', 'table', 'inet', FOREIGN, check=False).returncode == 0:
        raise RuntimeError('foreign sentinel name already exists')
    snapshot = {str(path): path.read_bytes() for path in (
        Path('/etc/resolv.conf'), Path('/etc/systemd/resolved.conf')) if path.is_file()}
    peers = []
    server = None
    installed = False
    run('ip', 'netns', 'add', NS)
    try:
        run('ip', 'link', 'add', VETH, 'type', 'veth', 'peer', 'name', PEER)
        run('ip', 'link', 'set', PEER, 'netns', NS)
        for prefix, device, v4, v6 in (([], VETH, '10.203.240.1/30', 'fd42:db:ac::1/64'),
                                      (['-n', NS], PEER, V4 + '/30', V6 + '/64')):
            run('ip', *prefix, 'addr', 'add', v4, 'dev', device)
            run('ip', *prefix, '-6', 'addr', 'add', v6, 'dev', device, 'nodad')
            run('ip', *prefix, 'link', 'set', device, 'up')
        run('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        # Route one catalogued address of each family into the canary
        # namespace. The wildcard port-443 listeners make the test exercise
        # the real protected-UID nftables address/transport decision without
        # contacting the public Internet.
        run('ip', 'route', 'add', DOH_V4 + '/32', 'via', '10.203.240.2', 'dev', VETH)
        run('ip', '-6', 'route', 'add', DOH_V6 + '/128',
            'via', 'fd42:db:ac::2', 'dev', VETH)
        run('ip', '-n', NS, 'addr', 'add', DOH_V4 + '/32', 'dev', 'lo')
        run('ip', '-n', NS, '-6', 'addr', 'add', DOH_V6 + '/128', 'dev', 'lo', 'nodad')
        run('nft', 'add', 'table', 'inet', FOREIGN)
        foreign = run('nft', '-j', 'list', 'table', 'inet', FOREIGN).stdout
        server = subprocess.Popen(['ip', 'netns', 'exec', NS, sys.executable, __file__, '--serve'],
                                  stdout=subprocess.PIPE, text=True)
        if server.stdout.readline().strip() != 'canaries ready':
            raise RuntimeError('canary server failed')
        local = [listener(address, 18081) for address in ('127.0.0.1', '::1')]
        install(uid, True)
        installed = True
        owner, root = Probe(uid), Probe(0)
        peers.extend((owner, root))
        wait_for(lambda: owner.ask(action='rpc', command='status').get('result', {}).get('healthy', False),
                 'healthy policy RPC')
        expect(owner, True, action='echo', address=V4, port=18080, key='established')
        for address in (V4, V6):
            expect(owner, True, action='echo', address=address, port=18080)
            for tcp in (False, True):
                expect(owner, True, action='dns', address=address, port=53, tcp=tcp, name='canary.invalid')
                expect(owner, True, action='echo', address=address, port=853, tcp=tcp)
        print('PASS baseline IPv4/IPv6 canaries and owner RPC', flush=True)

        controls(owner, 'whole_internet')
        expect(owner, False, action='echo', key='established', address=V4, port=18080)
        for address in (V4, V6):
            expect(owner, False, action='echo', address=address, port=18080)
            expect(root, True, action='echo', address=address, port=18080)
        for address in ('127.0.0.1', '::1'):
            expect(owner, True, action='echo', address=address, port=18081)
        if owner.rpc('status')['active_counts']['network'] != 1:
            raise RuntimeError('wrong active network count')
        print('PASS whole-internet, existing flow denial, UID scope, loopback and RPC', flush=True)

        controls(owner, 'alternate_dns')
        for address in (V4, V6):
            expect(owner, True, action='echo', address=address, port=18080)
            for tcp in (False, True):
                expect(owner, False, action='dns', address=address, port=53, tcp=tcp, name='canary.invalid')
                expect(owner, False, action='echo', address=address, port=853, tcp=tcp)
        expect(owner, True, action='dns', address='127.0.0.53', port=53, tcp=False,
               name='www.google.com', key='old_dns')
        print('PASS alternate DNS/DoT ports without blocking ordinary traffic', flush=True)
        for address in (V4, V6):
            for port in (PROXY_PORT, VPN_PORT):
                for tcp in (False, True):
                    expect(owner, True, action='echo', address=address, port=port, tcp=tcp,
                           key=f'endpoint-{address}-{port}-{tcp}')
                    expect(root, True, action='echo', address=address, port=port, tcp=tcp)
        controls(owner, 'proxy')
        for address in (V4, V6):
            for tcp in (False, True):
                expect(owner, False, action='echo', address=address, port=PROXY_PORT, tcp=tcp)
                expect(owner, False, action='echo', address=address, port=PROXY_PORT, tcp=tcp,
                       key=f'endpoint-{address}-{PROXY_PORT}-{tcp}')
                expect(root, True, action='echo', address=address, port=PROXY_PORT, tcp=tcp)
                expect(owner, True, action='echo', address=address, port=VPN_PORT, tcp=tcp)
        print('PASS common proxy endpoint ports without blocking VPN endpoints', flush=True)
        controls(owner, 'vpn')
        for address in (V4, V6):
            for tcp in (False, True):
                expect(owner, False, action='echo', address=address, port=VPN_PORT, tcp=tcp)
                expect(owner, False, action='echo', address=address, port=VPN_PORT, tcp=tcp,
                       key=f'endpoint-{address}-{VPN_PORT}-{tcp}')
                expect(root, True, action='echo', address=address, port=VPN_PORT, tcp=tcp)
                expect(owner, True, action='echo', address=address, port=PROXY_PORT, tcp=tcp)
        expect(owner, True, action='echo', address=V4, port=18080)
        print('PASS common VPN endpoint ports with protected-UID and root scope', flush=True)

        for address in (DOH_V4, DOH_V6):
            for tcp in (False, True):
                expect(owner, True, action='echo', address=address, port=443,
                       tcp=tcp, key=f'doh-{address}-{tcp}')
                expect(root, True, action='echo', address=address, port=443, tcp=tcp)
        controls(owner, 'doh')
        for address in (DOH_V4, DOH_V6):
            for tcp in (False, True):
                expect(owner, False, action='echo', address=address, port=443,
                       tcp=tcp)
                expect(owner, False, action='echo', address=address, port=443,
                       tcp=tcp, key=f'doh-{address}-{tcp}')
                expect(root, True, action='echo', address=address, port=443, tcp=tcp)
        expect(owner, True, action='echo', address=V4, port=18080)
        print('PASS static DoH catalog blocks TCP/UDP 443 for protected UID', flush=True)

        forced = {source: expect(root, True, action='dns', address='127.0.0.53', port=53,
                                 tcp=False, name=target) for source, target in SOURCES.items()}
        controls(owner, 'safe_search')
        old = owner.ask(action='dns', key='old_dns', address='127.0.0.53', port=53,
                        tcp=False, name='www.google.com')
        if old['ok'] and old['result'] != forced['www.google.com']:
            raise RuntimeError('pre-activation DNS connection bypassed SafeSearch')
        for address in ('127.0.0.53', '::1'):
            for tcp in (False, True):
                for source in SOURCES:
                    result = expect(owner, True, action='dns', address=address, port=53, tcp=tcp, name=source)
                    if result != forced[source]:
                        raise RuntimeError(f'unfiltered DNS answer for {source}: {result}')
                    for qtype in (28, 64, 65):
                        response = owner.ask(action='dns', address=address, port=53, tcp=tcp,
                                             name=source, qtype=qtype)
                        if not response['ok'] or response['result']:
                            raise RuntimeError(f'SafeSearch record leakage: {response}')
        ordinary = expect(root, True, action='dns', address='127.0.0.53', port=53, tcp=False, name='www.google.com')
        if ordinary == forced['www.google.com']:
            raise RuntimeError('root resolver unexpectedly received SafeSearch mapping')
        controls(owner, 'whole_internet', 'safe_search')
        expect(owner, False, action='echo', address=V4, port=18080)
        if expect(owner, True, action='dns', address='127.0.0.53', port=53, tcp=False,
                  name='www.google.com') != forced['www.google.com']:
            raise RuntimeError('whole-internet discarded active SafeSearch')
        print('PASS SafeSearch UDP/TCP IPv4/IPv6, DNS transition and AAAA/SVCB/HTTPS isolation', flush=True)

        run('nft', 'delete', 'table', 'inet', 'distraction_blocker')
        wait_for(lambda: run('nft', 'list', 'table', 'inet', 'distraction_blocker', check=False).returncode == 0,
                 'firewall drift repair')
        expect(owner, False, action='echo', address=V4, port=18080)
        if run('nft', '-j', 'list', 'table', 'inet', FOREIGN).stdout != foreign:
            raise RuntimeError('foreign firewall table changed')
        controls(owner)
        run('systemctl', 'stop', 'distraction-blocker.service')
        run('systemctl', 'restart', 'distraction-blocker-network-restore.service')
        expect(owner, False, action='echo', address=V4, port=18080)
        run('systemctl', 'start', 'distraction-blocker.service')
        wait_for(lambda: owner.ask(action='echo', address=V4, port=18080)['ok'], 'signed inactive-policy reconciliation')
        print('PASS drift repair and boot fence with inactive network policy', flush=True)

        for probe in peers:
            probe.close()
        peers.clear()
        run(sys.executable, str(ROOT / 'scripts/recover_network.py'), '--confirm')
        if (STATE / 'network.enabled').exists() or run('nft', 'list', 'table', 'inet', 'distraction_blocker', check=False).returncode == 0:
            raise RuntimeError('offline recovery left owned enforcement enabled')
        uninstall()
        installed = False
        install(uid, False)
        installed = True
        owner = Probe(uid)
        peers.append(owner)
        wait_for(lambda: owner.ask(action='rpc', command='status').get('result', {}).get('healthy', False),
                 'default installation RPC')
        denied = owner.ask(action='rpc', command='put_rule', fields={'rule': {
            'id': RULE_ID, 'name': 'Unavailable', 'enabled': False,
            'targets': [{'kind': 'network', 'value': 'whole_internet'}],
            'schedule': {'kind': 'indefinite'}, 'revision': 0}})
        if denied['ok'] or not denied.get('error', '').startswith('network_unavailable:'):
            raise RuntimeError(f'default installation did not explicitly refuse network policy: {denied}')
        owner.close()
        peers.clear()
        uninstall()
        installed = False
        if run('nft', '-j', 'list', 'table', 'inet', FOREIGN).stdout != foreign:
            raise RuntimeError('recovery/uninstall touched foreign firewall table')
        for name, data in snapshot.items():
            if Path(name).read_bytes() != data:
                raise RuntimeError(f'global resolver file changed: {name}')
        print('PASS offline recovery, uninstall, default-install refusal and foreign state preservation', flush=True)
        if keep_installed:
            install(uid, True)
            installed = True
        print('NETWORK ACCEPTANCE PASSED', flush=True)
    finally:
        for probe in peers:
            probe.close()
        if server is not None:
            server.terminate()
            server.wait(timeout=5)
        run('nft', 'delete', 'table', 'inet', FOREIGN, check=False)
        run('ip', 'link', 'delete', VETH, check=False)
        run('ip', 'netns', 'delete', NS, check=False)
        if installed:
            print('VM installation retained for inspection; recover/uninstall explicitly when finished.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep-installed', action='store_true')
    parser.add_argument('--serve', action='store_true', help=argparse.SUPPRESS)
    options = parser.parse_args()
    try:
        if options.serve:
            require_vm()
            serve()
        else:
            main(options.keep_installed)
    except Exception as error:
        print(f'NETWORK ACCEPTANCE FAILED: {error}', file=sys.stderr)
        raise
