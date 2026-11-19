#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""ids_list.py - what the Intrusion Detection's IPS policy drops, blocked and cut for a while (ff-10,
2026-11-19, and its review the same day) - against an eve.json written here as Suricata writes it, with
pf (its table and states), ifconfig, /tmp's gateway and prefix files, resolv.conf, name resolution and the
system log stood in for. No Suricata, no OPNsense, no root:

    python3 tools/test-ids.py

What enters: an alert logged as blocked, over TCP, on a connection Suricata saw established (its
application protocol recognised, packets both ways past the handshake), by a rule that is not one of
Suricata's own event rules; its source. What never does: a lone SYN or a forged one, UDP and ICMP, those
event rules, IDS mode's alerts; the firewall's own addresses (interfaces, virtual IPs, NAT's external
sides - and one it has just been given), its gateways and their monitors, its DNS servers, its VPN peers,
who manages it (a state to its web GUI or SSH), Never block, the special ranges; and, with "Outside
addresses only" on, its own networks - a LAN's IPv6 /64, a public DMZ, a delegated prefix, a static
route's network, a tunnel - and the private ones. Held addresses checked again when the settings or the
firewall change; the time kept from the last drop with the minutes set now; one reading's budget and
the cap; the cut of the new addresses' states only; the log read from where it stopped, its rotated rest,
a log emptied in place and grown again, a line cut in half; off and on; taking one out, also while the
minute's run holds the lock; the removers' table flush; the page's line and grid. Documentation
addresses throughout, but for the private ones Outside addresses only is about.
"""
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src')
SCRIPTS = os.path.join(SRC, 'opnsense', 'scripts', 'blocklists')
sys.path.insert(0, SCRIPTS)
POSIX = os.name == 'posix'      # a real flock: not the stand-in Windows gets
if importlib.util.find_spec('fcntl') is None:     # Windows: a lock that always takes
    sys.modules['fcntl'] = types.ModuleType('fcntl')
    sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB, sys.modules['fcntl'].LOCK_UN = 2, 4, 8
    sys.modules['fcntl'].flock = lambda *args: None
import ids_list     # noqa: E402

FAILED = []
CHECKS = [0]
T0 = int(time.time())           # now: what --remove and --list, run at real time, see as now

# the firewall's interfaces as FreeBSD's ifconfig -a writes them: a WAN, a LAN with an IPv6 /64, a
# public DMZ, a tunnel, the loopback; a CARP address
IFCONFIG = '''igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 203.0.113.1 netmask 0xffffff00 broadcast 203.0.113.255
\tinet6 fe80::a%igb0 prefixlen 64 scopeid 0x1
igb1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8:1::1 prefixlen 64
\tinet 192.168.1.250 netmask 0xffffffff vhid 1
igb2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 192.0.2.1 netmask 0xffffff80 broadcast 192.0.2.127
ovpns1: flags=1008051<UP,POINTOPOINT,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.0.0.1 --> 10.0.0.2 netmask 0xffffff00
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
'''
# pf's states: one to the web GUI (port 8443 here) from 198.51.100.200, one of a source that is about to
# enter, one of another
STATES = '''all tcp 203.0.113.1:8443 <- 198.51.100.200:51234       ESTABLISHED:ESTABLISHED
   age 00:05:00, expires in 24:00:00, 30:20 pkts, 3000:2000 bytes, rule 5
   id: 00000000000000a3 creatorid: 12345678
all tcp 192.0.2.10:443 <- 198.51.100.7:44321       ESTABLISHED:ESTABLISHED
   age 00:00:10, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000a1 creatorid: 12345678
all tcp 192.0.2.11:443 <- 198.51.100.99:44322       ESTABLISHED:ESTABLISHED
   age 00:00:10, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000a2 creatorid: 12345678
'''
ESTABLISHED = {'pkts_toserver': 4, 'pkts_toclient': 3, 'bytes_toserver': 600, 'bytes_toclient': 900}


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


def when(t):
    """A time as Suricata stamps an event."""
    return time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000', time.gmtime(t))


def alert(src, t, proto='TCP', sid=1000001, action='blocked', msg='LOCAL test drop', app='http', flow=ESTABLISHED):
    """One alert line as Suricata writes it to eve.json: compact, one object a line; app_proto and the flow's
    counts as on an established HTTP connection unless said otherwise (None: not in the line)."""
    line = {
        'timestamp': when(t), 'flow_id': 1234567890, 'in_iface': 'igb0', 'event_type': 'alert',
        'src_ip': src, 'src_port': 44321, 'dest_ip': '192.0.2.10', 'dest_port': 443, 'proto': proto,
        'alert': {'action': action, 'gid': 1, 'signature_id': sid, 'rev': 1, 'signature': msg,
                  'category': 'Attempted Administrator Privilege Gain', 'severity': 1},
    }
    if app is not None:
        line['app_proto'] = app
    if flow is not None:
        line['flow'] = dict(flow, start=when(t - 1))
    return json.dumps(line, separators=(',', ':')) + '\n'


def other(t):
    """A line of another kind, as the log holds many."""
    return json.dumps({'timestamp': when(t), 'event_type': 'flow', 'src_ip': '198.51.100.98', 'proto': 'TCP'},
                      separators=(',', ':')) + '\n'


CONFIG = '''<opnsense>
<system><webgui><protocol>https</protocol><port>8443</port></webgui><ssh><port>2222</port></ssh>
<dnsserver>198.51.100.52</dnsserver></system>
<gateways><gateway_item><name>WAN_GW</name><gateway>198.51.100.254</gateway><monitor>198.51.100.253</monitor></gateway_item></gateways>
<virtualip><vip><mode>ipalias</mode><subnet>192.0.2.200</subnet><subnet_bits>32</subnet_bits></vip>
<vip><mode>proxyarp</mode><subnet>192.0.2.208</subnet><subnet_bits>29</subnet_bits></vip></virtualip>
<nat><onetoone><external>192.0.2.220</external></onetoone><outbound><rule><target>192.0.2.221</target></rule></outbound></nat>
<staticroutes><route><network>198.18.0.0/15</network><gateway>WAN_GW</gateway></route></staticroutes>
<ipsec><phase1><remote-gateway>198.51.100.78</remote-gateway></phase1></ipsec>
<openvpn><openvpn-client><server_addr>198.51.100.79</server_addr><tunnel_network>10.0.0.0/24</tunnel_network></openvpn-client></openvpn>
<OPNsense>
<wireguard><client><clients><client><serveraddress>vpn.example.net</serveraddress><tunneladdress>198.51.100.160/28</tunneladdress></client></clients></client></wireguard>
<BlockLists><general><enabled>{enabled}</enabled><ids>{on}</ids><ids_minutes>{minutes}</ids_minutes>
<ids_outside>{outside}</ids_outside><ids_never>{never}</ids_never><direction>both</direction><cut>{cut}</cut></general></BlockLists>
<IDS><general><enabled>{ids}</enabled><mode>{mode}</mode></general></IDS>
<Firewall><Alias><aliases>{alias}</aliases></Alias></Firewall>
</OPNsense></opnsense>
'''
ALIAS = '<alias uuid="u-ids"><name>blocklists_ids</name><enabled>1</enabled><type>external</type></alias>'


class Pf:
    """pf as ids_list.py asks it: the table blocklists_ids, filled and emptied, and its states killed."""

    def __init__(self):
        self.table, self.fills, self.flushes, self.looks, self.killed = None, 0, 0, 0, []
        self.states = STATES

    def now(self):
        self.looks += 1
        return None if self.table is None else set(self.table)

    def fill(self, addresses):
        if self.now() == set(addresses):
            return False, None
        self.table, self.fills = set(addresses), self.fills + 1
        return True, None

    def flush(self):
        if self.table is not None:
            self.table = set()
        self.flushes += 1

    def kill(self, state_id):
        self.killed.append(state_id)
        return True


def main():
    tmp = tempfile.mkdtemp(prefix='blocklists-ids-')
    try:
        run(tmp)
        config_tests()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


def run(tmp):
    state = os.path.join(tmp, 'ids')
    ids_list.CONFIG = ids_list.cut.CONFIG = os.path.join(tmp, 'config.xml')
    ids_list.EVE = os.path.join(tmp, 'eve.json')
    ids_list.STATE_DIR = state
    ids_list.STATE = os.path.join(state, 'state.json')
    ids_list.LOCK = os.path.join(state, 'lock')
    ids_list.REMOVE = os.path.join(state, 'remove')
    run_dir = os.path.join(tmp, 'tmp')
    os.makedirs(run_dir)
    ids_list.PREFIXES = os.path.join(run_dir, '*_prefixv6')
    ids_list.ROUTERS = (os.path.join(run_dir, '*_router'), os.path.join(run_dir, '*_routerv6'))
    ids_list.RESOLV = os.path.join(run_dir, 'resolv.conf')
    for name, text in (('igb0_prefixv6', '2001:db8:1200::/56\n'), ('igb0_router', '203.0.113.254\n'),
                       ('resolv.conf', 'domain example.net\nnameserver 198.51.100.53\nnameserver 127.0.0.1\n')):
        with open(os.path.join(run_dir, name), 'w') as fh:
            fh.write(text)
    pf = Pf()
    ids_list.fill, ids_list.flush, ids_list.table_now, ids_list.kill = pf.fill, pf.flush, pf.now, pf.kill
    ids_list.pf_states = lambda: pf.states
    host = {'ifconfig': IFCONFIG, 'resolved': 0}
    ids_list.ifconfig_text = lambda: host['ifconfig']

    def resolve(names, wait=3):
        host['resolved'] += 1
        return {'198.51.100.77/32'} if 'vpn.example.net' in names else set()
    ids_list.resolve = resolve
    said = []
    ids_list.log = said.append
    ids_list.categories.say = lambda message: None
    ids_list.cut.log = lambda message: None

    def config(on='1', enabled='1', minutes='60', outside='1', ids='1', mode='netmap', alias=ALIAS, never='', cut='1'):
        with open(ids_list.CONFIG, 'w') as fh:
            fh.write(CONFIG.format(on=on, enabled=enabled, minutes=minutes, outside=outside, ids=ids, mode=mode,
                                   alias=alias, never=never, cut=cut))
        stamp_ = time.time() + len(said) + len(on + enabled + minutes + outside + ids + mode + alias + never + cut) * 7
        config.n = getattr(config, 'n', 0) + 1
        os.utime(ids_list.CONFIG, (stamp_ + config.n, stamp_ + config.n))

    def log(*lines):
        with open(ids_list.EVE, 'a', newline='\n') as fh:
            fh.write(''.join(lines))

    def quiet_main(*argv):
        out = io.StringIO()
        with redirect_stdout(out):
            ids_list.main(list(argv))
        return json.loads(out.getvalue())

    # never turned on: nothing made, nothing read
    config(on='0')
    log(alert('198.51.100.1', T0 - 600))
    answer = quiet_main()
    check(not os.path.exists(state) and 'off' in answer['message'], 'off and never on: no folder made, said off: %r' % (answer,))
    quiet_main('--for', '58')
    answer = quiet_main('--remove', '198.51.100.1')
    check(not os.path.exists(state) and answer['removed'] is False, 'off and never on: the minute\'s run and a removal make nothing')

    # turned on: from the log's end - what was logged before is not taken, even a line stamped a little ahead
    log(alert('198.51.100.2', T0 + 1))
    config()
    os.makedirs(state)
    w = ids_list.Watch()
    w.once(now=T0)
    check(w.state['since'] == T0 and w.state['offset'] == os.path.getsize(ids_list.EVE) and w.state['entries'] == {},
          'turned on: the log taken from its end, nothing logged before entered')

    # what enters, and what never does
    log(other(T0 + 1),
        alert('198.51.100.7', T0 + 2),                                   # TCP, established, outside: enters
        alert('198.51.100.8', T0 + 2, proto='UDP'), alert('198.51.100.9', T0 + 2, proto='ICMP'),
        alert('198.51.100.10', T0 + 2, sid=2210020), alert('198.51.100.11', T0 + 2, sid=2200074),
        alert('198.51.100.12', T0 + 2, action='allowed'),                # IDS mode: logged, not blocked
        alert('198.51.100.13', T0 + 2, action='allowed', msg='blocked'),  # "blocked" in its text, not its action
        # a forged source: a lone SYN; SYN and a blind ACK; one Suricata gave up recognising; counts one way
        alert('198.51.100.14', T0 + 2, app=None, flow={'pkts_toserver': 1, 'pkts_toclient': 0}),
        alert('198.51.100.15', T0 + 2, app=None, flow={'pkts_toserver': 2, 'pkts_toclient': 1}),
        alert('198.51.100.16', T0 + 2, app='failed'),
        alert('198.51.100.17', T0 + 2, flow={'pkts_toserver': 1, 'pkts_toclient': 0}),
        alert('198.51.100.18', T0 + 2, flow=None),                       # app_proto, no counts: enters
        # the firewall's own: interfaces, a CARP address, a virtual IP, Proxy ARP, 1:1 and outbound NAT
        alert('203.0.113.1', T0 + 2), alert('2001:db8:1::1', T0 + 2), alert('192.168.1.250', T0 + 2),
        alert('192.0.2.200', T0 + 2), alert('192.0.2.210', T0 + 2), alert('192.0.2.220', T0 + 2),
        alert('192.0.2.221', T0 + 2),
        # what it depends on, and who manages it
        alert('198.51.100.254', T0 + 2), alert('198.51.100.253', T0 + 2), alert('203.0.113.254', T0 + 2),
        alert('198.51.100.52', T0 + 2), alert('198.51.100.53', T0 + 2), alert('198.51.100.78', T0 + 2),
        alert('198.51.100.79', T0 + 2), alert('198.51.100.77', T0 + 2), alert('198.51.100.200', T0 + 2),
        # inside its own networks (Outside addresses only): private, a LAN's IPv6 /64, a public DMZ, a
        # delegated prefix, a static route's network, a tunnel's peer network
        alert('192.168.1.20', T0 + 2), alert('172.16.0.9', T0 + 2), alert('100.64.0.9', T0 + 2), alert('fd00::5', T0 + 2),
        alert('2001:db8:1::50', T0 + 2), alert('192.0.2.50', T0 + 2), alert('2001:db8:1200:5::9', T0 + 2),
        alert('198.19.1.1', T0 + 2), alert('198.51.100.170', T0 + 2),
        # no host has them, or every host does
        alert('169.254.1.1', T0 + 2), alert('fe80::9', T0 + 2), alert('224.0.0.5', T0 + 2), alert('ff02::1', T0 + 2),
        alert('127.0.0.1', T0 + 2), alert('::1', T0 + 2), alert('0.0.0.0', T0 + 2), alert('::', T0 + 2),
        alert('2001:db8:5::7', T0 + 3), alert('::ffff:198.51.100.20', T0 + 3),
        '{"timestamp":"broken', '\n',
        alert('198.51.100.7', T0 + 4, sid=1000002, msg='LOCAL second'))
    said.clear()
    summary = w.once(now=T0 + 5)
    entries = w.state['entries']
    check(sorted(entries) == ['198.51.100.18', '198.51.100.20', '198.51.100.7', '2001:db8:5::7'],
          'entered: the drops on established TCP connections from outside - IPv4, IPv6, an IPv4-mapped one: %r'
          % (sorted(entries),))
    refused = summary['refused']
    expect = {
        'not TCP': 2,
        'an event rule of Suricata, which drops one frame': 2,
        'a connection not seen established: no application protocol recognised': 3,
        'a connection not seen established: no packets both ways past the handshake': 1,
        'an address of the firewall': 8,       # 127.0.0.1 among them: lo0's
        'a gateway, a DNS server or a VPN peer of the firewall, or an address managing it': 9,
        'inside the networks of the firewall (Outside addresses only)': 9,
        'an address no host has, or every host has': 7,
    }
    check(refused == expect, 'not entered, each for its reason: %r' % ({k: (refused.get(k), v) for k, v in expect.items()
                                                                        if refused.get(k) != v} or refused,))
    check(pf.table == set(entries), 'the table holds them')
    check(pf.killed == ['00000000000000a1'], 'the new addresses\' states cut, and no other: %r' % (pf.killed,))
    check(len(said) == 1 and said[0].startswith('4 entered for 60 minutes: '), 'one line in the system log for the reading: %r' % (said,))
    e = entries['198.51.100.7']
    check(e['count'] == 2 and e['sid'] == 1000002 and e['msg'] == 'LOCAL second' and e['until'] == T0 + 5 + 3600
          and e['at'] == T0 + 2 and e['last'] == T0 + 4,
          'a source dropped twice: counted, the last signature kept, held 60 minutes from now: %r' % (e,))

    # pf's table looked at when the list changes, and once a minute; put back where it lost them
    looks = pf.looks
    w.once(now=T0 + 6)
    w.once(now=T0 + 7)
    check(pf.looks == looks, 'nothing changed: pf\'s table not listed again within the minute')
    pf.table = set()        # as a reboot leaves it, /var kept
    w.once(now=T0 + 5 + 61)
    check(pf.table == set(entries), 'a minute on: looked at, and what it lost put back')

    # the log's position: nothing read twice; a line cut in half waits for its end
    before = json.dumps(entries, sort_keys=True)
    w.once(now=T0 + 70)
    check(json.dumps(entries, sort_keys=True) == before, 'read again: nothing new, nothing counted twice')
    half = alert('198.51.100.30', T0 + 71)
    log(half[:40])
    w.once(now=T0 + 72)
    check('198.51.100.30' not in entries, 'a line cut in half: left for the next reading')
    log(half[40:])
    w.once(now=T0 + 73)
    check(entries.get('198.51.100.30', {}).get('count') == 1, 'its end written: taken, once')
    check(pf.killed == ['00000000000000a1'], 'a later reading cuts the states of what it entered only, not again those held: %r'
          % (pf.killed,))

    # the firewall given a new address (PPPoE, DHCP): read again before anything enters, and held
    # addresses that are now its own taken out
    host['ifconfig'] = IFCONFIG + 'pppoe0: flags=88d1<UP,POINTOPOINT,RUNNING> metric 0 mtu 1492\n\tinet 198.51.100.140 --> 198.51.100.1 netmask 0xffffffff\n'
    log(alert('198.51.100.140', T0 + 74))
    w.once(now=T0 + 74 + ids_list.OWN_FRESH)
    check('198.51.100.140' not in entries, 'a source that is the firewall\'s address since seconds: not entered')
    log(alert('198.51.100.141', T0 + 80))
    w.once(now=T0 + 81)
    check('198.51.100.141' in entries, 'an outside source: entered')
    host['ifconfig'] += '\tinet 198.51.100.141 netmask 0xffffffff\n'
    for i in range(ids_list.REFILTER_EVERY):
        w.once(now=T0 + 81 + ids_list.RUNTIME_EVERY + i)
    check('198.51.100.141' not in entries, 'held, then given to the firewall: taken out within the readings to check')
    host['ifconfig'] = IFCONFIG

    # Outside addresses only off: a private source enters - the firewall's own never; turned on again, it
    # leaves at the next reading; Never block added: one held leaves
    config(outside='0')
    log(alert('192.168.1.20', T0 + 150), alert('192.168.1.1', T0 + 150), alert('2001:db8:1::50', T0 + 150))
    w.once(now=T0 + 150)
    check('192.168.1.20' in entries and '2001:db8:1::50' in entries and '192.168.1.1' not in entries,
          'Outside addresses only off: inside sources enter, the firewall\'s own address never')
    config(outside='1')
    w.once(now=T0 + 151)
    check('192.168.1.20' not in entries and '2001:db8:1::50' not in entries, 'turned on again: they leave at the next reading')
    config(never='198.51.100.18,2001:db8:5::/48')
    w.once(now=T0 + 152)
    check('198.51.100.18' not in entries and '2001:db8:5::7' not in entries and '198.51.100.7' in entries,
          'Never block: addresses and networks held leave, others stay')
    log(alert('198.51.100.18', T0 + 153))
    summary = w.once(now=T0 + 153)
    check('198.51.100.18' not in entries and summary['refused'] == {'in Never block': 1}, 'and do not enter again')
    config()

    # the time kept from the last drop, with the minutes set now; dropped again before its end, it starts again
    log(alert('198.51.100.30', T0 + 200))
    w.once(now=T0 + 205)
    check(entries['198.51.100.30']['until'] == T0 + 205 + 3600 and entries['198.51.100.30']['count'] == 2,
          'dropped again before its time was over: its time starts again')
    config(minutes='5')
    w.once(now=T0 + 210)
    check(entries['198.51.100.30']['until'] == T0 + 205 + 300, 'Keep an address lowered to 5: held addresses follow')
    w.once(now=T0 + 205 + 301)
    check('198.51.100.30' not in entries, 'its time over: out of the list and the table')
    config()

    # a rotation: the old log's rest read first, then the new one from its start
    log(alert('198.51.100.40', T0 + 600))                       # after the last reading, in the old log
    os.replace(ids_list.EVE, ids_list.EVE + '.0')
    log(alert('198.51.100.41', T0 + 601), alert('198.51.100.42', T0 - 100))
    w.once(now=T0 + 602)
    check('198.51.100.40' in entries and '198.51.100.41' in entries and '198.51.100.42' not in entries,
          'rotated: the old log\'s rest read, then the new one from its start; a line from before turning on not taken')
    # emptied in place and grown past the offset: from its start
    offset = w.state['offset']
    with open(ids_list.EVE, 'w', newline='\n') as fh:
        fh.write(other(T0 + 700) * 3 + alert('198.51.100.43', T0 + 700) + other(T0 + 700) * 3)
    check(os.path.getsize(ids_list.EVE) > offset, 'the new content longer than the offset kept')
    w.once(now=T0 + 701)
    check('198.51.100.43' in entries, 'emptied in place and grown again: read from its start')

    # one reading's budget: the rest at the next; the cap: the oldest out first
    saved = ids_list.BUDGET, ids_list.CAP
    ids_list.BUDGET = 3
    log(*[alert('198.51.100.%d' % (110 + i), T0 + 800 + i) for i in range(5)])
    said.clear()
    summary = w.once(now=T0 + 810)
    check(len(summary['entered']) == 3 and summary['deferred'] == 1 and '198.51.100.113' not in entries,
          'the budget: 3 entered at the reading, the rest left: %r' % (summary['entered'],))
    summary = w.once(now=T0 + 811)
    check(sorted(summary['entered']) == ['198.51.100.113', '198.51.100.114'] and len(said) == 2,
          'the rest at the next reading, one log line each: %r' % (summary['entered'],))
    ids_list.CAP = 3
    log(alert('198.51.100.60', T0 + 820))
    summary = w.once(now=T0 + 820)
    check(len(entries) == 3 and '198.51.100.60' in entries and summary['capped'] > 0,
          'the cap: 3 held, the newest in, the oldest out: %r' % (sorted(entries),))
    ids_list.BUDGET, ids_list.CAP = saved
    w.save()

    # taken out at once; not held; not an address
    target = sorted(entries)[0]
    answer = quiet_main('--remove', target)
    check(answer['removed'] is True and target not in json.load(open(ids_list.STATE))['entries'] and target not in pf.table,
          'taken out now: out of the list and the table: %r' % (answer,))
    answer = quiet_main('--remove', target)
    check(answer['removed'] is False and answer['message']['text'] == '%s is not held', 'one not held: said so')
    answer = quiet_main('--remove', '198.51.100.52;reboot')
    check(answer['removed'] is False and answer['message']['text'] == 'not an address', 'not an address: refused')
    # a request taken by the watcher after its reading: one taken out does not enter again from that line
    w = ids_list.Watch()
    w.once(now=T0 + 900)
    keep = sorted(w.state['entries'])[0]
    log(alert(keep, T0 + 901))
    os.makedirs(ids_list.REMOVE, exist_ok=True)
    with open(os.path.join(ids_list.REMOVE, ids_list.ipaddress.ip_address(keep).packed.hex()), 'w'):
        pass
    w.once(now=T0 + 902)
    check(keep not in w.state['entries'] and os.listdir(ids_list.REMOVE) == [],
          'a request taken after the reading: out, its drop in the same reading not putting it back')
    w.save()
    if POSIX:
        # --remove while the minute's run holds the lock: the request taken by the run within seconds
        import fcntl
        w = ids_list.Watch()
        log(alert('198.51.100.90', T0 + 950))
        w.once(now=T0 + 950)
        w.save()
        lock = open(ids_list.LOCK, 'a')
        fcntl.flock(lock, fcntl.LOCK_EX)
        watcher = threading.Timer(1.0, lambda: (w.once(now=T0 + 951), w.save()))
        watcher.start()
        started = time.monotonic()
        answer = quiet_main('--remove', '198.51.100.90')
        watcher.join()
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
        check(answer['removed'] is True and time.monotonic() - started < ids_list.REMOVE_WAIT
              and '198.51.100.90' not in json.load(open(ids_list.STATE))['entries'],
              '--remove while the watcher holds the lock: taken by its next reading: %r' % (answer,))

    # the IDS off, or in IDS mode: said; the minute's run reads once and leaves
    config(ids='0')
    check(ids_list.settings()['problem']['text'].startswith('the Intrusion Detection is off'), 'the IDS off: said')
    config(mode='pcap')
    check('IDS mode' in ids_list.settings()['problem']['text'], 'the IDS in IDS mode (pcap): said')
    started = time.monotonic()
    quiet_main('--for', '58')
    check(time.monotonic() - started < 5, 'IDS mode: the minute\'s run read once and left')
    config(mode='divert')
    check(ids_list.settings()['problem'] is None, 'Divert is IPS mode too')

    # Cut open connections off: entered, nothing cut
    config(cut='0')
    w = ids_list.Watch()
    killed = len(pf.killed)
    log(alert('198.51.100.95', T0 + 1000))
    w.once(now=T0 + 1000)
    check('198.51.100.95' in w.state['entries'] and len(pf.killed) == killed, 'Cut open connections off: blocked, not cut')
    config()

    # the alias not there: the list kept, the table not touched, the line says Apply makes it
    config(alias='')
    w = ids_list.Watch()
    fills = pf.fills
    log(alert('198.51.100.96', T0 + 1050))
    w.once(now=T0 + 1050)
    check('198.51.100.96' in w.state['entries'] and pf.fills == fills
          and any('Apply makes it' in m['text'] for m in w.message()),
          'its alias not there: entered, the table left alone, the line says Apply makes it')
    w.save()

    # turned off: every address out and the table emptied; on again: nothing from before
    config(on='0')
    flushes = pf.flushes
    w = ids_list.Watch()
    w.once(now=T0 + 1100)
    w.save()
    check(w.state['entries'] == {} and pf.flushes == flushes + 1 and w.state['since'] is None and pf.table == set(),
          'turned off: every address out, the table emptied')
    log(alert('198.51.100.70', T0 + 1150))
    config()
    w = ids_list.Watch()
    w.once(now=T0 + 1200)
    check(w.state['entries'] == {} and w.state['since'] == T0 + 1200, 'on again: what was logged while off not taken')
    log(alert('198.51.100.71', T0 + 1300))
    w.once(now=T0 + 1300)
    check(list(w.state['entries']) == ['198.51.100.71'], 'and what is logged after, taken')
    w.save()
    config(on='1', enabled='0')
    check(ids_list.settings()['on'] is False, 'Block Lists off: as off')
    config()

    # the page: its line, its grid, its texts catalogued
    w = ids_list.Watch()
    w.once(now=T0 + 1400)
    w.state['message'] = w.message()
    w.save()
    page = ids_list.page()
    check(page['on'] and page['entries'] == 1 and page['minutes'] == 60 and page['problem'] is None
          and page['message'][0]['text'] == '%s addresses held, each for %s minutes after its last drop',
          'the page\'s line: on, how many held, for how long: %r' % (page,))
    listed = quiet_main('--list')['entries']
    check([r['address'] for r in listed] == ['198.51.100.71'] and listed[0]['msg'] == 'LOCAL test drop'
          and listed[0]['sid'] == 1000001 and listed[0]['until'].endswith('UTC') and listed[0]['at'].endswith('UTC'),
          'the grid: each address, first and last drop, until when, its signature: %r' % (listed,))
    catalogued = set(json.load(open(os.path.join(SCRIPTS, 'i18n', 'ui', 'source.json'), encoding='utf-8')))
    found = [t['text'] for t in w.message()] + list(expect)
    for conf in ({'ids': '0'}, {'mode': 'pcap'}, {'alias': ''}, {'on': '0'}):
        config(**conf)
        w = ids_list.Watch()
        w.reload(T0 + 1500)
        found += [t['text'] for t in w.message()]
    config()
    check(found and all(t in catalogued for t in found), 'every text of the line and every reason catalogued: %r'
          % (sorted(set(found) - catalogued),))

    # the minute's run reads the log every few seconds: a drop logged while it runs is taken within it
    saved = ids_list.EVERY
    ids_list.EVERY = 0.2
    later = threading.Timer(0.5, lambda: log(alert('198.51.100.80', T0 + 1600)))
    later.start()
    answer = quiet_main('--for', '2')
    later.join()
    ids_list.EVERY = saved
    check('198.51.100.80' in json.load(open(ids_list.STATE))['entries'] and '198.51.100.80' in pf.table,
          'the minute\'s run: a drop logged while it ran entered within it, and in the table: %r' % (answer,))
    if POSIX:
        # the minute's run waits for the last one to end rather than losing its minute
        import fcntl
        lock = open(ids_list.LOCK, 'a')
        fcntl.flock(lock, fcntl.LOCK_EX)
        threading.Timer(1.0, lambda: fcntl.flock(lock, fcntl.LOCK_UN)).start()
        answer = quiet_main('--for', '2')
        lock.close()
        check('busy' not in answer, 'the minute\'s run waited for the last one to end: %r' % (answer,))
    check(ids_list.LOCK_WAIT >= 30, 'the minute\'s run waits up to %d s for the last one' % ids_list.LOCK_WAIT)

    # the parsers
    addresses, networks = ids_list.interfaces_of(IFCONFIG)
    check(addresses == {'203.0.113.1', 'fe80::a', '192.168.1.1', '2001:db8:1::1', '192.168.1.250', '192.0.2.1', '10.0.0.1',
                        '127.0.0.1'}
          and {'203.0.113.0/24', '2001:db8:1::/64', '192.168.1.0/24', '192.0.2.0/25', '10.0.0.2/32'} <= networks,
          'ifconfig read: every interface\'s address and its network, a CARP one, a tunnel\'s far end: %r %r'
          % (addresses, networks))
    check(ids_list.hosts_in('vpn.example.net:51820, [2001:db8::9]:443 198.51.100.5:1194 1194 bad_name') ==
          ['vpn.example.net', '2001:db8::9/128', '198.51.100.5/32'], 'peers read: a host name, an IPv6 and an IPv4 address, ports off')
    check(host['resolved'] >= 1, 'a VPN peer named by its host name resolved')
    guard = ids_list.Guard()
    host['ifconfig'] = None
    guard.refresh(T0, 0)
    check(guard.why('198.51.100.7', ids_list.settings())['text'] == 'the firewall addresses could not be read',
          'ifconfig not read: nothing enters')
    host['ifconfig'] = IFCONFIG


def config_tests():
    feeds = json.load(open(os.path.join(SCRIPTS, 'feeds.json'), encoding='utf-8'))
    check(feeds.get('ids', {}).get('local') is True and 'url' not in feeds['ids'] and feeds['ids']['name'] == 'IPS drops',
          'feeds.json: IPS drops, a list of the plugin\'s own, filled here and never fetched')
    check('blocklists_ids' in ids_list.cut.owned(), 'cut.py, the rules hook and the page take blocklists_ids for the plugin\'s')
    model = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'models', 'OPNsense', 'BlockLists', 'BlockLists.xml'),
                 encoding='utf-8').read()
    check('<ids type="BooleanField">\n                <Required>Y</Required>\n                <Default>0</Default>' in model
          and '<MinimumValue>5</MinimumValue>' in model and '<MaximumValue>10080</MaximumValue>' in model
          and '<ids_outside type="BooleanField">\n                <Required>Y</Required>\n                <Default>1</Default>' in model
          and '<ids_never type="CSVListField">' in model,
          'the model: off by default, 5 to 10080 minutes (60), outside only on by default, Never block')
    form = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'forms', 'general.xml'),
                encoding='utf-8').read()
    for field in ('blocklists.general.ids', 'blocklists.general.ids_minutes', 'blocklists.general.ids_outside',
                  'blocklists.general.ids_never'):
        check('<id>%s</id>' % field in form, 'the form: %s' % field)
    for said in ('connection it saw established', 'a lone SYN', '2200000-2299999', 'its gateways and their monitor',
                 'its DNS servers', 'its VPN peers', 'web GUI or SSH', 'Never block', 'every network connected to the firewall',
                 'delegated IPv6 prefixes', 'VPN tunnel and remote networks', "static routes' networks", 'virtual IPs',
                 '1:1 and outbound NAT', 'Cut open connections is on', 'Direction Both ways', '10,000', 'At most 200',
                 'applies to the addresses already held', 'reboot'):
        check(said in form, 'the help says: %s' % said)
    volt = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'index.volt'),
                encoding='utf-8').read()
    check("lang._('First dropped')" in volt and 'Cut open connections is on' in volt and 'Direction is Both ways' in volt,
          'the page: the first drop shown, and the cut said to need Cut open connections and Both ways')
    readme = ' '.join(open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read().split())
    for said in ('established', 'a lone SYN', 'Never block', 'every network connected to it', 'Cut open connections'):
        check(said in readme, 'the README says: %s' % said)
    # the removers: the alias taken out, and the table emptied whatever names it
    for name in ('install/uninstall.sh', 'pkg/post-deinstall.sh'):
        text = open(os.path.join(ROOT, name), encoding='utf-8').read()
        check('"blocklists_ids"' in text and '->del($uuid)' in text and text.find('blocklists_ids') < text.find('filter reload > /dev/null'),
              '%s: the IPS drops\' alias taken out before the filter reload' % name)
        line = '/sbin/pfctl -t blocklists_ids -T flush > /dev/null 2>&1 || true\n'
        check(('\n' + line) in text and text.find(line) > text.find('filter reload > /dev/null'),
              '%s: the table emptied, unconditionally, after the filter reload (tools/test-ids.php runs it)' % name)
    service = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'Api',
                                'ServiceController.php'), encoding='utf-8').read()
    action = service[service.find('public function idsRemoveAction()'):]
    action = action[:action.find('\n    }\n')]
    check('isPost()' in action and action.find('FILTER_VALIDATE_IP') < action.find("configdpRun('blocklists ids_remove'"),
          'the controller: POST only, an address checked before configd sees it')
    check("'at' => (string)($entry['at'] ?? '')" in service, 'the controller: the first drop in the grid\'s rows')
    import lookup
    lookup.pfctl = lambda args: types.SimpleNamespace(
        returncode=0, stdout='   blocklists_ids\n' if args == ['-s', 'Tables'] else '', stderr='1/1 addresses match.\n')
    held = lookup.tables('198.51.100.7')['held']
    check(held == [{'alias': 'blocklists_ids', 'list': lookup.categories.T('IPS drops')}],
          'the Lookup tab: an address held names IPS drops: %r' % (held,))


if __name__ == '__main__':
    sys.exit(main())
