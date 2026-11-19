#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""ids_list.py - what the Intrusion Detection's IPS policy drops, blocked and cut for a while (ff-10,
2026-11-19) - against an eve.json written here as Suricata writes it, with pf's table, ifconfig, the cut
and the system log stood in for. No Suricata, no OPNsense, no root:

    python3 tools/test-ids.py

What enters: an alert logged as blocked, over TCP, by a rule that is not one of Suricata's own event
rules (2200000-2299999); its source. What never does: UDP and ICMP, those event rules, IDS mode's alerts
(not blocked), the firewall's own addresses, loopback, multicast, unspecified, link-local - and private
and unique local ones while "Outside addresses only" is on. The time kept and its end, a drop again
starting it again, the cap (the oldest leave first); the log read from where it stopped, from its start
after a rotation, a line cut in half left for the next reading; turned off, every address out and the
table emptied; turned on, nothing logged before taken. Taking one out at once and through the minute's
watcher; the page's line and grid; and what installs, runs and lists it. Documentation addresses
throughout, but for the private ones the switch is about (the conventional 192.168.1.x and 10.0.0.x).
"""
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import time
import types
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src')
SCRIPTS = os.path.join(SRC, 'opnsense', 'scripts', 'blocklists')
sys.path.insert(0, SCRIPTS)
if importlib.util.find_spec('fcntl') is None:     # Windows: a lock that always takes
    sys.modules['fcntl'] = types.ModuleType('fcntl')
    sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB, sys.modules['fcntl'].LOCK_UN = 2, 4, 8
    sys.modules['fcntl'].flock = lambda *args: None
import ids_list     # noqa: E402

FAILED = []
CHECKS = [0]
T0 = int(time.time())                   # now: what --remove and --list run at real time sees as now
OWN = {'203.0.113.1', '192.168.1.1', '2001:db8:1::1', 'fe80::1'}


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


def when(t):
    """A time as Suricata stamps an event."""
    return time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000', time.gmtime(t))


def alert(src, t, proto='TCP', sid=1000001, action='blocked', msg='LOCAL test drop'):
    """One alert line as Suricata writes it to eve.json: compact, one object a line."""
    return json.dumps({
        'timestamp': when(t), 'flow_id': 1234567890, 'in_iface': 'igb0', 'event_type': 'alert',
        'src_ip': src, 'src_port': 44321, 'dest_ip': '192.0.2.10', 'dest_port': 443, 'proto': proto,
        'alert': {'action': action, 'gid': 1, 'signature_id': sid, 'rev': 1, 'signature': msg,
                  'category': 'Attempted Administrator Privilege Gain', 'severity': 1},
    }, separators=(',', ':')) + '\n'


def other(t):
    """A line of another kind, as the log holds many."""
    return json.dumps({'timestamp': when(t), 'event_type': 'flow', 'src_ip': '198.51.100.99', 'proto': 'TCP'},
                      separators=(',', ':')) + '\n'


CONFIG = '''<opnsense><OPNsense>
<BlockLists><general><enabled>{enabled}</enabled><ids>{on}</ids><ids_minutes>{minutes}</ids_minutes>
<ids_outside>{outside}</ids_outside><direction>both</direction><cut>1</cut></general></BlockLists>
<IDS><general><enabled>{ids}</enabled><mode>{mode}</mode></general></IDS>
<Firewall><Alias><aliases>{alias}</aliases></Alias></Firewall>
</OPNsense></opnsense>
'''
ALIAS = '<alias uuid="u-ids"><name>blocklists_ids</name><enabled>1</enabled><type>external</type></alias>'


class Pf:
    """pf's table blocklists_ids, filled and emptied as ids_list.py asks."""

    def __init__(self):
        self.table, self.fills, self.flushes, self.looks = None, 0, 0, 0

    def now(self):
        self.looks += 1
        return None if self.table is None else set(self.table)

    def fill_(self, addresses):
        """as ids_list.fill(): the table looked at, then filled where it differs"""
        self.now()
        return self.fill(addresses)

    def fill(self, addresses):
        if self.table is not None and self.table == set(addresses):
            return False, None
        self.table, self.fills = set(addresses), self.fills + 1
        return True, None

    def flush(self):
        if self.table is not None:
            self.table = set()
        self.flushes += 1


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
    ids_list.CONFIG = os.path.join(tmp, 'config.xml')
    ids_list.EVE = os.path.join(tmp, 'eve.json')
    ids_list.STATE_DIR = state
    ids_list.STATE = os.path.join(state, 'state.json')
    ids_list.LOCK = os.path.join(state, 'lock')
    ids_list.REMOVE = os.path.join(state, 'remove')
    pf = Pf()
    ids_list.fill, ids_list.flush, ids_list.table_now = pf.fill_, pf.flush, pf.now
    cuts, said = [], []
    ids_list.cut_now = lambda: cuts.append(sorted(pf.table or [])) or {'cut': 0}
    ids_list.log = said.append
    ids_list.own_addresses = lambda: set(OWN)
    ids_list.categories.say = lambda message: None

    def config(on='1', enabled='1', minutes='60', outside='1', ids='1', mode='netmap', alias=ALIAS):
        with open(ids_list.CONFIG, 'w') as fh:
            fh.write(CONFIG.format(on=on, enabled=enabled, minutes=minutes, outside=outside, ids=ids, mode=mode,
                                   alias=alias))
        os.utime(ids_list.CONFIG, (time.time(), time.time() + len(on + enabled + minutes + outside + ids + mode + alias)))

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
    answer = quiet_main('--for', '58')
    check(not os.path.exists(state), 'off and never on: the minute\'s run makes nothing either')
    answer = quiet_main('--remove', '198.51.100.1')
    check(not os.path.exists(state) and answer['removed'] is False, 'off and never on: nothing to take out, nothing made')

    # turned on: from the log's end - what was logged before is not taken
    config()
    os.makedirs(state)
    w = ids_list.Watch()
    w.once(now=T0)
    check(w.state['since'] == T0 and w.state['offset'] == os.path.getsize(ids_list.EVE) and w.state['entries'] == {},
          'turned on: the log taken from its end, nothing logged before entered')

    # what enters and what does not
    log(other(T0 + 1),
        alert('198.51.100.7', T0 + 2),                                   # TCP, blocked: enters
        alert('198.51.100.8', T0 + 2, proto='UDP'),                      # UDP: easily forged
        alert('198.51.100.9', T0 + 2, proto='ICMP'),                     # ICMP: the same
        alert('198.51.100.10', T0 + 2, sid=2210020),                     # Suricata's stream event rule
        alert('198.51.100.11', T0 + 2, sid=2200074),                     # its decoder event rule
        alert('198.51.100.12', T0 + 2, action='allowed'),                # IDS mode: logged, not blocked
        alert('203.0.113.1', T0 + 2),                                    # the firewall's own
        alert('2001:db8:1::1', T0 + 2),                                  # the firewall's own, IPv6
        alert('192.168.1.20', T0 + 2),                                   # private: Outside addresses only
        alert('10.0.0.5', T0 + 2),
        alert('100.64.0.9', T0 + 2),                                     # shared, VPN overlays
        alert('fd00::5', T0 + 2),                                        # unique local
        alert('169.254.1.1', T0 + 2), alert('fe80::9', T0 + 2),          # link-local
        alert('224.0.0.5', T0 + 2), alert('ff02::1', T0 + 2),            # multicast
        alert('127.0.0.1', T0 + 2), alert('::1', T0 + 2),                # loopback
        alert('0.0.0.0', T0 + 2), alert('::', T0 + 2),                   # unspecified
        alert('2001:db8:5::7', T0 + 3),                                  # TCP, IPv6: enters
        alert('::ffff:198.51.100.20', T0 + 3),                           # IPv4-mapped: as its IPv4 address
        '{"timestamp":"broken', '\n',                                    # a line that is not one
        alert('198.51.100.7', T0 + 4, sid=1000002, msg='LOCAL second'))  # the same again
    summary = w.once(now=T0 + 5)
    entries = w.state['entries']
    check(sorted(entries) == ['198.51.100.20', '198.51.100.7', '2001:db8:5::7'],
          'entered: the TCP drops from outside - IPv4, IPv6, an IPv4-mapped one as IPv4: %r' % (sorted(entries),))
    check(pf.table == set(entries) and cuts == [sorted(entries)],
          'the table holds them, and the cut was run at once for them: %r %r' % (pf.table, cuts))
    refused = summary['refused']
    check(refused.get('not TCP') == 2 and refused.get('an event rule of Suricata, which drops one frame') == 2,
          'not entered: UDP and ICMP; Suricata\'s event rules: %r' % (refused,))
    check(refused.get('an address of the firewall') == 2 and refused.get('a private address (Outside addresses only)') == 4
          and refused.get('an address no host has, or every host has') == 8,
          'not entered: the firewall\'s own, private and unique local, link-local, multicast, loopback, unspecified: %r'
          % (refused,))
    check(sum(refused.values()) == 18, 'the IDS mode line (allowed) and the broken one not even counted: %r' % (refused,))
    e = entries['198.51.100.7']
    check(e['count'] == 2 and e['sid'] == 1000002 and e['msg'] == 'LOCAL second' and e['until'] == T0 + 5 + 3600
          and e['at'] == T0 + 2 and e['last'] == T0 + 4,
          'a source dropped twice: counted, the last signature kept, held 60 minutes from now: %r' % (e,))
    check(any('198.51.100.7 entered for 60 minutes' in s for s in said), 'the system log says what entered')

    # pf's table looked at when the list changes, and once a minute - not every few seconds
    looks = pf.looks
    w.once(now=T0 + 6)
    w.once(now=T0 + 7)
    check(pf.looks == looks, 'nothing changed: pf\'s table not listed again within the minute')
    w.once(now=T0 + 5 + 60)
    check(pf.looks == looks + 1, 'a minute on: looked at once, to put back what it lost')
    pf.table = set()        # as a reboot leaves it, /var kept
    w.once(now=T0 + 5 + 120)
    check(pf.table == set(entries), 'the table lost its addresses: put back at the next look')

    # the log's position: nothing read twice; a line cut in half waits for its end
    before = json.dumps(entries, sort_keys=True)
    w.once(now=T0 + 8)
    check(json.dumps(entries, sort_keys=True) == before, 'read again: nothing new, nothing counted twice')
    half = alert('198.51.100.30', T0 + 9)
    log(half[:40])
    w.once(now=T0 + 10)
    check('198.51.100.30' not in entries, 'a line cut in half: left for the next reading')
    log(half[40:])
    w.once(now=T0 + 11)
    check(entries.get('198.51.100.30', {}).get('count') == 1, 'its end written: taken, once')

    # the time kept, and its end
    w.once(now=T0 + 5 + 3600)
    check('198.51.100.7' not in entries and '2001:db8:5::7' not in entries and '198.51.100.30' in entries
          and pf.table == set(entries), 'its time over: out of the list and the table; one dropped later still in')
    log(alert('198.51.100.30', T0 + 3000))
    w.once(now=T0 + 3600 + 20)
    check(entries['198.51.100.30']['until'] == T0 + 3600 + 20 + 3600, 'dropped again: its time starts again')

    # a rotation: the new log from its start; what it holds from before turning on is not taken
    os.replace(ids_list.EVE, ids_list.EVE + '.0')
    log(alert('198.51.100.40', T0 - 100), alert('198.51.100.41', T0 + 3700))
    w.once(now=T0 + 3700)
    check('198.51.100.41' in entries and '198.51.100.40' not in entries,
          'rotated: the new log read from its start; a line from before turning on not taken')

    # Outside addresses only off: a private source enters; the time from the setting
    config(outside='0', minutes='5')
    log(alert('192.168.1.20', T0 + 3800))
    w.once(now=T0 + 3800)
    check(entries.get('192.168.1.20', {}).get('until') == T0 + 3800 + 300,
          'Outside addresses only off: a private source enters, kept the 5 minutes set')
    check('192.168.1.1' not in entries, 'the firewall\'s own private address never')

    # the cap: past it, those dropped longest ago leave first
    saved, ids_list.CAP = ids_list.CAP, 3
    log(*[alert('198.51.100.%d' % (50 + i), T0 + 3801 + i) for i in range(4)])
    summary = w.once(now=T0 + 3810)
    check(len(entries) == 3 and sorted(entries) == ['198.51.100.51', '198.51.100.52', '198.51.100.53']
          and summary['capped'] == 4, 'the cap: the 3 last dropped kept, the 4 oldest out: %r' % (sorted(entries),))
    ids_list.CAP = saved
    w.save()

    # taken out at once, with the watcher not running
    answer = quiet_main('--remove', '198.51.100.52')
    state_now = json.load(open(ids_list.STATE))
    check(answer['removed'] is True and '198.51.100.52' not in state_now['entries'] and '198.51.100.52' not in pf.table,
          'taken out now: out of the list and the table: %r' % (answer,))
    answer = quiet_main('--remove', '198.51.100.52')
    check(answer['removed'] is False and answer['message']['text'] == '%s is not held', 'one not held: said so')
    answer = quiet_main('--remove', '198.51.100.52;reboot')
    check(answer['removed'] is False and answer['message']['text'] == 'not an address', 'not an address: refused')
    # through the minute's watcher, which holds the lock: a request it takes at its next reading
    w = ids_list.Watch()
    os.makedirs(ids_list.REMOVE, exist_ok=True)
    with open(os.path.join(ids_list.REMOVE, ids_list.ipaddress.ip_address('198.51.100.53').packed.hex()), 'w'):
        pass
    w.once(now=T0 + 3820)
    check('198.51.100.53' not in w.state['entries'] and os.listdir(ids_list.REMOVE) == [],
          'a request the watcher took: out, and the request gone')

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

    # the alias not there: the list kept, the table not touched, the line says Apply makes it
    config(alias='')
    w = ids_list.Watch()
    fills = pf.fills
    log(alert('198.51.100.60', T0 + 3900))
    w.once(now=T0 + 3900)
    check('198.51.100.60' in w.state['entries'] and pf.fills == fills
          and any('Apply makes it' in m['text'] for m in w.message()),
          'its alias not there: entered, the table left alone, the line says Apply makes it')
    w.save()

    # turned off: every address out and the table emptied at the next run; on again: nothing from before
    config(on='0')
    flushes = pf.flushes
    w = ids_list.Watch()
    w.once(now=T0 + 4000)
    w.save()
    check(w.state['entries'] == {} and pf.flushes == flushes + 1 and w.state['since'] is None
          and pf.table == set(), 'turned off: every address out, the table emptied')
    log(alert('198.51.100.70', T0 + 4100))
    config()
    w = ids_list.Watch()
    w.once(now=T0 + 4200)
    check(w.state['entries'] == {} and w.state['since'] == T0 + 4200,
          'on again: what was logged while off not taken, the log from its end')
    log(alert('198.51.100.71', T0 + 4300))
    w.once(now=T0 + 4300)
    check(list(w.state['entries']) == ['198.51.100.71'], 'and what is logged after, taken')
    w.save()
    config(on='1', enabled='0')
    check(ids_list.settings()['on'] is False, 'Block Lists off: as off')
    config()

    # the page: its line, its grid
    w = ids_list.Watch()
    w.once(now=T0 + 4400)
    w.state['message'] = w.message()
    w.save()
    page = ids_list.page()
    check(page['on'] and page['entries'] == 1 and page['minutes'] == 60 and page['problem'] is None
          and page['message'][0]['text'] == '%s addresses held, each for %s minutes after its last drop',
          'the page\'s line: on, how many held, for how long: %r' % (page,))
    listed = quiet_main('--list')['entries']
    check([r['address'] for r in listed] == ['198.51.100.71'] and listed[0]['msg'] == 'LOCAL test drop'
          and listed[0]['sid'] == 1000001 and listed[0]['until'].endswith('UTC'),
          'the grid: each address, its signature, until when: %r' % (listed,))
    catalogued = set(json.load(open(os.path.join(SCRIPTS, 'i18n', 'ui', 'source.json'), encoding='utf-8')))
    texts = [t['text'] for t in w.message()]
    for conf in ({'ids': '0'}, {'mode': 'pcap'}, {'alias': ''}, {'on': '0'}):
        config(**conf)
        w = ids_list.Watch()
        texts += [t['text'] for t in w.message()]
    config()
    check(texts and all(t in catalogued for t in texts), 'the line\'s texts catalogued for translation: %r'
          % (sorted(set(texts) - catalogued),))

    # the minute's run reads the log every few seconds: a drop logged while it runs is taken within it
    import threading
    saved, ids_list.EVERY = ids_list.EVERY, 0.2
    later = threading.Timer(0.5, lambda: log(alert('198.51.100.80', T0 + 5000)))
    later.start()
    answer = quiet_main('--for', '2')
    later.join()
    ids_list.EVERY = saved
    check('198.51.100.80' in json.load(open(ids_list.STATE))['entries'] and '198.51.100.80' in pf.table,
          'the minute\'s run: a drop logged while it ran entered within it, and in the table: %r' % (answer,))

    # ifconfig's lines, as FreeBSD writes them
    sample = ('igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
              '\tinet 203.0.113.1 netmask 0xffffff00 broadcast 203.0.113.255\n'
              '\tinet6 fe80::a%igb0 prefixlen 64 scopeid 0x1\n'
              '\tinet6 2001:db8:1::1 prefixlen 64\n'
              'lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384\n'
              '\tinet 127.0.0.1 netmask 0xff000000\n'
              '\tinet 198.51.100.254 netmask 0xffffffff vhid 1\n')
    check(ids_list.addresses_of(sample) == {'203.0.113.1', 'fe80::a', '2001:db8:1::1', '127.0.0.1', '198.51.100.254'},
          'ifconfig read: every interface\'s addresses, a CARP one too, scopes taken off: %r' % (ids_list.addresses_of(sample),))
    check(ids_list.why_not({'proto': 'tcp', 'sid': 1, 'src': ids_list.ipaddress.ip_address('198.51.100.7')}, None, True)['text']
          == 'the firewall addresses could not be read', 'the firewall\'s addresses not read: nothing entered')


def config_tests():
    feeds = json.load(open(os.path.join(SCRIPTS, 'feeds.json'), encoding='utf-8'))
    check(feeds.get('ids', {}).get('local') is True and 'url' not in feeds['ids'] and feeds['ids']['name'] == 'IPS drops',
          'feeds.json: IPS drops, a list of the plugin\'s own, filled here and never fetched')
    check('blocklists_ids' in ids_list.cut.owned(), 'cut.py, the rules hook and the page take blocklists_ids for the plugin\'s')
    model = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'models', 'OPNsense', 'BlockLists', 'BlockLists.xml'),
                 encoding='utf-8').read()
    check('<ids type="BooleanField">\n                <Required>Y</Required>\n                <Default>0</Default>' in model
          and '<MinimumValue>5</MinimumValue>' in model and '<MaximumValue>10080</MaximumValue>' in model
          and '<ids_outside type="BooleanField">\n                <Required>Y</Required>\n                <Default>1</Default>' in model,
          'the model: off by default, 5 to 10080 minutes (60), outside only on by default')
    form = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'forms', 'general.xml'),
                encoding='utf-8').read()
    for field in ('blocklists.general.ids', 'blocklists.general.ids_minutes', 'blocklists.general.ids_outside'):
        check('<id>%s</id>' % field in form, 'the form: %s' % field)
    for said in ('Only TCP', '2200000-2299999', 'Never an address of the firewall', '10,000', 'nothing logged before',
                 'IDS mode logs nothing', 'reboot', 'unique local', 'every address leaves'):
        check(said in form, 'the help says: %s' % said)
    cron = open(os.path.join(SRC, 'etc', 'cron.d', 'blocklists'), encoding='utf-8').read()
    check('* * * * * root /usr/local/opnsense/scripts/blocklists/ids_list.py --for 58 > /dev/null 2>&1' in cron,
          'cron: every minute, through the minute')
    actions = open(os.path.join(SRC, 'opnsense', 'service', 'conf', 'actions.d', 'actions_blocklists.conf'),
                   encoding='utf-8').read()
    check('[ids_remove]\ncommand:/usr/local/opnsense/scripts/blocklists/ids_list.py --remove\nparameters:%s\n' in actions
          and '[ids_entries]\ncommand:/usr/local/opnsense/scripts/blocklists/ids_list.py --list\n' in actions,
          'configd: the list and taking one out, its one parameter quoted')
    service = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'Api',
                                'ServiceController.php'), encoding='utf-8').read()
    action = service[service.find('public function idsRemoveAction()'):]
    action = action[:action.find('\n    }\n')]
    check('isPost()' in action and action.find('FILTER_VALIDATE_IP') < action.find("configdpRun('blocklists ids_remove'"),
          'the controller: POST only, an address checked before configd sees it')
    volt = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'index.volt'),
                encoding='utf-8').read()
    check('href="#ids"' in volt and "search: '/api/blocklists/service/search_ids'" in volt
          and "ajaxCall('/api/blocklists/service/ids_remove'" in volt and "/^[0-9A-Fa-f:.]+$/.test(row.address)" in volt,
          'the page: the IPS drops tab, its grid, its button - an address the only value in an attribute')
    for name in ('install/uninstall.sh', 'pkg/post-deinstall.sh'):
        text = open(os.path.join(ROOT, name), encoding='utf-8').read()
        check('"blocklists_ids"' in text and '->del($uuid)' in text and text.find('blocklists_ids') < text.find('filter reload > /dev/null'),
              '%s: the IPS drops\' alias taken out before the filter reload, so no table of it stays' % name)
    # the Lookup tab names this table
    import lookup
    lookup.pfctl = lambda args: types.SimpleNamespace(
        returncode=0, stdout='   blocklists_ids\n' if args == ['-s', 'Tables'] else '', stderr='1/1 addresses match.\n')
    held = lookup.tables('198.51.100.7')['held']
    check(held == [{'alias': 'blocklists_ids', 'list': lookup.categories.T('IPS drops')}],
          'the Lookup tab: an address held names IPS drops: %r' % (held,))


if __name__ == '__main__':
    sys.exit(main())
