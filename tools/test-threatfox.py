#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""threatfox.py - ThreatFox's command-and-control addresses, fetched with the owner's abuse.ch Auth-Key -
against a recorded sample of ThreatFox's export (made up: documentation addresses only), with stand-ins
for abuse.ch's server, pfctl and the system log. No network, no OPNsense, no root:

    python3 tools/test-threatfox.py

What is checked: the export read - ip:port indicators of botnet_cc only, each address once, IPv4 and
IPv6, a line that is not one dropped, an address no internet server has dropped, its columns found by
the line naming them or at their places, zipped or not; an empty or broken file, a 401 or 403, a 429,
a download that breaks off or is too large, keeping the last good list; the key unset, the list not
chosen, its alias not there; abuse.ch's pace - the whole export once a day and no more than twice begun
in a UTC day, the recent additions as often as "Fetch the lists" says, a refused key not sent again
for a day unless Apply; pf's table filled from stdin, and filled again after a reboot without a fetch;
and the Auth-Key, which goes to abuse.ch in the address and nowhere else - never in an answer, a file
or the system log. The configuration around it: the catalogue's entry, the model's field and its mask,
the form, the cron entry, configd's action and the page's Apply.
"""
import calendar
import csv
import email.message
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types
import urllib.error
import xml.etree.ElementTree as ET
import zipfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src')
sys.path.insert(0, os.path.join(SRC, 'opnsense', 'scripts', 'blocklists'))
if importlib.util.find_spec('fcntl') is None:     # Windows: a lock that always takes
    sys.modules['fcntl'] = types.ModuleType('fcntl')
    sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB = 2, 4
    sys.modules['fcntl'].flock = lambda *args: None
import threatfox    # noqa: E402

FAILED = []
CHECKS = [0]


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


# an Auth-Key no account has: the tests' own, never a real one
FAKE_KEY = 'test-only-not-a-real-auth-key-0000'
EXPORTS = 'https://threatfox-api.abuse.ch/v2/files/exports/'

# A recorded sample of ThreatFox's CSV export, as it lays it out (made up: documentation addresses and
# names only). Each line's indicator in the comment after it, here only.
SAMPLE = '\r\n'.join([
    '################################################################',
    '# ThreatFox IOCs: CSV export                                   #',
    '# Last updated: 2026-11-17 09:55:12 UTC                        #',
    '#                                                              #',
    '# Terms Of Use: https://threatfox.abuse.ch/faq/#tos            #',
    '# For questions please contact threatfox [at] abuse.ch         #',
    '################################################################',
    '#',
    '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias",'
    '"malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"',
    '"2026-11-17 09:41:07", "1700001", "198.51.100.7:443", "ip:port", "botnet_cc", "win.cobalt_strike", '
    '"Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "None", "c2,CobaltStrike", "0", "sample"',
    '"2026-11-17 09:12:44", "1700002", "198.51.100.7:8080", "ip:port", "botnet_cc", "win.cobalt_strike", '
    '"", "Cobalt Strike", "", "100", "None", "CobaltStrike", "0", "sample"',
    '"2026-11-16 22:03:19", "1700003", "203.0.113.45:4444", "ip:port", "botnet_cc", "win.asyncrat", "", '
    '"AsyncRAT", "", "75", "None", "AsyncRAT,RAT", "0", "sample"',
    '"2026-11-16 21:00:00", "1700004", "[2001:db8:5::23]:443", "ip:port", "botnet_cc", "elf.mirai", "", '
    '"Mirai", "", "50", "None", "Mirai", "0", "sample"',
    '"2026-11-16 20:00:00", "1700005", "2001:db8:6::9:8443", "ip:port", "botnet_cc", "elf.mirai", "", '
    '"Mirai", "", "50", "None", "Mirai", "0", "sample"',
    '"2026-11-16 19:00:00", "1700006", "192.0.2.66:80", "ip:port", "payload_delivery", "elf.mirai", "", '
    '"Mirai", "", "50", "None", "Mirai", "0", "sample"',
    '"2026-11-16 18:00:00", "1700007", "c2.example.com", "domain", "botnet_cc", "win.asyncrat", "", '
    '"AsyncRAT", "", "75", "None", "AsyncRAT", "0", "sample"',
    '"2026-11-16 17:00:00", "1700008", "http://192.0.2.77/bin.sh", "url", "payload_delivery", "elf.mirai", "", '
    '"Mirai", "", "50", "None", "Mirai", "0", "sample"',
    '"2026-11-16 16:00:00", "1700009", "198.51.100.300:443", "ip:port", "botnet_cc", "win.asyncrat", "", '
    '"AsyncRAT", "", "50", "None", "AsyncRAT", "0", "sample"',
    '"2026-11-16 15:00:00", "1700010", "203.0.113.9:99999", "ip:port", "botnet_cc", "win.asyncrat", "", '
    '"AsyncRAT", "", "50", "None", "AsyncRAT", "0", "sample"',
    '"2026-11-16 14:00:00", "1700011", "00112233445566778899aabbccddeeff", "md5_hash", "payload", '
    '"win.asyncrat", "", "AsyncRAT", "", "50", "None", "AsyncRAT", "0", "sample"',
    '',
])
SAMPLE_SET = {'198.51.100.7', '203.0.113.45', '2001:db8:5::23', '2001:db8:6::9'}
# its recent additions: one new, one the whole export has
RECENT = '\n'.join(SAMPLE.split('\r\n')[:9] + [
    '"2026-11-17 11:40:00", "1700020", "203.0.113.88:443", "ip:port", "botnet_cc", "win.asyncrat", "", '
    '"AsyncRAT", "", "75", "None", "AsyncRAT", "0", "sample"',
    '"2026-11-17 09:41:07", "1700001", "198.51.100.7:443", "ip:port", "botnet_cc", "win.cobalt_strike", "", '
    '"Cobalt Strike", "", "100", "None", "CobaltStrike", "0", "sample"', ''])
# the next day's whole export: 203.0.113.45 gone, 192.0.2.10 new
NEXT = SAMPLE.replace('203.0.113.45:4444', '192.0.2.10:443')
NEXT_SET = SAMPLE_SET - {'203.0.113.45'} | {'192.0.2.10'}
HEADER_ONLY = '\n'.join(SAMPLE.split('\r\n')[:9]) + '\n'


def zipped(text, name='full.csv'):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, text)
    return out.getvalue()


class Answer:
    """A response of abuse.ch's server: a body, and optionally a read that times out at a place."""

    def __init__(self, body, status=200, stall_at=None):
        self.body, self.status, self.stall_at, self.at = body, status, stall_at, 0

    def read(self, n=-1):
        if self.stall_at is not None and self.at >= self.stall_at:
            raise TimeoutError('timed out')
        n = len(self.body) - self.at if n < 0 else n
        if self.stall_at is not None:
            n = min(n, self.stall_at - self.at) or 1
        chunk = self.body[self.at:self.at + n]
        self.at += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Net:
    """abuse.ch's server: an answer for each file name - bytes, an Answer, or an exception to raise,
    built from the address asked (an HTTPError carries it, the key in it, as urllib's does)."""

    def __init__(self):
        self.answers, self.asked = {}, []

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.asked.append({'url': url, 'agent': request.get_header('User-agent'), 'timeout': timeout})
        answer = self.answers.get(url.rsplit('/', 1)[-1], 404)
        if callable(answer):
            answer = answer(url)
        if isinstance(answer, int):
            headers = email.message.Message()
            raise urllib.error.HTTPError(url, answer, 'no', headers, io.BytesIO(b'{"query_status": "x"}'))
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, Answer) else Answer(answer)

    def files(self):
        return [a['url'].rsplit('/', 1)[-1] for a in self.asked]


def http_error(code, retry=None):
    def make(url):
        headers = email.message.Message()
        if retry is not None:
            headers['Retry-After'] = retry
        return urllib.error.HTTPError(url, code, 'no', headers, io.BytesIO(b''))
    return make


class Pf:
    """pfctl: one table, or none; replace takes the list from stdin."""

    def __init__(self):
        self.table, self.calls, self.fail = None, [], None

    def __call__(self, args, text=None):
        self.calls.append((list(args), text))
        if args[:2] != ['-t', threatfox.ALIAS]:
            return types.SimpleNamespace(returncode=1, stdout='', stderr='wrong table')
        if args[2:] == ['-T', 'show']:
            if self.table is None:
                return types.SimpleNamespace(returncode=1, stdout='', stderr='pfctl: Table does not exist.')
            return types.SimpleNamespace(returncode=0, stdout=''.join('   %s\n' % a for a in sorted(self.table)),
                                         stderr='')
        if args[2:] == ['-T', 'replace', '-f', '-']:
            if self.fail:
                return types.SimpleNamespace(returncode=1, stdout='', stderr=self.fail)
            self.table = {line.strip() for line in text.splitlines() if line.strip()}
            return types.SimpleNamespace(returncode=0, stdout='', stderr='%d addresses added.' % len(self.table))
        return types.SimpleNamespace(returncode=1, stdout='', stderr='unexpected')

    def replaced(self):
        return sum(1 for args, _ in self.calls if 'replace' in args)


TMP = tempfile.mkdtemp(prefix='blocklists-threatfox-')
SEEN = []           # every text the script wrote, printed or logged: none may carry the key
LOGS = []


def config(enabled='1', feeds='feodo,threatfox', key=FAKE_KEY, alias=('1', 'external'), refresh='h2'):
    alias_xml = '' if alias is None else (
        '<alias uuid="t1"><name>blocklists_threatfox</name><enabled>%s</enabled><type>%s</type>'
        '<content></content><description>Block Lists: ThreatFox</description></alias>' % alias)
    key_xml = '' if key is None else '<threatfox_key>%s</threatfox_key>' % key
    with open(threatfox.CONFIG, 'w', encoding='utf-8') as fh:
        fh.write('<opnsense><OPNsense><BlockLists><general><enabled>%s</enabled><feeds>%s</feeds>'
                 '<refresh>%s</refresh>%s</general></BlockLists><Firewall><Alias><aliases>%s'
                 '<alias uuid="o1"><name>mine</name><enabled>1</enabled><type>host</type></alias>'
                 '</aliases></Alias></Firewall></OPNsense></opnsense>' % (enabled, feeds, refresh, key_xml, alias_xml))


def fresh():
    """A firewall the list was never fetched on: no state, no table; the stand-ins new."""
    state = os.path.join(TMP, 'state')
    shutil.rmtree(state, ignore_errors=True)
    os.makedirs(state)
    threatfox.STATE_DIR = state
    threatfox.STATUS = os.path.join(state, 'status.json')
    threatfox.LOCK = os.path.join(state, 'lock')
    threatfox.LISTS = {'full': os.path.join(state, 'full.txt'), 'recent': os.path.join(state, 'recent.txt')}
    threatfox.CONFIG = os.path.join(TMP, 'config.xml')
    net, pf = Net(), Pf()
    threatfox.URLOPEN, threatfox.pfctl = net, pf
    config()
    return net, pf


def keep_texts():
    for path in [threatfox.STATUS] + list(threatfox.LISTS.values()):
        if os.path.exists(path):
            with open(path, encoding='utf-8') as fh:
                SEEN.append(fh.read())


def run(now, apply=False):
    answer = threatfox.run(now=now, apply=apply)
    SEEN.append(json.dumps(answer))
    keep_texts()
    return answer


def status():
    return threatfox.load(threatfox.STATUS, {})


def table(pf):
    return {threatfox.network_of(a).split('/')[0] for a in (pf.table or set())}


def at(*when):
    return calendar.timegm(when + (0,) * (6 - len(when)))


T0 = at(2026, 11, 17, 9, 58)
HOUR = 3600


def said(line):
    LOGS.append(line)
    SEEN.append(line)


threatfox.say = said


def test_reading():
    found, counts = threatfox.read(io.StringIO(SAMPLE, newline=''))
    check(found == SAMPLE_SET, 'the sample: its command-and-control addresses, each once, IPv4 and IPv6: %r' % (found,))
    check(counts == {'indicators': 11, 'c2': 7, 'dropped': 2}, 'the sample: 11 indicators, 7 ip:port of botnet_cc, 2 '
          'not addresses dropped: %r' % (counts,))
    lines = SAMPLE.split('\r\n')
    head = lines[8].lstrip('# ').split(',')
    order = [4, 2, 0, 3, 1] + list(range(5, len(head)))
    moved = ['# ' + ','.join(head[i] for i in order)]
    for row in csv.reader(lines[9:], skipinitialspace=True):
        if row:
            moved.append(', '.join('"%s"' % row[i] for i in order))
    found, _ = threatfox.read(io.StringIO('\n'.join(moved)))
    check(found == SAMPLE_SET, 'columns in another order: found by the line naming them')
    found, _ = threatfox.read(io.StringIO('\n'.join(lines[9:])))
    check(found == SAMPLE_SET, 'no line naming the columns: taken at their places')
    try:
        threatfox.read(io.StringIO('<html><body>Not found</body></html>\n'))
        check(False, 'a page that is not an export is refused')
    except threatfox.NotExport:
        pass
    try:
        threatfox.read(io.StringIO(''))
        check(False, 'an empty file is refused')
    except threatfox.NotExport:
        pass
    found, counts = threatfox.read(io.StringIO(HEADER_ONLY))
    check(found == set() and counts['indicators'] == 0, 'an export of nothing: read, nothing in it')

    cases = {
        '198.51.100.7:443': '198.51.100.7', ' 198.51.100.7:443 ': '198.51.100.7', '[2001:db8::7]:443': '2001:db8::7',
        '2001:db8::7:443': '2001:db8::7', '2001:DB8::A:8080': '2001:db8::a', '[2001:db8::7]': '2001:db8::7',
        '198.51.100.7': '198.51.100.7', '2001:db8::7': '2001:db8::7', '198.51.100.7:0': None,
        '198.51.100.7:65536': None, '198.51.100.7:x': None, '198.51.100.7:\u0664\u0664\u0663': None,
        'c2.example.com:443': None, '198.051.100.7:443': None, '': None, '2001:db8::7%em0:443': None,
    }
    for value, want in cases.items():
        got = threatfox.address_of(value)
        check(got == want, 'address_of(%r): %r, not %r' % (value, want, got))
    # the ranges no server on the internet has - built here, not a sample of an export
    never = ['0.0.0.1', '10.0.0.7', '100.64.0.1', '127.0.0.1', '169.254.1.1', '172.16.0.5', '192.168.1.20',
             '224.0.0.1', '240.0.0.1', '255.255.255.255', '[::]', '[::1]', '[::ffff:198.51.100.8]', '[fd00::1]',
             '[fe80::1]', '[ff02::1]']
    rows = HEADER_ONLY + ''.join('"2026-11-17 09:00:00", "1", "%s:443", "ip:port", "botnet_cc"\n' % a for a in never)
    found, counts = threatfox.read(io.StringIO(rows))
    check(found == set() and counts['dropped'] == len(never), 'private, shared, loopback, link-local, multicast, '
          'reserved, unspecified, IPv4-mapped, unique local: all dropped: %r' % (found,))
    check(threatfox.address_of('198.51.100.8:443') == '198.51.100.8', 'documentation ranges are not among them')

    for name, body in (('zipped', zipped(SAMPLE)), ('plain', SAMPLE.encode())):
        found, _ = threatfox.read_export(io.BytesIO(body))
        check(found == SAMPLE_SET, 'an export %s: read' % name)
    two = io.BytesIO()
    with zipfile.ZipFile(two, 'w') as archive:
        archive.writestr('a.csv', SAMPLE)
        archive.writestr('b.csv', SAMPLE)
    for name, body in (('two CSV files', two.getvalue()), ('no CSV', zipped(SAMPLE, 'full.txt')),
                       ('a damaged zip', zipped(SAMPLE)[:60] + b'\x00' * 40)):
        try:
            threatfox.read_export(io.BytesIO(body))
            check(False, 'a zip with %s is refused' % name)
        except threatfox.NotExport:
            pass


def test_pace():
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE), 'recent.csv': RECENT.encode()}
    LOGS.clear()
    answer = run(T0)
    check(net.files() == ['full.csv.zip'], 'first run: the whole export, and nothing else: %r' % net.files())
    asked = net.asked[0]
    check(asked['url'] == EXPORTS + FAKE_KEY + '/full.csv.zip', 'the key in the address, as abuse.ch asks: '
          + asked['url'].replace(FAKE_KEY, '<key>'))
    check(asked['agent'] == 'os-blocklists' and asked['timeout'] == threatfox.TIMEOUT,
          'a User-Agent of os-blocklists, and a timeout: %r' % ((asked['agent'], asked['timeout']),))
    check(table(pf) == SAMPLE_SET, "pf's table holds the list: %r" % (table(pf),))
    check(pf.calls[-1][0] == ['-t', 'blocklists_threatfox', '-T', 'replace', '-f', '-']
          and set(pf.calls[-1][1].split()) == SAMPLE_SET, 'filled by pfctl -T replace -f -, the list on stdin')
    check(answer['fetched'] == {'full': True} and answer['entries'] == 4 and answer['table'] == 'filled',
          'the answer: fetched, 4 addresses, the table filled: %r' % (answer,))
    check(status()['message'] == '4 addresses, from the whole export fetched 2026-11-17 09:58 UTC',
          'the message: ' + status()['message'])
    check(any('whole export fetched' in line and '4 addresses' in line for line in LOGS),
          'the system log says it: %r' % LOGS)
    check(threatfox.read_list(threatfox.LISTS['full']) == SAMPLE_SET, 'the list kept for the next run')

    run(T0 + 300)
    check(len(net.asked) == 1 and pf.replaced() == 1, 'five minutes on: nothing fetched, the table not touched')
    run(T0 + 2 * HOUR - 60)
    check(len(net.asked) == 1, 'just under two hours: nothing fetched')
    run(T0 + 2 * HOUR)
    check(net.files()[1:] == ['recent.csv'], 'two hours on ("Fetch the lists" by default): the recent additions')
    check(table(pf) == SAMPLE_SET | {'203.0.113.88'}, 'the list: the whole export and the recent additions')
    check('the recent additions fetched 2026-11-17 11:58 UTC' in status()['message'], status()['message'])
    run(T0 + 4 * HOUR)
    check(net.files()[2:] == ['recent.csv'], 'and again two hours later')
    run(T0 + 5 * HOUR)
    check(len(net.asked) == 3, 'nothing between')
    net.answers['full.csv.zip'] = zipped(NEXT)
    run(T0 + 24 * HOUR)
    check(net.files()[3:] == ['full.csv.zip'], 'a day on: the whole export again, and only it')
    check(table(pf) == NEXT_SET, 'the list now that whole export alone, the recent additions it holds gone: %r'
          % (table(pf),))
    check(threatfox.read_list(threatfox.LISTS['recent']) == set(), 'the recent additions kept here emptied')

    # "Fetch the lists" Every 6 hours
    net, pf = fresh()
    config(refresh='h6')
    net.answers = {'full.csv.zip': zipped(SAMPLE), 'recent.csv': RECENT.encode()}
    for t in (T0, T0 + 2 * HOUR, T0 + 6 * HOUR - 60, T0 + 6 * HOUR):
        run(t)
    check(net.files() == ['full.csv.zip', 'recent.csv'], 'Every 6 hours: the recent additions six hours on: %r'
          % net.files())

    # a reboot: the table empty again, the list put back without a fetch
    pf.table = None
    run(T0 + 6 * HOUR + 300)
    check(len(net.asked) == 2 and table(pf) == SAMPLE_SET | {'203.0.113.88'},
          'after a reboot the table is filled again from the lists kept, nothing fetched')

    # the whole export failing: tried again after the pace, no more than twice begun in a UTC day
    net, pf = fresh()
    net.answers = {'full.csv.zip': b'<html>Service unavailable</html>', 'recent.csv': RECENT.encode()}
    run(T0)
    check(net.files() == ['full.csv.zip', 'recent.csv'], 'a whole export that is no export: the recent additions '
          'all the same: %r' % net.files())
    check(table(pf) == {'203.0.113.88', '198.51.100.7'}, 'the list: the recent additions alone')
    run(T0 + 2 * HOUR)
    check(net.files()[2:3] == ['full.csv.zip'], 'tried again two hours on (the second of the day)')
    run(T0 + 4 * HOUR)
    run(T0 + 13 * HOUR)
    check('full.csv.zip' not in net.files()[3:], 'no third download of the whole export begun in the UTC day: %r'
          % net.files())
    check(status()['full']['tries'] == 2, 'two begun in the day: %r' % status()['full'])
    run(at(2026, 11, 18, 0, 5))
    check(net.files()[-1:] == ['full.csv.zip'] or 'full.csv.zip' in net.files()[-2:],
          'the next UTC day: tried again: %r' % net.files())

    # a download that breaks off counts as begun: the cap holds for it too
    net, pf = fresh()
    net.answers = {'full.csv.zip': lambda url: Answer(zipped(SAMPLE), stall_at=100)}
    run(T0)
    check(status()['full']['tries'] == 1 and 'broke off' in status()['full']['error'],
          'a download that broke off: one begun, said: %r' % status()['full'])
    check(pf.table is None, 'nothing put into pf')

    # 429: not before the time abuse.ch gives
    net, pf = fresh()
    net.answers = {'full.csv.zip': http_error(429, '18000'), 'recent.csv': RECENT.encode()}
    run(T0)
    check(status()['full']['held'] == T0 + 18000 and 'HTTP 429' in status()['message'], '429 with Retry-After: '
          'held 5 hours, said: %r' % status()['full'])
    net.answers['full.csv.zip'] = zipped(SAMPLE)
    run(T0 + 2 * HOUR)
    check(net.files().count('full.csv.zip') == 1, '429: not asked again within its Retry-After')
    run(T0 + 5 * HOUR)
    check(net.files().count('full.csv.zip') == 2 and table(pf) >= SAMPLE_SET, 'after it: fetched')
    net, pf = fresh()
    net.answers = {'full.csv.zip': http_error(429)}
    run(T0)
    check(status()['full']['held'] == at(2026, 11, 18), '429 without Retry-After: held until 00:00 UTC')
    run(at(2026, 11, 17, 23, 55))
    check(net.files().count('full.csv.zip') == 1, '429: not before 00:00 UTC')


def test_refused():
    for code in (401, 403):
        net, pf = fresh()
        net.answers = {'full.csv.zip': zipped(SAMPLE), 'recent.csv': RECENT.encode()}
        run(T0)
        net.answers = {'full.csv.zip': code, 'recent.csv': code}
        LOGS.clear()
        run(T0 + 24 * HOUR)
        check(net.files() == ['full.csv.zip', 'full.csv.zip'], '%d: the whole export refused, the recent additions not '
              'asked with the same key: %r' % (code, net.files()))
        check(table(pf) == SAMPLE_SET and threatfox.read_list(threatfox.LISTS['full']) == SAMPLE_SET,
              '%d: the last good list kept, in pf and here' % code)
        message = status()['message']
        check(('abuse.ch refused the Auth-Key at 2026-11-18 09:58 UTC (HTTP %d)' % code) in message
              and 'nothing is sent before 2026-11-19 09:58 UTC, or the next Apply' in message
              and message.endswith('the list is kept'), '%d: said on the page: %s' % (code, message))
        check(any(('refused the Auth-Key (HTTP %d)' % code) in line for line in LOGS), '%d: in the system log' % code)
        for t in (T0 + 24 * HOUR + 300, T0 + 26 * HOUR, T0 + 48 * HOUR - 300):
            run(t)
        check(len(net.asked) == 2, '%d: nothing sent again for a day: %r' % (code, net.files()))
        run(T0 + 24 * HOUR + 450, apply=True)
        check(net.files()[2:] == ['full.csv.zip'], '%d: Apply with the key still refused: the whole export asked once, '
              'the recent additions not after it: %r' % (code, net.files()))
        net.answers = {'full.csv.zip': zipped(NEXT)}
        run(T0 + 24 * HOUR + 600, apply=True)
        check(len(net.asked) == 4 and table(pf) == NEXT_SET and not status().get('refused'),
              '%d: Apply (a key just replaced) sends it again at once: fetched' % code)
    net, pf = fresh()
    net.answers = {'full.csv.zip': 401}
    run(T0)
    run(T0 + 24 * HOUR)
    check(len(net.asked) == 2, 'refused: sent again a day later')
    # the recent additions refused (the key revoked since the whole export), then Apply with a new one
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE), 'recent.csv': 401}
    run(T0)
    run(T0 + 2 * HOUR)
    check(net.files() == ['full.csv.zip', 'recent.csv'] and status().get('refused') == T0 + 2 * HOUR,
          'the recent additions refused: %r' % net.files())
    net.answers['recent.csv'] = RECENT.encode()
    run(T0 + 2 * HOUR + 600, apply=True)
    check(net.files()[2:] == ['recent.csv'] and table(pf) == SAMPLE_SET | {'203.0.113.88'},
          'Apply: the recent additions tried again at once, and fetched: %r' % net.files())


def test_kept():
    """failures that keep the last good list"""
    for name, answer, said in (
            ('an empty file', b'', 'not a ThreatFox export: no line of a ThreatFox export in it'),
            ('a whole export with no command-and-control address', zipped(HEADER_ONLY),
             'not a ThreatFox export: no command-and-control address in it'),
            ('a broken zip', b'PK\x03\x04' + b'\x00' * 50, 'not a ThreatFox export: a damaged zip'),
            ('HTTP 500', 500, 'abuse.ch answered HTTP 500'),
            ('HTTP 404', 404, 'abuse.ch answered HTTP 404'),
            ('no connection', urllib.error.URLError('connection refused'), 'abuse.ch not reached: connection refused'),
            ('a timeout', lambda url: Answer(zipped(SAMPLE), stall_at=0), 'the download broke off: no answer within 30 s')):
        net, pf = fresh()
        net.answers = {'full.csv.zip': zipped(SAMPLE)}
        run(T0)
        net.answers = {'full.csv.zip': answer, 'recent.csv': answer}
        run(T0 + 24 * HOUR)
        check(table(pf) == SAMPLE_SET and threatfox.read_list(threatfox.LISTS['full']) == SAMPLE_SET,
              '%s: the last good list kept' % name)
        error = status()['full'].get('error', '')
        check(error.startswith(said), '%s: said "%s", not "%s"' % (name, said, error))
        check(status()['message'].endswith('the list is kept'), '%s: the page says the list is kept: %s'
              % (name, status()['message']))
    # a recent export of nothing is an export: read, nothing added
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE), 'recent.csv': HEADER_ONLY.encode()}
    run(T0)
    run(T0 + 2 * HOUR)
    check(table(pf) == SAMPLE_SET and 'error' not in status()['recent'], 'recent additions of nothing: fine')
    # too large
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE)}
    limit, threatfox.LIMIT = threatfox.LIMIT, {'full': 100, 'recent': 100}
    run(T0)
    threatfox.LIMIT = limit
    check(status()['full'].get('error') == 'larger than 0 MB' and pf.table is None, 'too large: refused, nothing put')
    # past its deadline
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE)}
    deadline, threatfox.DEADLINE = threatfox.DEADLINE, {'full': -1, 'recent': -1}
    run(T0)
    threatfox.DEADLINE = deadline
    check(status()['full'].get('error') == 'not done within -1 s' and pf.table is None,
          'a download past its deadline: stopped, said, nothing put: %r' % status()['full'].get('error'))
    # pf refusing the list
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE)}
    pf.fail = 'pfctl: Cannot allocate memory.'
    run(T0)
    check(status()['table'].get('error') == 'pfctl: Cannot allocate memory.'
          and "pf's table not filled: pfctl: Cannot allocate memory." in status()['message']
          and threatfox.read_list(threatfox.LISTS['full']) == SAMPLE_SET, 'pfctl failing: said, the list kept here')
    pf.fail = None
    run(T0 + 300)
    check(table(pf) == SAMPLE_SET and not status()['table'], 'and filled at the next run, nothing fetched again')
    # a state file of another shape, and a list of one address
    net, pf = fresh()
    with open(threatfox.STATUS, 'w') as fh:
        fh.write('{"full": "x", "recent": [], "table": 3}')
    one = HEADER_ONLY + '"2026-11-17 09:00:00", "1", "192.0.2.5:443", "ip:port", "botnet_cc"\n'
    net.answers = {'full.csv.zip': zipped(one)}
    run(T0)
    check(table(pf) == {'192.0.2.5'} and status()['message'] == '1 address, from the whole export fetched '
          '2026-11-17 09:58 UTC', 'a state file of another shape: started again; one address: ' + status()['message'])


def test_not_ready():
    for name, kwargs, said in (
            ('the key unset', {'key': None}, 'no abuse.ch Auth-Key saved: nothing fetched'),
            ('the key empty', {'key': ''}, 'no abuse.ch Auth-Key saved: nothing fetched'),
            ('a key with a slash', {'key': 'test-only/not-a-real-key'},
             'abuse.ch Auth-Key saved is not one (letters, digits, . _ ~ -): nothing fetched'),
            ('the list not chosen', {'feeds': 'feodo'}, 'ThreatFox is not chosen: nothing fetched'),
            ('Block Lists off', {'enabled': '0'}, 'Block Lists is off: nothing fetched'),
            ('no alias', {'alias': None}, 'its alias is not there yet, Apply makes it: nothing fetched'),
            ('the alias off', {'alias': ('0', 'external')}, 'its alias is switched off: nothing fetched'),
            ('the alias a URL table', {'alias': ('1', 'urltable')},
             'its alias is not an external one, Apply makes it one: nothing fetched')):
        net, pf = fresh()
        net.answers = {'full.csv.zip': zipped(SAMPLE)}
        pf.table = {'192.0.2.200'}
        config(**kwargs)
        answer = run(T0, apply=True)
        check(net.asked == [] and pf.table == {'192.0.2.200'} and pf.replaced() == 0,
              '%s: nothing sent, the table left alone' % name)
        check(answer['message'] == said and status()['message'] == said, '%s: said "%s"' % (name, answer['message']))
    with open(threatfox.CONFIG, 'w') as fh:
        fh.write('<opnsense')
    check(threatfox.run(now=T0)['message'] == 'config.xml could not be read: nothing fetched', 'config.xml unread')


def test_key_kept_to_itself():
    # the last guard of each way out: a file written, a line logged
    net, pf = fresh()
    threatfox._secrets.append(FAKE_KEY)
    threatfox.save(threatfox.STATUS, {'note': 'in ' + EXPORTS + FAKE_KEY + '/x'})
    with open(threatfox.STATUS, encoding='utf-8') as fh:
        written = fh.read()
    LOGS.clear()
    threatfox.log('in ' + EXPORTS + FAKE_KEY + '/x')
    check(FAKE_KEY not in written and '<Auth-Key>' in written and LOGS and FAKE_KEY not in LOGS[0]
          and '<Auth-Key>' in LOGS[0], 'a text carrying the key, written or logged: the key taken out')
    net, pf = fresh()
    net.answers = {'full.csv.zip': lambda url: urllib.error.URLError('no route to ' + url)}
    run(T0)
    check(FAKE_KEY not in status()['full']['error'] and '<Auth-Key>' in status()['full']['error'],
          'an error naming the address: the key taken out: ' + status()['full']['error'])
    out = io.StringIO()
    real_run = threatfox.run
    threatfox.run = lambda **kwargs: (_ for _ in ()).throw(RuntimeError(EXPORTS + FAKE_KEY + '/full.csv.zip'))
    with redirect_stdout(out):
        rc = threatfox.main([])
    threatfox.run = real_run
    SEEN.append(out.getvalue())
    check(rc == 0 and FAKE_KEY not in out.getvalue() and 'stopped' in out.getvalue(), 'a run that stops: exit 0, '
          'said, the key taken out: ' + out.getvalue().strip())
    net, pf = fresh()
    net.answers = {'full.csv.zip': zipped(SAMPLE)}
    out = io.StringIO()
    with redirect_stdout(out):
        rc = threatfox.main(['--apply'])
    SEEN.append(out.getvalue())
    printed = json.loads(out.getvalue())
    check(rc == 0 and printed['ready'] and printed['fetched'] == {'full': True}, 'main(): one JSON answer, exit 0')
    keep_texts()
    leaked = [text[:80] for text in SEEN if FAKE_KEY in text or 'not-a-real-key' in text]
    check(not leaked and len(SEEN) > 50, 'the key in no answer, file or log line (%d looked at): %r' % (len(SEEN), leaked))


def test_configuration():
    feeds = json.load(open(os.path.join(SRC, 'opnsense', 'scripts', 'blocklists', 'feeds.json'), encoding='utf-8'))
    feed = feeds.get('threatfox', {})
    check(feed.get('c2') is True and feed.get('key') == 'abuse.ch' and 'url' not in feed,
          'feeds.json: ThreatFox a command-and-control list, fetched with the abuse.ch key, no URL table')
    check(feed.get('name') == 'ThreatFox: command-and-control addresses' and feed.get('proto') == ''
          and feed.get('min_hours') == 1, 'feeds.json: its name, both families, a floor of an hour')
    check(threatfox.pace('h2', feed) == 2 and threatfox.pace('h24', feed) == 24 and threatfox.pace('x', feed) == 2
          and threatfox.pace('h2', {'min_hours': 6}) == 6 and threatfox.pace('h2', {}) == 24,
          'the pace: "Fetch the lists", or the floor where longer')

    model = ET.parse(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'models', 'OPNsense', 'BlockLists',
                                  'BlockLists.xml')).getroot()
    field = model.find('items/general/threatfox_key')
    check(field is not None and field.get('type') == 'UpdateOnlyTextField',
          "the model's key: OPNsense's write-only field, never handed to the page")
    mask = field.findtext('Mask') if field is not None else ''
    check(mask == '/' + threatfox.KEY.pattern + '/D', 'the model takes the keys threatfox.py takes: ' + str(mask))
    check(model.findtext('items/general/feeds/OptionValues/threatfox') == feed.get('name'), 'the list offered by its name')
    for key in ('0123456789abcdef0123456789abcdef0123456789abcdef', 'A-b_c.d~e', FAKE_KEY):
        check(threatfox.KEY.fullmatch(key) is not None, 'a key taken: ' + key)
    for key in ('short', 'a/b/c/d/e/f', 'abcdefgh?x=1', 'abcdefgh#x', 'abcd efgh', 'abcdefgh\n', 'abc%2Fdefgh', 'x' * 129):
        check(threatfox.KEY.fullmatch(key) is None, 'a key refused: %r' % key)

    form = ET.parse(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'forms',
                                 'general.xml')).getroot()
    fields = {f.findtext('id'): f for f in form.findall('field')}
    shown = fields.get('blocklists.general.threatfox_key')
    check(shown is not None and shown.findtext('type') == 'password' and shown.findtext('label') == 'abuse.ch Auth-Key',
          'the form: a password field "abuse.ch Auth-Key"')

    cron = open(os.path.join(SRC, 'etc', 'cron.d', 'blocklists'), encoding='utf-8').read()
    check(re.search(r'^\*/5 \* \* \* \* root /usr/local/opnsense/scripts/blocklists/threatfox\.py > /dev/null 2>&1$',
                    cron, re.M) is not None, 'the cron entry: every five minutes, without --apply')
    actions = open(os.path.join(SRC, 'opnsense', 'service', 'conf', 'actions.d', 'actions_blocklists.conf'),
                   encoding='utf-8').read()
    section = actions.split('[threatfox]', 1)[-1].split('\n\n', 1)[0]
    check('[threatfox]' in actions and 'command:/usr/local/opnsense/scripts/blocklists/threatfox.py' in section
          and 'parameters:--apply\n' in section and '%s' not in section,
          "configd's action: the script with --apply, no parameter of the caller's")
    controller = open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'Api',
                                   'ServiceController.php'), encoding='utf-8').read()
    refresh = controller.find("configdRun('filter refresh_aliases')")
    fetch = controller.find("configdRun('blocklists threatfox', true)")
    cut = controller.find("configdRun('blocklists cut')")
    check(-1 < refresh < fetch < cut, "the page's Apply: ThreatFox fetched after the aliases' reload, in the "
          'background, before the cut')


def main():
    try:
        test_reading()
        test_pace()
        test_refused()
        test_kept()
        test_not_ready()
        test_key_kept_to_itself()
        test_configuration()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
