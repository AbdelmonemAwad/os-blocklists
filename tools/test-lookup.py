#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""lookup.py - where a name or an address is held, for the page's Lookup tab (2026-11-19) - with
fixtures: the web categories' files, an Unbound dnsbl.json as OPNsense writes it, and a stand-in for
pfctl. No OPNsense, no root:

    python3 tools/test-lookup.py

The plan's test - a name a UT1 category holds, an address in a listed table, a name in nothing: three
right answers - and around it: a name under a listed one (a wildcard entry) and not under an exact one,
the exception that lets it through, the owner's policies told from this plugin's, dnsbl.json read in
place, missing or empty; and the argument checked before anything runs: shell metacharacters, a name
with spaces, an empty one, a zone, a port, a bracket - refused, and pfctl never run for them.
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
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'blocklists'))
if importlib.util.find_spec('fcntl') is None:     # Windows: the scripts lock with it; nothing here locks
    sys.modules['fcntl'] = types.ModuleType('fcntl')
    sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB, sys.modules['fcntl'].LOCK_UN = 2, 4, 8
    sys.modules['fcntl'].flock = lambda *args: None
import lookup       # noqa: E402

FAILED = []
CHECKS = [0]
OWNER = '5b7a3c2e-0000-4000-8000-000000000001'      # a policy of the owner's in Unbound DNS: Blocklists


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


class Run:
    def __init__(self, returncode, stdout='', stderr=''):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class Pf:
    """pfctl as lookup.py calls it: -s Tables, and -t <table> -T test <address>; each call recorded."""

    def __init__(self, tables, holds):
        self.tables, self.holds, self.calls = tables, holds, []

    def __call__(self, args):
        self.calls.append(list(args))
        if args == ['-s', 'Tables']:
            return Run(0, ''.join('   %s\n' % t for t in self.tables)) if self.tables is not None else Run(1, '', 'pfctl: no')
        table, address = args[1], args[4]
        if table not in self.tables:
            return Run(1, '', 'pfctl: Table does not exist.\n')
        if address in self.holds.get(table, ()):
            return Run(0, '', '1/1 addresses match.\n')
        return Run(2, '', '0/1 addresses match.\n')


def dnsbl(pretty=False):
    """dnsbl.json as OPNsense's blocklists.py writes it (ujson, one line): this plugin's policy and one of
    the owner's for a network, with entries exact and wildcard."""
    data = {
        'casino.example': [{'bl': 'ut1_gambling', 'wildcard': True, 'idx': lookup.categories.POLICY}],
        'ads.example': [{'bl': 'custom1', 'wildcard': False, 'idx': OWNER}],
        'tracker.example': [{'bl': 'hgz002', 'wildcard': True, 'idx': OWNER},
                            {'bl': 'ut1_publicite', 'wildcard': True, 'idx': lookup.categories.POLICY}],
    }
    for i in range(20000):
        data['filler%05d.example' % i] = [{'bl': 'custom1', 'wildcard': True, 'idx': OWNER}]
    config = {'general': {'has_wildcards': True},
              OWNER: {'source_nets': ['192.168.1.0/24'], 'address': '0.0.0.0', 'rcode': 'NOERROR',
                      'description': 'Office', 'id': OWNER, 'passlist': '.*localhost$', 'prio': 256, 'hidx': 0,
                      # a key in the policies shaped like an entry: not one, being after "config"
                      'decoy.example': [{'bl': 'x', 'wildcard': True, 'idx': OWNER}]},
              lookup.categories.POLICY: {'source_nets': [], 'address': '0.0.0.0', 'rcode': 'NOERROR',
                                         'description': 'Block Lists: web categories (UT1)', 'id': lookup.categories.POLICY,
                                         'passlist': r'(.*\.)?safe\.casino\.example$', 'prio': 2 ** 128, 'hidx': 1}}
    whole = {'data': data, 'config': config}
    return json.dumps(whole, indent=1) if pretty else json.dumps(whole, separators=(',', ':'))


def main():
    tmp = tempfile.mkdtemp(prefix='blocklists-lookup-')
    try:
        state = os.path.join(tmp, 'categories')
        os.makedirs(state)
        lookup.categories.STATE_DIR = state
        lookup.categories.ACTIVE = os.path.join(state, 'unbound.json')
        lookup.categories.CATALOGUE = os.path.join(state, 'catalogue.json')
        with open(lookup.categories.ACTIVE, 'w') as fh:
            json.dump({'categories': {'gambling': 'gambling', 'malware': 'phishing', 'phishing': 'phishing'},
                       'exceptions': ['safe.casino.example']}, fh)
        with open(os.path.join(state, 'gambling.domains'), 'w') as fh:
            fh.write('casino.example\nbet.example\n')
        with open(os.path.join(state, 'phishing.domains'), 'w') as fh:
            fh.write('phish.example\n')
        lookup.DNSBL = os.path.join(tmp, 'dnsbl.json')
        with open(lookup.DNSBL, 'w') as fh:
            fh.write(dnsbl())
        pf = Pf(['blocklists_feodo', 'blocklists_spamhaus_drop', 'blocklists_countries', 'owner_table'],
                {'blocklists_feodo': {'198.51.100.7', '2001:db8::7'}, 'owner_table': {'198.51.100.7'}})
        lookup.pfctl = pf

        # the plan's three: a name one UT1 category holds, an address in a listed table, a name in nothing
        one = lookup.lookup('www.casino.example')
        check(one['kind'] == 'name' and one['found'] == 2
              and one['categories']['held'] == [{'id': 'gambling', 'name': 'Gambling', 'entry': 'casino.example', 'exception': ''}],
              'a name of one UT1 category: Gambling, by its parent casino.example: %r' % (one.get('categories'),))
        check([(u['entry'], u['wildcard'], u['mine'], u['passes']) for u in one['unbound']['held']] == [('casino.example', True, True, False)]
              and one['unbound']['held'][0]['description'] == 'Block Lists: web categories (UT1)',
              'a name of one UT1 category: in Unbound\'s data, the web categories\' policy, a wildcard entry: %r' % (one.get('unbound'),))
        check(pf.calls == [], 'a name: pf never asked - its tables hold addresses')
        two = lookup.lookup('198.51.100.7')
        check(two['kind'] == 'address' and two['found'] == 1
              and two['tables']['held'] == [{'alias': 'blocklists_feodo', 'list': 'abuse.ch Feodo Tracker'}]
              and two['tables']['checked'] == 3,
              'an address in a listed table: blocklists_feodo, of the three tables of the plugin\'s: %r' % (two.get('tables'),))
        check(not any('owner_table' in call for call in pf.calls) and 'categories' not in two and 'unbound' not in two,
              'an address: the owner\'s own table not looked at, nor the names')
        check(all(call[:1] == ['-s'] or call[:2] == ['-t', call[1]] and call[2:] == ['-T', 'test', '198.51.100.7'] for call in pf.calls),
              'an address: pfctl -t <table> -T test <address>, nothing else: %r' % (pf.calls,))
        three = lookup.lookup('nothing.example.net')
        check(three['found'] == 0 and three['categories']['held'] == [] and three['unbound']['held'] == []
              and three['unbound']['read'] is True,
              'a name in nothing: held nowhere, and Unbound\'s data read: %r' % (three,))

        # around them
        six = lookup.lookup('2001:DB8:0::7')
        check(six['query'] == '2001:db8::7' and six['found'] == 1, 'an IPv6 address, in its canonical form: %r' % (six.get('query'),))
        check(lookup.lookup('192.0.2.99')['found'] == 0, 'an address in no table: held nowhere')
        safe = lookup.lookup('Safe.Casino.Example.')
        check(safe['query'] == 'safe.casino.example' and safe['categories']['held'][0]['exception'] == 'safe.casino.example'
              and safe['unbound']['held'][0]['passes'] is True,
              'an exception: the category holds it, and its exception and the policy\'s passlist let it through: %r' % (safe,))
        under = lookup.lookup('x.safe.casino.example')
        check(under['categories']['held'][0]['exception'] == 'safe.casino.example' and under['unbound']['held'][0]['passes'] is True,
              'an exception lets every name under it through')
        ads = lookup.lookup('ads.example')
        check([(u['entry'], u['mine'], u['description'], u['source_nets']) for u in ads['unbound']['held']]
              == [('ads.example', False, 'Office', ['192.168.1.0/24'])],
              'an exact entry of the owner\'s: his policy, its description and network: %r' % (ads['unbound'],))
        check(lookup.lookup('x.ads.example')['unbound']['held'] == [], 'a name under an exact entry: not held (only wildcards count)')
        both = lookup.lookup('a.tracker.example')
        check(sorted(u['mine'] for u in both['unbound']['held']) == [False, True], 'a wildcard entry of two policies: both told')
        check(lookup.lookup('phish.example')['categories']['held'] == [
            {'id': 'malware', 'name': 'Malware', 'entry': 'phish.example', 'exception': ''},
            {'id': 'phishing', 'name': 'Phishing', 'entry': 'phish.example', 'exception': ''}],
            'malware and phishing, one file: both named')
        check(lookup.lookup('source_nets')['unbound']['held'] == [] and lookup.lookup('general')['unbound']['held'] == []
              and lookup.lookup('decoy.example')['unbound']['held'] == [],
              'the policies\' own keys (source_nets, general, one shaped like an entry) are not entries')
        with open(lookup.DNSBL, 'w') as fh:
            fh.write(dnsbl(pretty=True))
        check([u['entry'] for u in lookup.lookup('www.casino.example')['unbound']['held']] == ['casino.example'],
              'dnsbl.json written with spaces: read the same')
        with open(lookup.DNSBL, 'w') as fh:
            fh.write(dnsbl())
        started = time.monotonic()
        for _ in range(5):
            lookup.lookup('nothing.example.net')
        check(time.monotonic() - started < 10, 'dnsbl.json of 20,000 names searched in place, five times, in %.2f s' % (time.monotonic() - started))
        open(lookup.DNSBL, 'w').close()
        empty = lookup.lookup('www.casino.example')['unbound']
        check(empty['read'] is True and empty['held'] == [], 'dnsbl.json empty (no policy holds a name): read, nothing held')
        os.unlink(lookup.DNSBL)
        gone = lookup.lookup('www.casino.example')
        check(gone['unbound']['read'] is False and gone['unbound']['errors'] and gone['categories']['held'],
              'dnsbl.json not there: said, and the categories still answered')
        os.unlink(lookup.categories.ACTIVE)
        check(lookup.lookup('www.casino.example')['categories'] == {'applied': 0, 'held': [], 'errors': []},
              'no category applied: none looked at')
        lookup.pfctl = Pf(None, {})
        check(lookup.lookup('198.51.100.7')['tables']['errors'], 'pf\'s tables not readable: said')

        # the argument: a host name or an address, nothing else, checked before anything runs
        pf = Pf(['blocklists_feodo'], {})
        lookup.pfctl = pf
        for bad in ('', ' ', 'a b.com', ' example.com', 'example.com ', 'example.com\n', 'a.com;reboot', '$(reboot)',
                    '`id`', 'a.com|sh', 'a.com&&x', 'a.com>x', "a'b.com", 'a"b.com', '../etc/passwd', '-rf', '-t',
                    'example.com:443', '[2001:db8::1]', 'fe80::1%em0', '192.0.2.1/24', '*.example.com', 'ex\u00e4mple.com',
                    'a..b.com', '.example.com', 'a-.com', '-a.com', 'x' * 64 + '.com', ('a.' * 127) + 'com', None, 7):
            result = lookup.lookup(bad)
            check(result == {'error': 'not a name or an address'}, 'refused: %r -> %r' % (bad, result))
        check(pf.calls == [], 'nothing refused reached pfctl')
        for argv in ([], ['a.example', 'b.example']):
            out = io.StringIO()
            with redirect_stdout(out):
                lookup.main(argv)
            check(json.loads(out.getvalue()) == {'error': 'not a name or an address'}, 'main %r: refused' % (argv,))
        out = io.StringIO()
        with redirect_stdout(out):
            lookup.main(['nothing.example.net'])
        check(json.loads(out.getvalue())['found'] == 0, 'main: one JSON object')
        check(lookup.parse('a.' * 125 + 'com') == ('name', 'a.' * 125 + 'com'), 'a name of 253 characters taken')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # the controller checks the query before configd sees it, as the script does
    service = open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'Api',
                                'ServiceController.php'), encoding='utf-8').read()
    action = service[service.find('public function lookupAction()'):]
    action = action[:action.find('\n    }\n')]
    check("$this->request->isPost()" in action and "configdpRun('blocklists lookup', [$query])" in action
          and action.find('FILTER_VALIDATE_IP') < action.find('configdpRun'),
          'the controller: POST only, the query checked, then configdpRun (quoted) - never configdRun with it')
    volt = open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'index.volt'),
                encoding='utf-8').read()
    check("ajaxCall('/api/blocklists/service/lookup', {'query': query}" in volt and 'id="bl-lookup-query"' in volt
          and '.text(plain(' in volt[volt.find('function lookup_show'):volt.find("$('#bl-lookup-form')")],
          'the page: the Lookup tab posts the query, and shows the answer as text')

    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
