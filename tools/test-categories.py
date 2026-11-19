#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""UT1's web categories (2026-11-19): the Unbound handler blocklists_ut1.py against a stand-in for
OPNsense's BaseBlocklistHandler, and categories.py against a stand-in for UT1's server, Unbound's
rebuild and the system log. No network, no OPNsense, no root:

    python3 tools/test-categories.py

The handler: its one policy (no source network, 0.0.0.0, NOERROR), each name as a wildcard entry, bare
IPv4 lines, comments and blank lines left out, a name given once though two categories hold it, the
exceptions as anchored regexes (example.com passes www.example.com and not example.com.evil.net, as
OPNsense's module matches them) and the names they cover left out, adult refused even where ACTIVE names
it, a file missing, a folder or a link left out and the rest given, and nothing that stops the update.
categories.py: an archive's <folder>/domains read by its name, a plain file and only one, every other
member left unread and nothing written by an archive's own path; the conditional request (304: no
rebuild of Unbound's blocklist), malware and phishing one download, adult never fetched though written
into config.xml by hand, a failed download keeping the last good copy, a category no longer chosen or
Block Lists off taken out, a rebuild that did not happen tried again; UT1's global_usage read, and its
maintenance page not taken for it; the catalogue shipped; the page's rows; and what installs, runs and
removes it.
"""
import email.message
import importlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import sys
import tarfile
import tempfile
import threading
import time
import types
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src')
SCRIPTS = os.path.join(SRC, 'opnsense', 'scripts', 'blocklists')
HANDLER = os.path.join(SRC, 'opnsense', 'scripts', 'unbound', 'blocklists', 'blocklists_ut1.py')
sys.path.insert(0, SCRIPTS)
if importlib.util.find_spec('fcntl') is None:     # Windows: a lock that always takes
    sys.modules['fcntl'] = types.ModuleType('fcntl')
    sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB, sys.modules['fcntl'].LOCK_UN = 2, 4, 8
    sys.modules['fcntl'].flock = lambda *args: None
if importlib.util.find_spec('syslog') is None:    # Windows: the handler logs with it; the tests catch it
    sys.modules['syslog'] = types.ModuleType('syslog')
    sys.modules['syslog'].LOG_ERR, sys.modules['syslog'].LOG_NOTICE = 3, 5
    sys.modules['syslog'].syslog = lambda *args: None
import categories    # noqa: E402
URLOPEN = categories.URLOPEN    # as the script has it, before the tests stand in for UT1's server

FAILED = []
CHECKS = [0]


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


# A stand-in for OPNsense's blocklists package: its BaseBlocklistHandler as OPNsense core 26.7.9 has it
# (src/opnsense/scripts/unbound/blocklists/__init__.py L43-97, BSD-2-Clause, Copyright (c) 2023-2025
# Deciso B.V.): the constructor, get_policies(), blocklists_iter(), get_passlist_patterns() and
# _load_config(), copied, and nothing else - the URL reader a handler of local files does not use.
FAKE_BASE = '''
import os
import re
import uuid
from configparser import ConfigParser


class BaseBlocklistHandler:
    def __init__(self, config=None):
        self.config = config
        self.cnf = None
        self.cnf_indexed = None
        self.priority = 0
        # XXX: remove when plugins are refactored
        self._compat_id = str(uuid.uuid4())

        self.cur_bl_location = '/var/unbound/data/dnsbl.json'

        self.domain_pattern = re.compile(
            r'^(\\*\\.){,1}(([\\da-zA-Z_])([_\\w-]{,62})\\.){,127}(([\\da-zA-Z])[_\\w-]{,61})'
            r'?([\\da-zA-Z]\\.((xn\\-\\-[a-zA-Z\\d]+)|([a-zA-Z\\d]{2,})))$'
        )

        self._load_config()

    def get_policies(self):
        if hasattr(self, "get_config") and callable(getattr(self, "get_config")):
            cfg = {
                'source_nets': [],
                'address': '0.0.0.0',
                'rcode': 'NOERROR',
                'description': 'compat',
                'id': self._compat_id
            }
            return [cfg]

    def blocklists_iter(self):
        if hasattr(self, "get_blocklist") and callable(getattr(self, "get_blocklist")):
            for domain, cnf in self.get_blocklist().items():
                yield domain, self._compat_id, cnf

    def get_passlist_patterns(self):
        return []

    def _load_config(self):
        if os.path.exists(self.config):
            self.cnf = ConfigParser()
            self.cnf.read(self.config)
'''


def merge(handlers):
    """What OPNsense 26.7.9's BlocklistParser.update_blocklist() makes of its handlers' output
    (__init__.py L198-259, condensed): the policies sorted, each domain's items in policy order, idx set."""
    from ipaddress import ip_network
    policies = {}
    for hidx, handler in enumerate(handlers):
        for policy in handler.get_policies():
            policies[policy['id']] = policy.copy()
            prio = (max([ip_network(src).num_addresses for src in policy['source_nets']]) if policy['source_nets']
                    else ip_network('0::0/0').num_addresses)
            policies[policy['id']]['prio'] = prio
            policies[policy['id']]['hidx'] = hidx
    policies = dict(sorted(policies.items(), key=lambda x: (x[1]['prio'], x[1]['hidx'])))
    blocklists = {}
    for handler in handlers:
        for domain, policy, cnf in handler.blocklists_iter():
            blocklists.setdefault(domain, {}).setdefault(policy, []).append(cnf)
    data, wild = {}, False
    for domain in blocklists:
        data[domain] = []
        for policy in policies:
            for item in blocklists[domain].get(policy, []):
                item['idx'] = policy
                data[domain].append(item)
                wild = wild or bool(item.get('wildcard'))
    config = {'general': {'has_wildcards': wild}}
    config.update(policies)
    return {'data': data, 'config': config}


def blocked(merged, name):
    """Whether OPNsense 26.7.9's Unbound module blocks a name for a client every policy covers: its
    DNSBL.policy_match() (unbound-dnsbl/lib/dnsbl.py L123-171) and ModuleContext.set_config()'s passlist
    (lib/__init__.py L137-170, re.compile(passlist, re.IGNORECASE), then .match()), condensed."""
    data, config = merged['data'], merged['config']
    domain = sub = name.rstrip('.').lower()
    while True:
        for meta in data.get(sub, []):
            if sub == domain or meta.get('wildcard'):
                policy = config.get(str(meta.get('idx')))
                if not policy:
                    return False
                if policy.get('passlist') and re.compile(policy['passlist'], re.IGNORECASE).match(domain):
                    return False
                return policy['id'] if 'id' in policy else True
        if '.' not in sub or not config['general']['has_wildcards']:
            return False
        sub = sub.split('.', maxsplit=1)[1]


def load_handler(tmp):
    """blocklists_ut1.py imported as OPNsense imports it - blocklists.blocklists_ut1, beside the
    stand-in base class - its files pointed at tmp."""
    package = os.path.join(tmp, 'pkg', 'blocklists')
    os.makedirs(package, exist_ok=True)
    with open(os.path.join(package, '__init__.py'), 'w') as fh:
        fh.write(FAKE_BASE)
    shutil.copy(HANDLER, os.path.join(package, 'blocklists_ut1.py'))
    sys.path.insert(0, os.path.join(tmp, 'pkg'))
    for name in list(sys.modules):
        if name == 'blocklists' or name.startswith('blocklists.'):
            del sys.modules[name]
    module = importlib.import_module('blocklists.blocklists_ut1')
    sys.path.pop(0)
    module.ACTIVE = os.path.join(tmp, 'unbound.json')
    module.DATA = tmp
    module.logged = []
    module.log = lambda priority, message: module.logged.append(message)
    return module


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def handler_tests(tmp):
    h = load_handler(tmp)
    base = sys.modules['blocklists'].BaseBlocklistHandler
    check(issubclass(h.UT1BlocklistHandler, base), 'handler: a subclass of BaseBlocklistHandler')

    # nothing applied: no policy, nothing given
    one = h.UT1BlocklistHandler()
    check(one.priority == 50, 'handler: priority 50, after OPNsense\'s own handler (10), as Q-Feeds\'')
    check(one.get_policies() == [] and list(one.blocklists_iter()) == [], 'handler: no ACTIVE - no policy, no name')

    write(os.path.join(tmp, 'gambling.domains'), '\n'.join([
        'casino.example', 'bet.example', '# a comment', '', '   ', '192.0.2.1', '198.51.100.20',
        '*.wild.example', 'UPPER.Example', 'dup.example', 'dup.example', 'nodot', '-bad-.example',
        'www.example.com', 'example.com', 'deep.www.example.org', 'x' * 300 + '.example', 'shared.example', '']))
    write(os.path.join(tmp, 'phishing.domains'), 'phish.example\nshared.example\n')
    write(os.path.join(tmp, 'games.domains'), 'game.example\nshared.example\n')
    write(os.path.join(tmp, 'unbound.json'), json.dumps({
        'categories': {'gambling': 'gambling', 'malware': 'phishing', 'phishing': 'phishing', 'games': 'games',
                       'adult': 'adult', 'porn': 'adult', '../etc': 'gambling', 'missing': 'missing',
                       'folder': 'folder'},
        'exceptions': ['Example.com', 'www.example.org', 'not a name', 7]}))
    os.makedirs(os.path.join(tmp, 'folder.domains'), exist_ok=True)
    write(os.path.join(tmp, 'adult.domains'), 'adult-only.example\n')
    one = h.UT1BlocklistHandler()
    check(sorted(one.categories) == ['folder', 'gambling', 'games', 'malware', 'missing', 'phishing'],
          'handler: adult and a category of the adult archive refused though ACTIVE names them, a name that is '
          'not one left out: %r' % (sorted(one.categories),))
    check(one.exceptions == ['example.com', 'www.example.org'], 'handler: exceptions lowercased, what is not a name '
          'left out: %r' % (one.exceptions,))
    policies = one.get_policies()
    check(len(policies) == 1 and policies[0]['id'] == h.POLICY and policies[0]['source_nets'] == []
          and policies[0]['address'] == '0.0.0.0' and policies[0]['rcode'] == 'NOERROR'
          and policies[0]['description'] == 'Block Lists: web categories (UT1)',
          'handler: one policy, every client, 0.0.0.0 NOERROR as OPNsense\'s default: %r' % (policies,))
    check(policies[0]['passlist'] == r'(.*\.)?example\.com$|(.*\.)?www\.example\.org$',
          'handler: the passlist, (.*\\.)?<escaped name>$ for each: %r' % (policies[0]['passlist'],))
    given = list(one.blocklists_iter())
    names = [g[0] for g in given]
    check(all(g[1] == h.POLICY and g[2]['wildcard'] is True for g in given),
          'handler: every name a wildcard entry of its own policy')
    check({'casino.example', 'bet.example', 'wild.example', 'upper.example', 'dup.example', 'phish.example',
           'game.example', 'shared.example'} == set(names),
          'handler: the names, a *. and capitals as one; IPv4, comments, blanks, a one-label name, a bad name, a '
          'too long one and the names the exceptions cover (example.com, www.example.com, deep.www.example.org) '
          'left out: %r' % (sorted(names),))
    check(len(names) == len(set(names)), 'handler: each name once, though two categories or a file twice hold it')
    check('192.0.2.1' not in names and '198.51.100.20' not in names, 'handler: bare IPv4 lines never given as names')
    check('adult-only.example' not in names, 'handler: adult\'s file never read')
    bl = {g[0]: g[2]['bl'] for g in given}
    check(bl.get('phish.example') == 'ut1_malware' and bl.get('shared.example') == 'ut1_gambling'
          and bl.get('game.example') == 'ut1_games',
          'handler: malware and phishing, one file, given once, by the first of them; a shared name by the first '
          'category: %r' % (bl,))
    check(any('missing' in m for m in h.logged) and any('folder' in m and 'not a plain file' in m for m in h.logged),
          'handler: a missing file and a folder left out and said in the log: %r' % (h.logged,))

    # the exceptions as OPNsense's module matches them
    merged = merge([one])
    pattern = re.compile(merged['config'][h.POLICY]['passlist'], re.IGNORECASE)
    check(pattern.match('www.example.com') and pattern.match('example.com') and pattern.match('A.B.EXAMPLE.COM'),
          'exceptions: example.com passes itself and every name under it')
    check(not pattern.match('example.com.evil.net') and not pattern.match('badexample.com')
          and not pattern.match('example.community'),
          'exceptions: not example.com.evil.net, badexample.com or example.community')
    check(blocked(merged, 'casino.example') == h.POLICY and blocked(merged, 'a.b.casino.example') == h.POLICY,
          'Unbound: a name of a category and every name under it blocked by the policy')
    check(blocked(merged, 'other.example') is False, 'Unbound: a name of no category passes')
    write(os.path.join(tmp, 'gambling.domains'), 'example.org\n')
    merged = merge([h.UT1BlocklistHandler()])
    check(blocked(merged, 'www.example.org') is False and blocked(merged, 'x.www.example.org') is False
          and blocked(merged, 'example.org') == h.POLICY and blocked(merged, 'mail.example.org') == h.POLICY,
          'Unbound: an exception under a listed name lets it and its subdomains through, the rest blocked')

    # a file that cannot be read: left out, the rest given
    write(os.path.join(tmp, 'gambling.domains'), 'casino.example\n')
    with open(os.path.join(tmp, 'games.domains'), 'wb') as fh:
        fh.write(b'game.example\n\xff\xfe\xfdbroken\nafter.example\n')
    try:
        os.symlink(os.path.join(tmp, 'gambling.domains'), os.path.join(tmp, 'missing.domains'))
        linked = True
    except (OSError, NotImplementedError):
        linked = False      # Windows without the right: the folder stands for it
    h.logged.clear()
    names = [g[0] for g in h.UT1BlocklistHandler().blocklists_iter()]
    check({'casino.example', 'game.example', 'after.example', 'phish.example', 'shared.example'} == set(names),
          'handler: bytes that are not UTF-8 skipped, the lines after them given: %r' % (sorted(names),))
    if linked:
        check(any('missing' in m and 'not a plain file' in m for m in h.logged), 'handler: a link left out, not followed')
        os.unlink(os.path.join(tmp, 'missing.domains'))

    # what never stops the update
    for text in ('not json', '[1, 2]', '{"categories": [], "exceptions": {}}', '{"categories": {"x": 3}}'):
        write(os.path.join(tmp, 'unbound.json'), text)
        try:
            ok = h.UT1BlocklistHandler().get_policies() == [] and list(h.UT1BlocklistHandler().blocklists_iter()) == []
        except Exception as e:      # noqa: BLE001
            ok = False
            print('  raised: %r' % e)
        check(ok, 'handler: ACTIVE %r - nothing, and no exception' % text)
    real = sys.modules['blocklists'].BaseBlocklistHandler.__init__

    def broken(self, config=None):
        raise TypeError('an interface that changed')
    sys.modules['blocklists'].BaseBlocklistHandler.__init__ = broken
    try:
        odd = h.UT1BlocklistHandler()
        ok = odd.get_policies() == [] and list(odd.blocklists_iter()) == [] and odd.priority == 50
    except Exception:       # noqa: BLE001
        ok = False
    sys.modules['blocklists'].BaseBlocklistHandler.__init__ = real
    check(ok, 'handler: a base class whose constructor fails - nothing given, nothing raised')
    write(os.path.join(tmp, 'unbound.json'), json.dumps({'categories': {'gambling': 'gambling'}, 'exceptions': []}))
    one = h.UT1BlocklistHandler()
    check(one.get_policies()[0]['passlist'] == '', 'handler: no exception - an empty passlist')
    os.unlink(os.path.join(tmp, 'gambling.domains'))
    check(list(one.blocklists_iter()) == [], 'handler: its only file gone - nothing given, nothing raised')
    for name in os.listdir(tmp):
        path = os.path.join(tmp, name)
        shutil.rmtree(path) if os.path.isdir(path) else os.unlink(path)


# ------------------------------------------------------------------ categories.py

def tar(members):
    """A .tar.gz: members are (name, bytes) for a plain file, or (name, 'symlink'|'hardlink'|'dir', target)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for member in members:
            info = tarfile.TarInfo(member[0])
            if isinstance(member[1], bytes):
                info.size = len(member[1])
                archive.addfile(info, io.BytesIO(member[1]))
                continue
            info.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE, 'dir': tarfile.DIRTYPE}[member[1]]
            info.linkname = member[2] if len(member) > 2 else ''
            archive.addfile(info)
    return out.getvalue()


GAMBLING = b'casino.example\nBET.example\n192.0.2.1\n# a comment\n\n*.wild.example\ndup.example\ndup.example\nnodot\n'
PHISHING = b'phish.example\n203.0.113.9\n'


def unpack_tests(tmp):
    def run(data, members=frozenset({'gambling/domains'})):
        out = io.StringIO()
        try:
            return categories.unpack(io.BytesIO(data), set(members), out) + (out.getvalue(),)
        except categories.Failed as e:
            return str(e)

    names, ipv4, dropped, sha, text = run(tar([('gambling/domains', GAMBLING), ('gambling/urls', b'x/y\n'),
                                               ('gambling/usage', b'black\n')]))
    check(text == 'casino.example\nbet.example\nwild.example\ndup.example\n' and (names, ipv4, dropped) == (4, 1, 1),
          'unpack: the names lowercased, each once, *. taken off; the IPv4 line and a one-label line left out: '
          '%r %r' % (text, (names, ipv4, dropped)))
    before = set(os.listdir(tmp))
    result = run(tar([('../../etc/passwd', b'root\n'), ('/etc/evil', b'x\n'), ('gambling/../../domains', b'x.example\n'),
                      ('gambling/domains', GAMBLING)]))
    check(isinstance(result, tuple) and result[0] == 4 and set(os.listdir(tmp)) == before,
          'unpack: members with a path that climbs out, an absolute one - left unread; nothing written anywhere')
    for members, why in (
            ([('gambling/domains', 'symlink', '/etc/passwd')], 'a symbolic link'),
            ([('gambling/domains', 'hardlink', 'gambling/urls'), ('gambling/urls', b'a.example\n')], 'a hard link'),
            ([('gambling/domains', 'dir')], 'a folder'),
            ([('gambling/domains', GAMBLING), ('gambling/domains', b'other.example\n')], 'there twice')):
        result = run(tar(members))
        check(isinstance(result, str) and ('not a plain file' in result or 'two ' in result),
              'unpack: its domains %s - the archive refused: %r' % (why, result))
    for members, why in (([('./gambling/domains', GAMBLING)], './ before it'), ([('/gambling/domains', GAMBLING)], 'absolute'),
                         ([('phishing/domains', PHISHING)], 'another category\'s'), ([], 'empty')):
        result = run(tar(members))
        check(isinstance(result, str) and result.startswith('no gambling/domains'),
              'unpack: a domains file by another name (%s) is not it: %r' % (why, result))
    result = run(tar([('phishing/domains', PHISHING)]), {'phishing/domains', 'malware/domains'})
    check(isinstance(result, tuple) and result[4] == 'phish.example\n',
          'unpack: malware\'s archive taken by its folder, phishing/')
    check(isinstance(run(b'<!DOCTYPE html><html>Site en maintenance</html>'), str)
          and run(b'<!DOCTYPE html>').startswith('not a category archive'),
          'unpack: a maintenance page is not an archive')
    import gzip
    check(isinstance(run(gzip.compress(b'not a tar file at all' * 40)), str), 'unpack: a gzip that is not a tar refused')
    check(isinstance(run(tar([('m%d' % i, b'') for i in range(categories.MEMBERS + 1)] + [('gambling/domains', GAMBLING)])), str),
          'unpack: more than MEMBERS members refused')
    saved = categories.UNPACKED, categories.MAX_NAMES
    categories.UNPACKED = 20
    check('larger than' in str(run(tar([('gambling/domains', GAMBLING)]))), 'unpack: a member larger than UNPACKED refused')
    categories.UNPACKED, categories.MAX_NAMES = saved[0], 2
    check('more than 2 names' in str(run(tar([('gambling/domains', GAMBLING)]))), 'unpack: more than MAX_NAMES names refused')
    categories.UNPACKED, categories.MAX_NAMES = saved
    long_line = b'a' * 5000 + b'.example\nok.example\n'
    result = run(tar([('gambling/domains', long_line)]))
    check(isinstance(result, tuple) and result[4] == 'ok.example\n', 'unpack: an overlong line left out whole, the next read')


class Server:
    """UT1's download folder as categories.py meets it: archives with their Last-Modified, a 304 to a
    request whose If-Modified-Since is that, failures on demand; every request recorded."""

    def __init__(self):
        self.files, self.fail, self.requests = {}, {}, []

    def put(self, name, body, modified):
        self.files[categories.DOWNLOAD + name] = (body, modified)

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.requests.append((url, request.get_header('If-modified-since'), request.get_header('User-agent')))
        if url in self.fail:
            if self.fail[url] == 'down':
                raise urllib.error.URLError('connection refused')
            raise urllib.error.HTTPError(url, self.fail[url], 'failed', email.message.Message(), io.BytesIO(b''))
        if url not in self.files:
            raise urllib.error.HTTPError(url, 404, 'not found', email.message.Message(), io.BytesIO(b''))
        body, modified = self.files[url]
        if modified and request.get_header('If-modified-since') == modified:
            raise urllib.error.HTTPError(url, 304, 'not modified', email.message.Message(), io.BytesIO(b''))
        return Answer(body, modified)

    def asked(self, name=None):
        return [r for r in self.requests if name is None or r[0] == categories.DOWNLOAD + name]


class Answer(io.BytesIO):
    def __init__(self, body, modified):
        super().__init__(body)
        self.status = 200
        self.headers = email.message.Message()
        if modified:
            self.headers['Last-Modified'] = modified


CONFIG = '''<opnsense><OPNsense>
<BlockLists><general><enabled>{enabled}</enabled><refresh>h2</refresh><categories>{categories}</categories>
<exceptions>{exceptions}</exceptions></general></BlockLists>
<unboundplus><general><enabled>1</enabled></general></unboundplus>
</OPNsense></opnsense>
'''

GLOBAL_USAGE = '''#
#	NAME : name of tar blacklist
#
NAME:	gambling
DEFAULT_TYPE: black
SOURCE: https://squidguard.example
DESC EN: Gambling sites.
NAME EN: Gambling
''' + ''.join('''
NAME:	cat%02d
DEFAULT_TYPE: white
DESC EN: Category number %d <b>bold</b>.
NAME EN: Category %d
''' % (i, i, i) for i in range(12)) + '''
NAME:	adult
DEFAULT_TYPE: black
NAME EN: Adult (X)
NAME:	../evil
NAME EN: Evil
'''


def run_tests(tmp):
    state = os.path.join(tmp, 'state')
    os.makedirs(state)
    categories.STATE_DIR = state
    categories.STATUS = os.path.join(state, 'status.json')
    categories.ACTIVE = os.path.join(state, 'unbound.json')
    categories.CATALOGUE = os.path.join(state, 'catalogue.json')
    categories.LOCK = os.path.join(state, 'lock')
    categories.MARKER = os.path.join(state, 'rebuild')
    categories.CONFIG = os.path.join(tmp, 'config.xml')
    categories.DNSBL = os.path.join(tmp, 'dnsbl.json')
    categories.CORE_LOCK = os.path.join(tmp, 'unbound-download_blocklists.tmp')
    server = Server()
    categories.URLOPEN = server
    reloads, said = [], []
    result = {'done': True}
    categories.say = said.append
    # OPNsense's blocklists.py stood in for, behind configctl: the handler itself, imported beside the
    # stand-in base class, run and merged as blocklists.py does, its dnsbl.json written as it writes it
    # (empty where no policy holds a name). Modes: 'sync' - rebuilt before configctl answers; 'skip' -
    # nothing written (blocklists.py left: another update held its lock); 'stale' - written from an older
    # ACTIVE (a rebuild that began before it was written); 'async' - configctl answers at once and
    # blocklists.py goes on, holding its lock, for `delay` seconds.
    handler = load_handler(os.path.join(tmp, 'core'))
    handler.ACTIVE, handler.DATA = categories.ACTIVE, state
    categories.HANDLER = handler.__file__       # the installed handler: the stamp reads its source
    core = {'mode': 'sync', 'busy': False, 'old': None, 'delay': 0.3, 'threads': []}

    def rebuild(active_path=None):
        handler.ACTIVE = active_path or categories.ACTIVE
        try:
            merged = merge([handler.UT1BlocklistHandler()])
        finally:
            handler.ACTIVE = categories.ACTIVE
        with open(categories.DNSBL, 'w') as fh:
            if merged['data']:
                json.dump(merged, fh, separators=(',', ':'))

    def configctl(*args):
        assert args == ('unbound', 'dnsbl'), args
        reloads.append(json.load(open(categories.ACTIVE)))
        if core['mode'] == 'sync' and result['done']:
            rebuild()
        elif core['mode'] == 'stale':
            rebuild(core['old'])
        elif core['mode'] == 'async':
            core['busy'] = True

            def later():
                time.sleep(core['delay'])
                rebuild()
                core['busy'] = False
            thread = threading.Thread(target=later)
            core['threads'].append(thread)
            thread.start()
        return types.SimpleNamespace(returncode=0, stdout='OK\n', stderr='')
    real_core_busy = categories.core_busy
    categories.configctl = configctl
    categories.core_busy = lambda: core['busy']
    categories.pause = lambda seconds: time.sleep(0.02)

    def config(cats, enabled='1', exceptions='Example.com,www.example.org,bad name'):
        write(categories.CONFIG, CONFIG.format(enabled=enabled, categories=cats, exceptions=exceptions))

    def active():
        return json.load(open(categories.ACTIVE))

    def core_of(given):
        return {k: v for k, v in given.items() if k != 'files'}

    def policy():
        """this plugin's policy in dnsbl.json, or None"""
        return (categories.dnsbl_config() or {}).get(categories.POLICY)

    # nothing chosen: no one contacted
    config('')
    out = categories.run(now=1000000, apply=True)
    check(server.requests == [] and reloads == [] and out['applied'] == [] and not os.path.exists(categories.ACTIVE),
          'run: nothing chosen - UT1 never contacted, no file written, Unbound not rebuilt: %r %r' % (server.requests, reloads))

    t0 = 2000000
    server.put('gambling.tar.gz', tar([('gambling/domains', GAMBLING), ('gambling/urls', b'a/b\n')]), 'Wed, 18 Nov 2026 21:50:17 GMT')
    server.put('phishing.tar.gz', tar([('phishing/domains', PHISHING), ('phishing/usage', b'black\n')]), 'Wed, 18 Nov 2026 21:50:17 GMT')
    server.put('adult.tar.gz', tar([('adult/domains', b'adult.example\n')]), 'Wed, 18 Nov 2026 21:50:17 GMT')
    server.put('global_usage', GLOBAL_USAGE.encode(), 'Sat, 24 Oct 2026 09:09:37 GMT')
    config('gambling,malware,phishing,adult,nosuch,../x')
    out = categories.run(now=t0, apply=True)
    check(len(server.asked('gambling.tar.gz')) == 1 and len(server.asked('phishing.tar.gz')) == 1
          and not server.asked('malware.tar.gz'),
          'run: malware and phishing chosen - one download, phishing.tar.gz: %r' % ([r[0] for r in server.requests],))
    check(not server.asked('adult.tar.gz') and not any('nosuch' in r[0] or '..' in r[0] for r in server.requests),
          'run: adult, written into config.xml by hand, never fetched; nor a name no catalogue has')
    check(all(r[2] == 'os-blocklists' for r in server.requests), 'run: a User-Agent of os-blocklists')
    check(set(out['refused']) == {'adult', 'nosuch', '../x'} and 'cannot be chosen' in out['refused']['adult'],
          'run: adult refused with its reason, the others too: %r' % (out['refused'],))
    check(core_of(active()) == {'categories': {'gambling': 'gambling', 'malware': 'phishing', 'phishing': 'phishing'},
                                'exceptions': ['example.com', 'www.example.org']}
          and set(active()['files']) == {'gambling', 'phishing'} and all(len(v) == 64 for v in active()['files'].values()),
          'run: ACTIVE - the categories applied and their archive, the exceptions checked: %r' % (active(),))
    check(len(reloads) == 1, 'run: Unbound\'s blocklist rebuilt once for the run: %d' % len(reloads))
    check(policy() and policy()['stamp'] == categories.expected() and json.load(open(categories.STATUS))['reload']['pending'] is False,
          'run: dnsbl.json holds the policy with the stamp of this handler and this ACTIVE - the rebuild done')
    check(sorted(os.listdir(state)) == sorted(['catalogue.json', 'gambling.domains', 'phishing.domains', 'status.json',
                                               'unbound.json']),
          'run: the files kept - one domains file each archive, nothing by an archive\'s own path: %r' % (sorted(os.listdir(state)),))
    check(open(os.path.join(state, 'gambling.domains')).read() == 'casino.example\nbet.example\nwild.example\ndup.example\n',
          'run: the names written as unpack() gives them')
    status = json.load(open(categories.STATUS))
    check(status['archives']['gambling']['last_modified'] == 'Wed, 18 Nov 2026 21:50:17 GMT'
          and status['archives']['gambling']['names'] == 4,
          'run: UT1\'s Last-Modified kept for the next request, and the names counted')
    check(status['catalogue'].get('categories') == 14 and 'cat03' in json.load(open(categories.CATALOGUE))['categories']
          and '../evil' not in json.load(open(categories.CATALOGUE))['categories'],
          'run: global_usage read: its categories, ../evil left out: %r' % (status['catalogue'],))
    entries = categories.catalogue()
    check(entries['cat03']['source'] == 'ut1' and entries['cat03']['use'] == 'allow' and '<' not in entries['cat03']['description']
          and entries['gambling']['source'] == 'shipped' and entries['adult']['refused'] and '../evil' not in entries,
          'catalogue: UT1\'s new categories added, < and > taken out of its text, the shipped ones kept, adult refused')

    # two hours on: checked again, with If-Modified-Since; 304 - nothing else
    server.requests.clear()
    out = categories.run(now=t0 + 2 * 3600 + 1)
    archives = [r for r in server.requests if r[0].endswith('.tar.gz')]
    check(len(archives) == 2 and all(r[1] == 'Wed, 18 Nov 2026 21:50:17 GMT' for r in archives),
          'run: each archive checked again after two hours, with If-Modified-Since: %r' % (server.requests,))
    check(server.asked('global_usage') == [(categories.CATALOGUE_URL, 'Sat, 24 Oct 2026 09:09:37 GMT', 'os-blocklists')],
          'run: nosuch, chosen and in no catalogue - global_usage asked again within the hour, conditionally')
    server.requests.clear()
    categories.run(now=t0 + 2 * 3600 + 301)
    check(server.requests == [], 'run: five minutes on - not asked again, the hour not gone')
    check(out['fetched'] == {'gambling': 'unchanged', 'phishing': 'unchanged'} and len(reloads) == 1,
          'run: 304 - unchanged, and Unbound not rebuilt: %r %d' % (out['fetched'], len(reloads)))
    server.requests.clear()
    categories.run(now=t0 + 2 * 3600 + 300)
    check(server.requests == [], 'run: five minutes on, nothing due - no request')

    # 200 with the same names: no rebuild; with new names: one
    server.put('gambling.tar.gz', tar([('gambling/domains', GAMBLING)]), 'Thu, 19 Nov 2026 03:00:00 GMT')
    out = categories.run(now=t0 + 4 * 3600 + 2)
    check(out['fetched'].get('gambling') == 'unchanged' and len(reloads) == 1,
          'run: a new copy with the same names - unchanged, not rebuilt: %r' % (out['fetched'],))
    server.put('gambling.tar.gz', tar([('gambling/domains', b'casino.example\nnew.example\n')]), 'Thu, 19 Nov 2026 09:00:00 GMT')
    out = categories.run(now=t0 + 6 * 3600 + 3)
    check(out['fetched'].get('gambling') == 'changed' and len(reloads) == 2 and policy()['stamp'] == categories.expected()
          and open(os.path.join(state, 'gambling.domains')).read() == 'casino.example\nnew.example\n',
          'run: a changed copy - kept, and Unbound rebuilt once')

    # a failed download keeps the last good copy, and says so
    server.fail[categories.DOWNLOAD + 'gambling.tar.gz'] = 500
    out = categories.run(now=t0 + 8 * 3600 + 4)
    status = json.load(open(categories.STATUS))
    check(out['fetched'].get('gambling') == 'failed' and 'gambling' in active()['categories'] and len(reloads) == 2
          and open(os.path.join(state, 'gambling.domains')).read() == 'casino.example\nnew.example\n',
          'run: HTTP 500 - the last good copy kept and still applied, Unbound not rebuilt')
    said = categories.english(status['archives']['gambling']['message'])
    check('the last copy is kept' in said and 'HTTP 500' in said, 'run: the page told the copy is kept: %r' % (said,))
    server.fail[categories.DOWNLOAD + 'gambling.tar.gz'] = 'down'
    server.requests.clear()
    categories.run(now=t0 + 8 * 3600 + 600)
    check(server.requests == [], 'run: a failure is not tried again before its pace (cron)')
    out = categories.run(now=t0 + 8 * 3600 + 900, apply=True)
    check(out['fetched'].get('gambling') == 'failed'
          and 'not reached' in categories.english(json.load(open(categories.STATUS))['archives']['gambling']['error']),
          'run: Apply tries a failed one again at once')
    server.put('gambling.tar.gz', b'<!DOCTYPE html><html>Site en maintenance</html>', 'Thu, 19 Nov 2026 10:00:00 GMT')
    del server.fail[categories.DOWNLOAD + 'gambling.tar.gz']
    out = categories.run(now=t0 + 8 * 3600 + 1000, apply=True)
    check(out['fetched'].get('gambling') == 'failed' and os.path.getsize(os.path.join(state, 'gambling.domains')) > 0,
          'run: a maintenance page answered 200 - not an archive, the copy kept')

    # a rebuild that did not happen is tried at the next run
    server.put('gambling.tar.gz', tar([('gambling/domains', b'casino.example\n')]), 'Thu, 19 Nov 2026 11:00:00 GMT')
    result['done'] = False
    categories.run(now=t0 + 9 * 3600, apply=True)
    check(json.load(open(categories.STATUS))['reload']['pending'] is True, 'run: Unbound\'s blocklist not written - pending')
    result['done'] = True
    before = len(reloads)
    categories.run(now=t0 + 9 * 3600 + 300)
    check(len(reloads) == before + 1 and json.load(open(categories.STATUS))['reload']['pending'] is False,
          'run: the pending rebuild done at the next run, though nothing changed')

    # a category no longer chosen: taken out; Block Lists off: all
    config('malware')
    before = len(reloads)
    out = categories.run(now=t0 + 10 * 3600, apply=True)
    check(not os.path.exists(os.path.join(state, 'gambling.domains')) and 'gambling' in out['removed']
          and core_of(active()) == {'categories': {'malware': 'phishing'}, 'exceptions': ['example.com', 'www.example.org']}
          and len(reloads) == before + 1,
          'run: gambling unchosen - its file deleted, ACTIVE without it, Unbound rebuilt: %r' % (active(),))
    check(os.path.exists(os.path.join(state, 'phishing.domains')), 'run: malware alone keeps phishing\'s one file')
    config('malware', exceptions='')
    categories.run(now=t0 + 10 * 3600 + 60, apply=True)
    check(active()['exceptions'] == [] and len(reloads) == before + 2, 'run: an exception removed - ACTIVE and Unbound follow')
    config('malware', enabled='0')
    server.requests.clear()
    out = categories.run(now=t0 + 11 * 3600, apply=True)
    check(active() == categories.EMPTY and not os.path.exists(os.path.join(state, 'phishing.domains'))
          and server.requests == [] and len(reloads) == before + 3 and 'Block Lists is off' in out['message'],
          'run: Block Lists off - every category taken out, nothing fetched, Unbound rebuilt once: %r' % (out['message'],))
    before = len(reloads)
    categories.run(now=t0 + 11 * 3600 + 300)
    check(len(reloads) == before, 'run: nothing changed - not rebuilt again')
    config('malware', enabled='1', exceptions='')
    out = categories.run(now=t0 + 11 * 3600 + 400, apply=True)
    check(out['fetched'] == {'phishing': 'changed'} and active()['categories'] == {'malware': 'phishing'}
          and open(os.path.join(state, 'phishing.domains')).read() == 'phish.example\n',
          'run: malware alone - phishing.tar.gz fetched, its phishing/domains taken: %r' % (out,))
    config('malware', enabled='0')
    categories.run(now=t0 + 11 * 3600 + 450, apply=True)
    before = len(reloads)
    mtime = os.stat(categories.STATUS).st_mtime_ns
    categories.run(now=t0 + 11 * 3600 + 600)
    check(os.stat(categories.STATUS).st_mtime_ns == mtime, 'run: a run with nothing to do writes nothing')

    # a category only UT1's catalogue holds, that catalogue lost with /var in memory: fetched again, not
    # refused for good (2026-11-19 review)
    server.put('cat03.tar.gz', tar([('cat03/domains', b'three.example\n')]), 'Thu, 19 Nov 2026 12:00:00 GMT')
    config('cat03')
    out = categories.run(now=t0 + 12 * 3600, apply=True)
    check(out['applied'] == ['cat03'], 'run: a category of UT1\'s catalogue only - applied: %r' % (out,))
    os.unlink(categories.CATALOGUE)
    server.requests.clear()
    out = categories.run(now=t0 + 12 * 3600 + 300)
    check('cat03' not in out['refused'] and out['applied'] == ['cat03'] and server.asked('global_usage')
          and os.path.exists(categories.CATALOGUE),
          'run: its catalogue gone - global_usage fetched again at once, the category kept: %r' % (out,))
    os.unlink(categories.CATALOGUE)
    server.fail[categories.CATALOGUE_URL] = 503
    out = categories.run(now=t0 + 12 * 3600 + 600, apply=True)
    check('cat03' in out['refused'], 'run: its catalogue gone and UT1 answering 503 - refused for now: %r' % (out['refused'],))
    server.requests.clear()
    categories.run(now=t0 + 12 * 3600 + 900)
    check(not server.asked('global_usage'), 'run: and asked again only within the hour, not every run')
    del server.fail[categories.CATALOGUE_URL]
    categories.run(now=t0 + 12 * 3600 + 600 + 3601)
    check(os.path.exists(categories.CATALOGUE) and 'cat03' in categories.catalogue(), 'run: an hour on - fetched, known again')
    config('malware', enabled='0')
    categories.run(now=t0 + 12 * 3600 + 600 + 3700, apply=True)

    # UT1's maintenance page for global_usage is not its catalogue: the one kept stays
    server.put('global_usage', b'<!DOCTYPE html><html lang="fr"><title>Site en maintenance</title></html>', 'x')
    config('gambling')
    categories.run(now=t0 + 40 * 3600, apply=True)
    status = json.load(open(categories.STATUS))
    check('not the catalogue of UT1' in categories.english(status['catalogue'].get('error', '')) and 'cat03' in categories.catalogue(),
          'run: global_usage answered with a maintenance page - refused, the catalogue kept: %r' % (status['catalogue'],))

    # --installed: a rebuild only where categories are applied and the handler is not the one that wrote
    before = len(reloads)
    check('holds the 1 categories' in categories.installed()['message'] and len(reloads) == before,
          'installed: the same handler already wrote this ACTIVE - nothing run')
    old = categories.expected()
    with open(categories.HANDLER, 'a') as fh:
        fh.write('# a new release of the handler\n')
    check(categories.expected() != old and policy()['stamp'] == old,
          'installed: a new handler - a new stamp, and dnsbl.json still the old one\'s')
    check('holds the 1 categories' in categories.installed()['message'] and len(reloads) == before + 1
          and policy()['stamp'] == categories.expected(),
          'installed: a new handler - Unbound\'s blocklist rebuilt with it')
    reload_tests(categories, core, reloads, result, policy, config, state, real_core_busy)
    write(categories.ACTIVE, json.dumps(categories.EMPTY))
    check('left as it is' in categories.installed()['message'], 'installed: none applied - nothing run')

    # the page's rows
    config('gambling,adult', exceptions='example.com')
    categories.run(now=t0 + 41 * 3600, apply=True)
    page = categories.page(categories.settings())
    rows = {r['id']: r for r in page['rows']}
    check(rows['adult']['refused'] and rows['adult']['state'] == '' and rows['adult']['approximate'] is True
          and rows['adult']['memory'] == 4600371 * 527,
          'page: adult with its reason, its size from UT1\'s page marked approximate: %r' % (rows['adult'],))
    check(rows['gambling']['chosen'] and rows['gambling']['applied'] and rows['gambling']['counted']
          and rows['gambling']['names'] == 1 and rows['gambling']['memory'] == 527
          and 'names, fetched' in categories.english(rows['gambling']['state']),
          'page: gambling chosen and applied, the names of its copy, 527 bytes a name: %r' % (rows['gambling'],))
    check(rows['games']['chosen'] is False and rows['games']['counted'] is False and rows['games']['names'] > 1000,
          'page: a category not chosen - the catalogue\'s count')
    check(page['unbound'] is True and page['handler'] is True and page['exceptions'] == ['example.com']
          and page['names'] == 1 and page['bytes_per_name'] == 527, 'page: the line\'s parts: %r' % ({k: v for k, v in page.items() if k != 'rows'},))
    texts_tests(json.load(open(categories.STATUS)), page)
    shutil.rmtree(state)


SOURCE = os.path.join(SCRIPTS, 'i18n', 'ui', 'source.json')


def reload_tests(categories, core, reloads, result, policy, config, state, real_core_busy):
    """A rebuild taken as done only when dnsbl.json says so (2026-11-19 review): configctl answering while
    blocklists.py goes on, past RELOAD_TIMEOUT too; a rebuild of an older ACTIVE; one that wrote nothing;
    nothing applied but the policy still there; an install that found a run going or a rebuild not done."""
    t = 3000000
    status = lambda: json.load(open(categories.STATUS))      # noqa: E731
    # configctl answers at once (its socket's 120 s), blocklists.py goes on: waited for, then read
    config('gambling', exceptions='')
    core['mode'], core['delay'] = 'async', 0.3
    started = time.monotonic()
    categories.run(now=t, apply=True)
    check(status()['reload']['pending'] is False and policy()['stamp'] == categories.expected()
          and time.monotonic() - started >= 0.25,
          'rebuild: configctl answered while blocklists.py went on - its end waited for, the stamp read: done')
    # past RELOAD_TIMEOUT: owed, and the next run finds it done without asking again
    saved, categories.RELOAD_TIMEOUT = categories.RELOAD_TIMEOUT, 0.2
    core['delay'] = 0.8
    config('gambling', exceptions='example.com')
    categories.run(now=t + 300, apply=True)
    check(status()['reload']['pending'] is True
          and 'still being rebuilt' in categories.english(status()['reload']['error']),
          'rebuild: longer than RELOAD_TIMEOUT - pending, not taken for done: %r' % (status()['reload'],))
    for thread in core['threads']:
        thread.join()
    calls = len(reloads)
    categories.run(now=t + 600)
    check(status()['reload']['pending'] is False and len(reloads) == calls and policy()['stamp'] == categories.expected(),
          'rebuild: the long one ended with this ACTIVE - the next run sees it done, and asks for no other')
    categories.RELOAD_TIMEOUT = saved
    # a rebuild that read the ACTIVE before this one: not taken for this one
    old = os.path.join(state, 'unbound.json.old')
    with open(categories.ACTIVE, 'rb') as src, open(old, 'wb') as dst:
        dst.write(src.read())
    core['mode'], core['old'] = 'stale', old
    config('gambling', exceptions='')
    categories.run(now=t + 900, apply=True)
    check(status()['reload']['pending'] is True and policy() and policy()['stamp'] != categories.expected(),
          'rebuild: dnsbl.json written from the older ACTIVE (a rebuild begun before it changed) - pending')
    core['mode'] = 'sync'
    categories.run(now=t + 1200)
    check(status()['reload']['pending'] is False and policy()['stamp'] == categories.expected(),
          'rebuild: rebuilt at the next run, with this ACTIVE')
    # nothing applied, the policy still there: owed until it is gone
    core['mode'] = 'skip'
    config('gambling', enabled='0')
    categories.run(now=t + 1500, apply=True)
    check(status()['reload']['pending'] is True and policy() is not None,
          'rebuild: nothing applied, blocklists.py wrote nothing - the policy still there, pending')
    core['mode'] = 'sync'
    categories.run(now=t + 1800)
    check(status()['reload']['pending'] is False and policy() is None,
          'rebuild: the policy gone from dnsbl.json - done')
    # an install that finds a run going: the rebuild owed to the next run, which does it
    config('gambling', exceptions='')
    categories.run(now=t + 2100, apply=True)
    with open(categories.HANDLER, 'a') as fh:
        fh.write('# another release\n')
    taken, categories.take = categories.take, lambda lock, wait: False
    out = io.StringIO()
    from contextlib import redirect_stdout
    with redirect_stdout(out):
        categories.main(['--installed'])
    categories.take = taken
    check(os.path.exists(categories.MARKER) and 'next run' in out.getvalue(),
          'installed: a run going - the rebuild owed to the next run (MARKER): %r' % (out.getvalue(),))
    calls = len(reloads)
    categories.run(now=t + 2400)
    check(len(reloads) == calls + 1 and not os.path.exists(categories.MARKER) and policy()['stamp'] == categories.expected(),
          'run: the rebuild owed by the install done with the new handler, though nothing else changed')
    # an install whose rebuild is not done: owed too
    with open(categories.HANDLER, 'a') as fh:
        fh.write('# a third release\n')
    core['mode'] = 'skip'
    message = categories.installed()['message']
    check(os.path.exists(categories.MARKER) and 'owed to the next run' in message,
          'installed: a rebuild not done - owed to the next run: %r' % (message,))
    core['mode'] = 'sync'
    categories.run(now=t + 2700)
    check(not os.path.exists(categories.MARKER) and policy()['stamp'] == categories.expected(), 'run: and done')
    # dnsbl.json's policies found at its end, or anywhere in it
    saved, categories.TAIL = categories.TAIL, 64
    check(categories.dnsbl_config().get(categories.POLICY, {}).get('stamp') == categories.expected(),
          'dnsbl_config: the policies found past the end read first')
    categories.TAIL = saved
    with open(categories.DNSBL, 'w') as fh:
        fh.write('{"data": {"a.example": [')
    check(categories.dnsbl_config() is None and categories.written(categories.expected()) is False,
          'dnsbl_config: a broken dnsbl.json - not read, not taken for done')
    core['mode'] = 'sync'
    categories.run(now=t + 3000, apply=True)
    # blocklists.py's lock as it holds it: probed, let go, never made
    lock = categories.CORE_LOCK
    if os.path.exists(lock):
        os.unlink(lock)
    check(real_core_busy() is False and not os.path.exists(lock), 'core_busy: no lock file - not busy, and none made')
    if os.name == 'posix':      # a real flock: not the stand-in Windows gets
        import fcntl
        with open(lock, 'w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            check(real_core_busy() is True, 'core_busy: blocklists.py holding its lock - busy')
            fcntl.flock(held, fcntl.LOCK_UN)
        check(real_core_busy() is False and os.path.exists(lock), 'core_busy: let go - not busy, the file left as it was')


def texts(value, found):
    """Every T() in a value, nested ones too, into found; a bare string where a text is - English the
    page cannot translate - as itself."""
    if isinstance(value, list):
        for item in value:
            texts(item, found)
    elif isinstance(value, dict) and set(value) == {'text', 'args'}:
        found.append(value['text'])
        for arg in value['args']:
            if isinstance(arg, (dict, list)):
                texts(arg, found)
    else:
        found.append(('not a T()', value))


def texts_tests(status, page):
    catalogued = set(json.load(open(SOURCE, encoding='utf-8')))
    found = []
    texts(status['message'], found)
    for archive in status['archives'].values():
        texts(archive['message'], found)
    for why in status['refused'].values():
        texts(why, found)
    texts(page['message'], found)
    for row in page['rows']:
        if row['state']:
            texts(row['state'], found)
        if row['refused']:
            texts(row['refused'], found)
        for key in ('name', 'description'):
            if row[key] and row['shipped']:
                found.append(row[key])
    check(found and all(isinstance(t, str) for t in found),
          'texts: every text the page is given is a T(), none a bare English sentence: %r'
          % ([t for t in found if not isinstance(t, str)][:3],))
    check(all(t in catalogued for t in found if isinstance(t, str)),
          'texts: every msgid the page is given is in source.json: %r' % (sorted({t for t in found if isinstance(t, str)} - catalogued),))


def quiet_tests(tmp):
    """What the README says of a firewall where no category is chosen (2026-11-19 review): no one
    contacted; where none was ever chosen nothing made; once what was applied is taken out, nothing
    written - checked on the files themselves, through main() as cron runs it."""
    from contextlib import redirect_stdout
    state = os.path.join(tmp, 'state')
    categories.STATE_DIR = state
    categories.STATUS = os.path.join(state, 'status.json')
    categories.ACTIVE = os.path.join(state, 'unbound.json')
    categories.CATALOGUE = os.path.join(state, 'catalogue.json')
    categories.LOCK = os.path.join(state, 'lock')
    categories.MARKER = os.path.join(state, 'rebuild')
    categories.CONFIG = os.path.join(tmp, 'config.xml')
    categories.DNSBL = os.path.join(tmp, 'dnsbl.json')
    categories.CORE_LOCK = os.path.join(tmp, 'core.lock')
    server = Server()
    server.put('gambling.tar.gz', tar([('gambling/domains', b'casino.example\n')]), 'Wed, 18 Nov 2026 21:50:17 GMT')
    categories.URLOPEN = server
    categories.say = lambda message: None
    asked = []
    categories.configctl = lambda *args: asked.append(args) or types.SimpleNamespace(returncode=0, stdout='', stderr='')
    categories.core_busy = lambda: False

    def main(*argv):
        with redirect_stdout(io.StringIO()):
            categories.main(list(argv))

    def files():
        return {n: (os.stat(os.path.join(state, n)).st_mtime_ns, os.path.getsize(os.path.join(state, n)))
                for n in sorted(os.listdir(state))} if os.path.isdir(state) else None

    write(categories.CONFIG, CONFIG.format(enabled='1', categories='', exceptions=''))
    main()
    main('--apply')
    main('--installed')
    check(not os.path.exists(state) and server.requests == [] and asked == [],
          'quiet: none ever chosen - no folder, no file, no one contacted, nothing rebuilt')
    write(categories.CONFIG, CONFIG.format(enabled='0', categories='gambling', exceptions=''))
    main()
    check(not os.path.exists(state) and server.requests == [], 'quiet: chosen but Block Lists off - nothing made either')
    write(categories.CONFIG, CONFIG.format(enabled='1', categories='gambling', exceptions=''))
    main('--apply')
    check(os.path.exists(os.path.join(state, 'gambling.domains')) and server.asked('gambling.tar.gz'),
          'quiet: a category chosen - its folder made, the category fetched')
    write(categories.CONFIG, CONFIG.format(enabled='1', categories='', exceptions=''))
    main('--apply')
    check(not os.path.exists(os.path.join(state, 'gambling.domains')), 'quiet: unchosen - taken out')
    before, server.requests[:] = files(), []
    main()
    main()
    main('--apply')
    check(files() == before and server.requests == [],
          'quiet: once taken out, runs write nothing - no file made or changed - and contact no one: %r -> %r'
          % (before, files()))


class Trickle:
    """A server that sends a byte every 50 ms, without end: read1 gives what has come, read(n) would
    wait for n bytes."""
    status = 200

    def __init__(self):
        self.headers = email.message.Message()

    def read1(self, n):
        time.sleep(0.05)
        return b'x'

    def read(self, n=-1):
        raise AssertionError('read(n) waits for n bytes: read1 is to be used')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def deadline_tests():
    """A download ended at DEADLINE whatever the server does, and redirects followed only to HTTPS on the
    same host (2026-11-19 review)."""
    saved_open, saved_deadline = categories.URLOPEN, categories.DEADLINE
    categories.DEADLINE = 1
    categories.URLOPEN = lambda request, timeout=None: Trickle()
    started = time.monotonic()
    try:
        categories.download(categories.DOWNLOAD + 'x.tar.gz', io.BytesIO(), categories.LIMIT)
        result = 'no failure'
    except categories.Failed as e:
        result = categories.english(e.text)
    took = time.monotonic() - started
    check(result == 'not done within 1 s' and took < 3,
          'download: a server trickling a byte at a time - ended at DEADLINE (%.1f s): %r' % (took, result))
    if hasattr(signal, 'SIGALRM'):
        def stalled(request, timeout=None):
            time.sleep(5)       # headers that never end: no read to check the time between
            return Trickle()
        categories.URLOPEN = stalled
        started = time.monotonic()
        try:
            categories.download(categories.DOWNLOAD + 'x.tar.gz', io.BytesIO(), categories.LIMIT)
            result = 'no failure'
        except categories.Failed as e:
            result = categories.english(e.text)
        took = time.monotonic() - started
        check(result == 'not done within 1 s' and took < 2.5,
              'download: an answer that never comes - ended by the alarm at DEADLINE (%.1f s): %r' % (took, result))
        check(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
              'download: the alarm put away after')
    categories.URLOPEN, categories.DEADLINE = saved_open, saved_deadline
    check(URLOPEN == categories.OPENER.open
          and any(isinstance(h, categories.SameHost) for h in categories.OPENER.handlers)
          and not any(type(h) is urllib.request.HTTPRedirectHandler for h in categories.OPENER.handlers),
          'download: through the opener whose redirects are SameHost\'s, and no other redirect handler')
    request = urllib.request.Request(categories.DOWNLOAD + 'gambling.tar.gz')
    same = categories.SameHost()
    for target, ok in (('https://dsi.ut-capitole.fr/blacklists/download/mirror/gambling.tar.gz', True),
                       ('http://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz', False),
                       ('https://evil.example/gambling.tar.gz', False),
                       ('https://dsi.ut-capitole.fr:8443/gambling.tar.gz', False),
                       ('ftp://ftp.ut-capitole.fr/pub/gambling.tar.gz', False)):
        try:
            followed = same.redirect_request(request, io.BytesIO(), 302, 'Found', email.message.Message(), target)
            got = followed is not None and followed.full_url == target
        except categories.Failed as e:
            got = False if 'refused' in categories.english(e.text) else 'other'
        check(got is ok, 'redirect to %s: %s' % (target, 'followed' if ok else 'refused'))


def catalogue_tests():
    shipped = json.load(open(os.path.join(SCRIPTS, 'categories.json'), encoding='utf-8'))
    cats = shipped['categories']
    check(shipped['bytes_per_name'] == 527 and shipped['licence'] == 'https://creativecommons.org/licenses/by-sa/4.0/'
          and shipped['download'] == categories.DOWNLOAD and re.match(r'^\d{4}-\d{2}-\d{2}$', shipped['counted']),
          'categories.json: 527 bytes a name, the licence, the download folder, the day counted')
    check(len(cats) >= 60 and all(categories.ID.match(c) for c in cats), 'categories.json: %d categories, each an id' % len(cats))
    check(all(isinstance(e.get('name'), str) and e['name'] and isinstance(e.get('description'), str)
              and e.get('use') in ('block', 'allow') and isinstance(e.get('names'), int) for e in cats.values()),
          'categories.json: each a name, a description (or none), its use and a count')
    check(all(len(e['description']) <= 80 and (not e['description'] or e['description'].endswith('.'))
              and '. ' not in e['description'] and e['description'].rstrip('.') != e['name'] for e in cats.values()),
          'categories.json: each description one short sentence, none that only repeats its label: %r'
          % ([c for c, e in cats.items() if len(e['description']) > 80 or '. ' in e['description']],))
    catalogued = set(json.load(open(SOURCE, encoding='utf-8')))
    texts_of = {t for e in cats.values() for t in (e['name'], e['description'], e.get('refused')) if t}
    check(texts_of <= catalogued, 'categories.json: every name, description and reason catalogued: %r'
          % (sorted(texts_of - catalogued)[:5],))
    literal = re.compile(r"""\bT\(\s*('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")""")
    import ast
    for script in ('categories.py', 'lookup.py'):
        found = {ast.literal_eval(m) for m in literal.findall(open(os.path.join(SCRIPTS, script), encoding='utf-8').read())}
        check(found and found <= catalogued, '%s: every T() msgid (%d) catalogued: %r' % (script, len(found), sorted(found - catalogued)))
    check([c for c, e in cats.items() if e.get('refused')] == ['adult'] and cats['adult'].get('approximate') is True
          and cats['adult']['names'] == 4600371 and [c for c, e in cats.items() if e.get('approximate')] == ['adult'],
          'categories.json: adult alone refused, its count the one not counted here (approximate)')
    check(cats['malware'].get('archive') == 'phishing' and [c for c, e in cats.items() if e.get('archive')] == ['malware']
          and cats['malware']['names'] == cats['phishing']['names'],
          'categories.json: malware is phishing\'s archive at UT1, the same names')
    check(categories.REFUSED.keys() == {'adult'}, 'categories.py: adult refused in the code too')
    handler = open(HANDLER, encoding='utf-8').read()
    check("POLICY = '%s'" % categories.POLICY in handler and "REFUSED = {'adult'}" in handler,
          'the handler: the policy id categories.py and the Lookup tab know, and adult refused')
    check("const REFUSED = ['adult'];" in open(os.path.join(SRC, 'opnsense', 'mvc', 'app', 'models', 'OPNsense', 'BlockLists',
                                                         'FieldTypes', 'CategoryField.php'), encoding='utf-8').read(),
          'the model: adult never offered')
    check(categories.parse_catalogue('<!DOCTYPE html><html><body>Site en maintenance</body></html>') == {},
          'parse_catalogue: a maintenance page holds no category')


def config_tests():
    root = os.path.join(SRC, 'opnsense')
    model = ET.parse(os.path.join(root, 'mvc', 'app', 'models', 'OPNsense', 'BlockLists', 'BlockLists.xml')).getroot()
    general = model.find('items/general')
    check(general.find('categories').get('type') == 'OPNsense\\BlockLists\\FieldTypes\\CategoryField'
          and general.find('categories/Multiple').text == 'Y' and general.find('categories/Default') is None,
          'model: categories, the plugin\'s CategoryField, several, empty by default (nothing to migrate)')
    check(general.find('exceptions').get('type') == 'CSVListField' and general.find('exceptions/MaskPerItem').text == 'Y'
          and general.find('exceptions/Default') is None, 'model: exceptions, a list of names, each masked, empty by default')
    check(model.find('version').text == '1.0.0', 'model: its version as it was - no migration needed')
    form = ET.parse(os.path.join(root, 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'forms', 'categories.xml')).getroot()
    ids = [f.findtext('id') for f in form.findall('field')]
    check(ids == ['blocklists.general.categories', 'blocklists.general.exceptions'], 'form: the two fields, %r' % ids)
    help_text = ' '.join(f.findtext('help') for f in form.findall('field'))
    check('policy only' in help_text and 'Adult cannot be chosen' in help_text and '527 bytes a name' in help_text,
          'form: the exceptions apply to this policy only; adult cannot be chosen; the estimate said')
    cron = open(os.path.join(SRC, 'etc', 'cron.d', 'blocklists'), encoding='utf-8').read()
    check('*/5 * * * * root /usr/local/opnsense/scripts/blocklists/categories.py > /dev/null 2>&1' in cron,
          'cron: categories.py every five minutes')
    actions = open(os.path.join(root, 'service', 'conf', 'actions.d', 'actions_blocklists.conf'), encoding='utf-8').read()
    check(re.search(r'\[categories\]\ncommand:/usr/local/opnsense/scripts/blocklists/categories.py\nparameters:--apply\n', actions)
          and re.search(r'\[lookup\]\ncommand:/usr/local/opnsense/scripts/blocklists/lookup.py\nparameters:%s\n', actions),
          'configd: categories --apply, and lookup with its one parameter')
    service = open(os.path.join(root, 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'Api', 'ServiceController.php'),
                   encoding='utf-8').read()
    check("$backend->configdRun('blocklists categories', true);" in service, 'the page\'s Apply: categories.py, detached')
    index = open(os.path.join(root, 'mvc', 'app', 'controllers', 'OPNsense', 'BlockLists', 'IndexController.php'),
                 encoding='utf-8').read()
    check("$this->view->categoriesForm = $this->getForm('categories');" in index, 'the page: the categories form')
    volt = open(os.path.join(root, 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'index.volt'), encoding='utf-8').read()
    check('href="#categories"' in volt and 'href="#lookup"' in volt and "'frm_categories': '/api/blocklists/settings/get'" in volt
          and "saveFormToEndpoint('/api/blocklists/settings/set', 'frm_categories'" in volt,
          'the page: the Web categories and Lookup tabs, the form read and saved')
    check(volt.find("saveFormToEndpoint('/api/blocklists/settings/set', 'frm_general'") <
          volt.find("saveFormToEndpoint('/api/blocklists/settings/set', 'frm_categories'"),
          'the page: the Settings tab\'s Apply first, as test-status.py reads it')
    check("$('#bl-cat-unbound').toggle(!web.unbound);" in volt, 'the page: Unbound DNS off said on the Web categories tab')
    credit = open(os.path.join(root, 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'credit.volt'), encoding='utf-8').read()
    check('https://dsi.ut-capitole.fr/blacklists/index_en.php' in credit and 'https://creativecommons.org/licenses/by-sa/4.0/' in credit
          and 'UT1' in credit, 'credit: UT1 credited, its licence linked')
    install = open(os.path.join(ROOT, 'install', 'install.sh'), encoding='utf-8').read()
    post = open(os.path.join(ROOT, 'pkg', 'post-install.sh'), encoding='utf-8').read()
    check('chmod 644 /usr/local/opnsense/scripts/unbound/blocklists/blocklists_ut1.py' in install
          and 'categories.py --installed' in install and 'categories.py --installed' in post,
          'installers: the handler in place, Unbound rebuilt where categories are applied')
    for name in ('install/uninstall.sh', 'pkg/post-deinstall.sh'):
        text = open(os.path.join(ROOT, name), encoding='utf-8').read()
        check(categories.POLICY in text and 'configctl unbound dnsbl' in text
              and '/usr/local/opnsense/scripts/unbound/blocklists/__pycache__/blocklists_ut1.' in text,
              '%s: the handler\'s compiled copy removed, Unbound rebuilt while it holds the policy' % name)
    check('/usr/local/opnsense/scripts/unbound/blocklists/blocklists_ut1.py' in open(os.path.join(ROOT, 'install', 'uninstall.sh')).read(),
          'install/uninstall.sh: the handler removed by its own path')
    with open(HANDLER, encoding='utf-8') as fh:
        check(not fh.readline().startswith('#!'), 'the handler: a module, not a script (no #!), so the package gives it 0644')


def main():
    tmp = tempfile.mkdtemp(prefix='blocklists-categories-')
    try:
        os.makedirs(os.path.join(tmp, 'handler'))
        handler_tests(os.path.join(tmp, 'handler'))
        os.makedirs(os.path.join(tmp, 'unpack'))
        unpack_tests(os.path.join(tmp, 'unpack'))
        os.makedirs(os.path.join(tmp, 'run'))
        run_tests(os.path.join(tmp, 'run'))
        os.makedirs(os.path.join(tmp, 'quiet'))
        quiet_tests(os.path.join(tmp, 'quiet'))
        deadline_tests()
        catalogue_tests()
        config_tests()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
