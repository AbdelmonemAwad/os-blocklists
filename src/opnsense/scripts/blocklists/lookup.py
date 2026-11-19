#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""Where a name or an address is held: the page's Lookup tab (2026-11-19).

    lookup.py <name or address>     print one JSON object (configctl blocklists lookup <query>)

AN ADDRESS: each of this plugin's pf tables that holds it, by `pfctl -t <table> -T test <address>` - the
tables of its own aliases (cut.owned()) that pf has. The web categories and Unbound's blocklist hold
names: an address is not looked up there.

A NAME: the UT1 categories applied (categories.py's files) that hold it or a parent of it - a UT1 name
means every subdomain - and the exception that lets it through this plugin's policy, where one does; and
Unbound's own blocklist data, /var/unbound/data/dnsbl.json, read and never written: each entry for the
name, and for a parent of it where the entry is a wildcard one, as Unbound's module matches them, with
the policy it is in - this plugin's or one of the owner's - its description, and whether that policy's
allowlist lets the name through. The file may hold millions of names; it is searched where it lies
(mmap), never loaded whole. pf's tables hold addresses: a name is not resolved, and not looked up there.

Read only: nothing is changed, written or fetched. The argument is checked before anything is run - a
host name, or an IPv4 or IPv6 address, and nothing else - and no shell is used. Never fails its caller.
"""
import ipaddress
import json
import mmap
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import categories                                                        # noqa: E402
import cut                                                               # noqa: E402

PFCTL = '/sbin/pfctl'
DNSBL = '/var/unbound/data/dnsbl.json'
FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'feeds.json')
# a host name: labels of letters, digits, - and _, none beginning or ending with -, 253 at the most
HOST = re.compile(r'^(?=.{1,253}\Z)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\Z')
ADDRESS = re.compile(r'^[0-9A-Fa-f:.]{2,45}\Z')
MATCH = re.compile(r'^\s*(\d+)/(\d+) addresses? match')


def parse(text):
    """(kind, query) - ('address', its canonical form) or ('name', lowercased, a final dot dropped) - or
    (None, None) for anything else: a space, a shell's character, a zone, a port, nothing at all."""
    if not isinstance(text, str) or not text or len(text) > 254:
        return None, None
    if ADDRESS.match(text):
        try:
            return 'address', str(ipaddress.ip_address(text))
        except ValueError:
            pass
    name = text.lower()
    if name.endswith('.'):
        name = name[:-1]
    if HOST.match(name):
        return 'name', name
    return None, None


def suffixes(name):
    """The name and each parent of it: www.example.com, example.com, com."""
    labels = name.split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels))]


def pfctl(args):
    try:
        return subprocess.run([PFCTL] + args, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None


def tables(address):
    """This plugin's pf tables that hold the address: {'checked', 'held': [{alias, list}], 'errors'}."""
    out = {'checked': 0, 'held': [], 'errors': []}
    shown = pfctl(['-s', 'Tables'])
    if shown is None or shown.returncode != 0:
        out['errors'].append("pf's tables could not be read")
        return out
    present = {line.strip() for line in shown.stdout.splitlines() if line.strip()}
    feeds = categories.load(FEEDS, {})
    feeds = feeds if isinstance(feeds, dict) else {}
    for table in sorted(cut.owned(FEEDS) & present):
        out['checked'] += 1
        r = pfctl(['-t', table, '-T', 'test', address])
        if r is None:
            out['errors'].append('%s: pfctl could not be run' % table)
            continue
        found = MATCH.match((r.stdout or '') + (r.stderr or ''))
        held = r.returncode == 0 if not found else int(found.group(1)) > 0
        if r.returncode not in (0, 2) and not found:
            out['errors'].append('%s: %s' % (table, ((r.stderr or r.stdout or '').strip() or 'pfctl failed')[:120]))
            continue
        if held:
            feed = feeds.get(table[len(cut.PREFIX):]) if isinstance(feeds.get(table[len(cut.PREFIX):]), dict) else {}
            out['held'].append({'alias': table, 'list': str(feed.get('name') or ('countries' if table == cut.PREFIX + 'countries' else ''))})
    return out


def web_categories(name):
    """The categories applied that hold the name or a parent of it:
    {'applied', 'held': [{id, name, entry, exception}]} - exception: the one that lets it through."""
    active = categories.load(categories.ACTIVE, {})
    applied = active.get('categories') if isinstance(active, dict) and isinstance(active.get('categories'), dict) else {}
    excepted = active.get('exceptions') if isinstance(active, dict) and isinstance(active.get('exceptions'), list) else []
    entries = categories.catalogue()
    wanted = set(suffixes(name))
    passing = next((s for s in suffixes(name) if s in excepted), '')
    out = {'applied': len(applied), 'held': [], 'errors': []}
    by_archive = {}
    for cid, archive in sorted(applied.items()):
        if isinstance(cid, str) and isinstance(archive, str) and categories.ID.match(cid) and categories.ID.match(archive):
            by_archive.setdefault(archive, []).append(cid)
    for archive, cids in sorted(by_archive.items()):
        found = []
        try:
            with open(categories.data_path(archive), encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    entry = line.strip()
                    if entry in wanted:
                        found.append(entry)
        except OSError as e:
            out['errors'].append('%s: %s' % (archive, e.strerror or e))
            continue
        for entry in sorted(found, key=len, reverse=True):
            for cid in cids:
                out['held'].append({'id': cid, 'name': (entries.get(cid) or {}).get('name', cid), 'entry': entry,
                                    'exception': passing})
    return out


def unbound(name, path=None):
    """Unbound's blocklist entries for the name, and for each parent with a wildcard entry, as its module
    matches them: {'read', 'held': [{entry, wildcard, policy, mine, description, bl, source_nets,
    passes}]}. dnsbl.json is OPNsense's {"data": {name: [items]}, "config": {policy: {...}}}; it is
    searched in place, and only the entries asked for and the policies are parsed."""
    path = path or DNSBL
    out = {'read': False, 'held': [], 'errors': []}
    try:
        size = os.path.getsize(path)
    except OSError:
        out['errors'].append('no blocklist data: %s is not there' % path)
        return out
    out['read'] = True
    if size == 0:
        return out          # OPNsense writes it empty when no policy holds a name
    keys = b'|'.join(re.escape(s.encode()) for s in suffixes(name))
    wanted = re.compile(rb'"(' + keys + rb')"\s*:\s*\[')
    found, config = [], {}
    try:
        with open(path, 'rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            start = None
            for start in re.finditer(rb'"config"\s*:\s*\{', data):
                pass
            if start is not None:
                try:
                    config, _ = json.JSONDecoder().raw_decode(data[start.end() - 1:].decode('utf-8', 'replace'))
                except ValueError:
                    config = {}
            limit = start.start() if start is not None else len(data)
            for match in wanted.finditer(data, 0, limit):
                end = data.find(b']', match.end())
                try:
                    items = json.loads(data[match.end() - 1:end + 1].decode('utf-8', 'replace'))
                except ValueError:
                    continue
                found.append((match.group(1).decode(), items if isinstance(items, list) else []))
    except (OSError, ValueError) as e:
        out['read'] = False
        out['errors'].append('%s could not be read: %s' % (path, e))
        return out
    config = config if isinstance(config, dict) else {}
    for entry, items in sorted(found, key=lambda f: len(f[0]), reverse=True):
        for item in items:
            if not isinstance(item, dict):
                continue
            wildcard = item.get('wildcard') is True
            if entry != name and not wildcard:
                continue        # a parent's entry counts only where it is a wildcard one
            idx = str(item.get('idx') or '')
            policy = config.get(idx) if isinstance(config.get(idx), dict) else {}
            passes = False
            if isinstance(policy.get('passlist'), str) and policy['passlist']:
                try:
                    passes = re.compile(policy['passlist'], re.IGNORECASE).match(name) is not None
                except re.error:
                    passes = False
            nets = policy.get('source_nets') if isinstance(policy.get('source_nets'), list) else []
            out['held'].append({
                'entry': entry, 'wildcard': wildcard, 'policy': idx, 'mine': idx == categories.POLICY,
                'description': str(policy.get('description') or ''), 'bl': str(item.get('bl') or ''),
                'source_nets': [str(n) for n in nets], 'passes': passes,
            })
    return out


def lookup(text):
    kind, query = parse(text)
    if kind is None:
        return {'error': 'not a name or an address'}
    out = {'query': query, 'kind': kind}
    if kind == 'address':
        out['tables'] = tables(query)
        out['found'] = len(out['tables']['held'])
    else:
        out['categories'] = web_categories(query)
        out['unbound'] = unbound(query)
        out['found'] = len(out['categories']['held']) + len(out['unbound']['held'])
    return out


def main(argv):
    try:
        result = lookup(argv[0] if len(argv) == 1 else None)
    except Exception as e:      # never fail the caller: the page
        result = {'error': 'stopped: %s' % e}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
