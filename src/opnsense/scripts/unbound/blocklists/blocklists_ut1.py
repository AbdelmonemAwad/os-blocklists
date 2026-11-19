# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""os-blocklists: UT1's web categories in OPNsense's Unbound blocklist (2026-11-19).

A handler of OPNsense's own blocklists.py (configctl unbound dnsbl), which imports every module of this
folder and merges what each handler gives into /var/unbound/data/dnsbl.json - as Deciso's
os-q-feeds-connector does with its qfeeds_bl.py. It changes none of the owner's Unbound settings and none
of his policies: it adds one policy of its own, for every client, beside his.

It reads only files the plugin wrote: ACTIVE, written by /usr/local/opnsense/scripts/blocklists/categories.py
- the categories applied, the file each reads, and the exceptions - and, for each, DATA/<archive>.domains,
one name a line. Each name is given with every subdomain (wildcard), as a UT1 name means; a name in two
chosen categories is given once, by the first of them. The exceptions are the policy's passlist,
(.*\\.)?<name>$ each: OPNsense's module matches it from the start of the name asked for (re.match), so
the $ and the escape keep example.com from passing example.com.evil.net; and a name an exception covers
is not given at all, so this policy holds no entry of its own for it. They apply to this policy only, as
OPNsense's own allowlists do.

Every name given is checked as OPNsense's own handler checks one (domain_pattern), and a bare IPv4
address is never given as a name. Never stops the update: a file that is missing, a link, too large or
unreadable is left out, the others given; what cannot be read is said in Unbound's log; and adult is
refused whatever ACTIVE says (decision d2).
"""
import ipaddress
import json
import os
import re
import stat
import syslog

from . import BaseBlocklistHandler

ACTIVE = '/var/db/os-blocklists/categories/unbound.json'
DATA = '/var/db/os-blocklists/categories'
# this plugin's policy, the same at every update: Unbound's reporting and the plugin's Lookup tab name it
POLICY = 'f188da6c-137b-41dd-b504-fe5d96a73483'
DESCRIPTION = 'Block Lists: web categories (UT1)'
# the answer OPNsense's own policies give by default (its template: address 0.0.0.0, NXDOMAIN off)
ADDRESS = '0.0.0.0'
RCODE = 'NOERROR'
PRIORITY = 50                   # after OPNsense's own handler (10), as Q-Feeds' is
REFUSED = {'adult'}             # never, whatever ACTIVE says
LIMIT = 256 << 20               # bytes a category's file may have
ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}\Z')
EXCEPTION = re.compile(r'^(?=.{1,253}\Z)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\Z')
# OPNsense 26.7.9's BaseBlocklistHandler.domain_pattern, used where the base class has none
DOMAIN = re.compile(
    r'^(\*\.){,1}(([\da-zA-Z_])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})'
    r'?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))$'
)


def log(priority, message):
    try:
        syslog.syslog(priority, 'blocklist: os-blocklists categories: %s' % message)
    except Exception:
        pass


def read_active(path):
    """({category: archive}, [exception]) from ACTIVE, each checked; nothing where it is missing,
    a link or not what categories.py writes."""
    try:
        if os.path.islink(path):
            raise ValueError('a link, not a file')
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as e:
        log(syslog.LOG_ERR, '%s not read: %s' % (path, e))
        return {}, []
    if not isinstance(data, dict):
        return {}, []
    categories = {}
    given = data.get('categories')
    for cid, archive in (given.items() if isinstance(given, dict) else []):
        if not (isinstance(cid, str) and isinstance(archive, str) and ID.match(cid) and ID.match(archive)):
            log(syslog.LOG_ERR, 'a category left out: not a name (%r)' % (cid,))
            continue
        if cid in REFUSED or archive in REFUSED:
            log(syslog.LOG_ERR, '%s left out: it cannot be chosen' % cid)
            continue
        categories[cid] = archive
    exceptions = []
    given = data.get('exceptions')
    for name in (given if isinstance(given, list) else []):
        name = name.strip().lower().rstrip('.') if isinstance(name, str) else ''
        if EXCEPTION.match(name) and name not in exceptions:
            exceptions.append(name)
    return categories, exceptions


def passlist(exceptions):
    """The policy's passlist: (.*\\.)?<name>$ for each exception - the name and every subdomain, and
    nothing that only begins with it - or '' where there is none."""
    text = '|'.join('(.*\\.)?%s$' % re.escape(name) for name in exceptions)
    try:
        re.compile(text, re.IGNORECASE)
    except re.error as e:
        log(syslog.LOG_ERR, 'exceptions left out: %s' % e)
        return ''
    return text


def address(name):
    """Whether a line is a bare IPv4 address, which a UT1 domains file may hold and DNS cannot use."""
    try:
        ipaddress.IPv4Address(name)
        return True
    except ValueError:
        return False


def covered(name, exceptions):
    """Whether an exception covers a name: the name itself, or a parent of it."""
    labels = name.split('.')
    return any('.'.join(labels[i:]) in exceptions for i in range(len(labels)))


class UT1BlocklistHandler(BaseBlocklistHandler):
    def __init__(self):
        self.categories, self.exceptions = {}, []
        try:
            super().__init__(ACTIVE)
        except Exception as e:      # an interface of OPNsense's that changed: this handler gives nothing
            log(syslog.LOG_ERR, 'not started: %s' % e)
            self.categories, self.exceptions = {}, []
        self.priority = PRIORITY

    def _load_config(self):
        """ACTIVE, a JSON file of the plugin's, read instead of the INI file the base class reads."""
        try:
            self.categories, self.exceptions = read_active(self.config)
        except Exception as e:
            log(syslog.LOG_ERR, '%s not read: %s' % (self.config, e))
            self.categories, self.exceptions = {}, []

    def get_policies(self):
        if not self.categories:
            return []
        try:
            return [{
                'id': POLICY,
                'source_nets': [],
                'address': ADDRESS,
                'rcode': RCODE,
                'description': DESCRIPTION,
                'passlist': passlist(self.exceptions),
            }]
        except Exception as e:
            log(syslog.LOG_ERR, 'no policy: %s' % e)
            return []

    def blocklists_iter(self):
        """(name, policy, {'bl': 'ut1_<category>', 'wildcard': True}) for each name of each category
        applied, each name once; a file that cannot be read is left out, the others given."""
        if not self.categories:
            return
        pattern = getattr(self, 'domain_pattern', None) or DOMAIN
        excepted = set(self.exceptions)
        archives = {}
        for cid in sorted(self.categories):
            archives.setdefault(self.categories[cid], []).append(cid)
        seen = set()
        for archive, cids in sorted(archives.items(), key=lambda item: item[1][0]):
            meta, given = {'bl': 'ut1_' + cids[0], 'wildcard': True}, 0
            path = os.path.join(DATA, archive + '.domains')
            try:
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('not a plain file')
                if info.st_size > LIMIT:
                    raise ValueError('larger than %d MB' % (LIMIT >> 20))
                with open(path, encoding='utf-8', errors='replace') as handle:
                    for line in handle:
                        name = line.strip().lower()
                        if name.startswith('*.'):
                            name = name[2:]
                        if not name or len(name) > 253 or not pattern.match(name) or name in seen or address(name):
                            continue
                        if excepted and covered(name, excepted):
                            continue
                        seen.add(name)
                        given += 1
                        yield name, POLICY, dict(meta)
            except Exception as e:
                log(syslog.LOG_ERR, '%s (%s) left out after %d names: %s' % (archive, ', '.join(cids), given, e))
                continue
            log(syslog.LOG_NOTICE, '%s: %d names' % (', '.join(cids), given))
