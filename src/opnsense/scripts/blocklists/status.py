#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""
What the page shows, as one JSON object: each list this plugin owns with its entries and what its
rules blocked, the countries, the DNS block lists OPNsense's Unbound has, the cutting of open
connections and of JA4 fingerprints, and what os-xgs-npu does beside it where it is installed.

    status.py

Read only.
"""

import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cut                                                               # noqa: E402
import ja4_cut                                                           # noqa: E402

CONFIG = '/conf/config.xml'
PFCTL = '/sbin/pfctl'
PREFIX = 'blocklists_'
FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'feeds.json')
CUT_STATUS = '/var/db/os-blocklists/cut/status.json'
JA4_STATUS = '/var/db/os-blocklists/ja4/status.json'
PROJECT_CUT = '/usr/local/opnsense/scripts/xgs/lists_cut.py'
PROJECT_JA4 = '/usr/local/opnsense/scripts/xgs/ja4_cut.py'


def load(path, default):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def tables():
    """Every pf table's entries and counters, from `pfctl -vvs Tables`."""
    try:
        text = subprocess.run([PFCTL, '-vvs', 'Tables'], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    out, name = {}, None
    for line in text.splitlines():
        head = re.match(r'^[-a-zA-Z]{7}\s+(\S+)', line)
        if head:
            name = head.group(1)
            out[name] = {}
            continue
        if name is None:
            continue
        found = re.match(r'^\s+Addresses:\s+(\d+)', line)
        if found:
            out[name]['entries'] = int(found.group(1))
        found = re.match(r'^\s+(In|Out)/Block:\s+\[ Packets: (\d+)\s+Bytes: (\d+)', line)
        if found:
            out[name][found.group(1).lower() + '_blocked'] = int(found.group(2))
    return out


def main():
    try:
        root = ET.parse(CONFIG).getroot()
    except (OSError, ET.ParseError):
        print(json.dumps({'error': 'config.xml could not be read'}))
        return
    general = root.find('OPNsense/BlockLists/general')
    enabled = general is None or (general.findtext('enabled') or '1') == '1'
    feeds = load(FEEDS, {})
    pf = tables()
    # the aliases this plugin makes, as cut.py, apply.php and the rules hook count them: one of the
    # owner's by another blocklists_ name is not shown as one of its lists
    mine = cut.owned(FEEDS)
    lists = []
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        name = alias.findtext('name') or ''
        if name not in mine:
            continue
        feed = feeds.get(name[len(PREFIX):], {})
        counters = pf.get(name, {})
        lists.append({
            'name': name, 'id': name[len(PREFIX):],
            'description': alias.findtext('description') or '',
            'type': alias.findtext('type') or '', 'proto': alias.findtext('proto') or '',
            'enabled': (alias.findtext('enabled') or '1') == '1',
            'source': feed.get('url') or (alias.findtext('content') or '').replace('\n', ', '),
            'what': feed.get('what', ''), 'terms': feed.get('terms', ''),
            'loaded': name in pf, 'entries': counters.get('entries'),
            'in_blocked': counters.get('in_blocked'), 'out_blocked': counters.get('out_blocked'),
        })

    unbound = root.find('OPNsense/unboundplus')
    dns = {'enabled': unbound is not None and (unbound.findtext('general/enabled') or '0') == '1', 'lists': []}
    if unbound is not None:
        for item in unbound.findall('dnsbl/blocklist'):
            dns['lists'].append({
                'enabled': (item.findtext('enabled') or '0') == '1',
                'types': [t for t in (item.findtext('type') or '').split(',') if t],
                'urls': len([u for u in (item.findtext('lists') or '').split(',') if u]),
                'description': item.findtext('description') or '',
            })

    listed, problem, bad, _ = ja4_cut.settings()
    project_ja4 = [f for f in re.split(r'[\s,]+', root.findtext('OPNsense/XGS/general/cut_ja4') or '') if f]
    project_lists = [u for u in (root.findtext('OPNsense/XGS/general/cut_lists') or '').split(',') if u.strip()]

    print(json.dumps({
        'enabled': enabled,
        'direction': (general.findtext('direction') if general is not None else None) or 'both',
        'lists': lists,
        'feeds': feeds,
        'countries': [c for c in ((general.findtext('countries') if general is not None else '') or '').split(',') if c],
        'geoip_source': bool(root.findtext('OPNsense/Firewall/Alias/geoip/url')),
        'dns': dns,
        'cut': {'on': general is not None and (general.findtext('cut') or '0') == '1',
                'last': load(CUT_STATUS, {})},
        'ja4': {'listed': listed, 'not_read': bad, 'problem': problem, 'last': load(JA4_STATUS, {})},
        'project': {'installed': os.path.exists(PROJECT_CUT) or os.path.exists(PROJECT_JA4),
                    'lists_watched': len(project_lists), 'ja4_listed': len(project_ja4)},
    }))


if __name__ == '__main__':
    main()
