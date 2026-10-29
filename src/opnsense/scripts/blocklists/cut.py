#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""Cut the connections already open to or from an address a block list has just gained.

A block list in OPNsense is an alias - a pf table, filled from a URL, a feed or by hand and
refreshed on its own schedule - and a rule that blocks it blocks new connections only. A connection
opened before its address was listed keeps its pf state, and on a Sophos XGS with offloading on its
flow in the coprocessor, for as long as it carries traffic. With "Cut open connections" on, this
watches the lists this plugin made (owned() below): for each, it compares the table with
what it held at the last run and kills, by id, every pf state with either end in what was added. A
coprocessor's flow goes with its state: os-xgs-npu's drivers take a connection out of hardware once
pf no longer holds it (its docs/measurements/lists-cut-2026-10-19.md).

    cut.py            run once, print a JSON summary (cron, every minute; and the page's Apply)
    cut.py --status   print the last run's record

It came from os-xgs-npu's scripts/xgs/lists_cut.py on 2026-10-22. That one still runs where
os-xgs-npu is installed, for the lists XGS: Settings names; a list named there is left to it here, so
no addition is cut twice. The first run for a list takes everything in it as new, so turning the
watch on cuts what the list already names. A state is killed by its id: `pfctl -k <host> -k <host>`
kills nothing on this firewall. Never fails its caller; what it could not do is in the summary and in
the system log, under blocklists.

What a list held is forgotten once the list is no longer watched - unchosen, switched off, left to
os-xgs-npu, or the cut or Block Lists turned off - so a list watched again starts from nothing and cuts
what it names, as its first run did. Until 2026-10-29 it was kept, and a connection opened while the
list was off was compared with it, found old, and never cut. It is written only when the table
changed - a list of 15,000 entries was rewritten every minute, a third of a megabyte each time - and
by one run at a time: the page's Apply and the minute's run wrote the same files.
"""
import bisect
import fcntl
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'
STATE_DIR = '/var/db/os-blocklists/cut'
STATUS = os.path.join(STATE_DIR, 'status.json')
LOCK = os.path.join(STATE_DIR, 'lock')
FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'feeds.json')
PFCTL = '/sbin/pfctl'
TAG = 'blocklists'
PREFIX = 'blocklists_'
WAIT = 10           # seconds a run waits for another to end, then leaves the cutting to the next minute


def log(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def owned(path=FEEDS):
    """The names of the aliases this plugin makes, and so owns: blocklists_<id> for each list of
    feeds.json, and blocklists_countries. Only these - an alias of the owner's by another blocklists_
    name is his. Until 2026-10-29 every blocklists_* alias was taken for the plugin's, so one he made -
    a list of exceptions, say - was blocked both ways before his own rules, its connections cut, and
    switched off or removed by the next Apply. apply.php and plugins.inc.d/blocklists.inc make the same
    set from the same file; status.py takes this one."""
    names = {PREFIX + 'countries'}
    try:
        with open(path, encoding='utf-8') as fh:
            names.update(PREFIX + key for key in json.load(fh))
    except (OSError, ValueError, TypeError):
        pass
    return names


def watched_lists(path=CONFIG):
    """This plugin's own lists, when the setting says to cut, less those os-xgs-npu's XGS: Settings
    watches itself; None when config.xml cannot be read - nothing is cut then, and nothing forgotten."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    general = 'OPNsense/BlockLists/general/'
    if (root.findtext(general + 'enabled') or '1') != '1' or (root.findtext(general + 'cut') or '0') != '1':
        return []
    project = set(u for u in (root.findtext('OPNsense/XGS/general/cut_lists') or '').split(',') if u.strip())
    mine = owned()
    out = []
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        name = alias.findtext('name') or ''
        if (name in mine and (alias.findtext('enabled') or '1') == '1'
                and alias.get('uuid') not in project):
            out.append(name)
    return out


def table_entries(name):
    """What pf's table holds now, as networks; None when there is no such table."""
    try:
        r = subprocess.run([PFCTL, '-t', name, '-T', 'show'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    out = set()
    for line in r.stdout.splitlines():
        item = line.strip()
        if not item or item.startswith('!'):     # a negated entry excludes, it does not list
            continue
        try:
            out.add(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return out


class Matcher:
    """Is an address inside any of a set of networks: each family's networks as sorted, merged
    integer ranges, so a state's addresses are looked up by bisection however long the list."""

    def __init__(self, networks):
        self.ranges = {4: [], 6: []}
        for n in networks:
            net = ipaddress.ip_network(n, strict=False)
            self.ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.starts = {}
        for v, rs in self.ranges.items():
            rs.sort()
            merged = []
            for a, b in rs:
                if merged and a <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], b))
                else:
                    merged.append((a, b))
            self.ranges[v] = merged
            self.starts[v] = [a for a, _ in merged]

    def __contains__(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        rs = self.ranges[ip.version]
        i = bisect.bisect_right(self.starts[ip.version], int(ip)) - 1
        return i >= 0 and rs[i][0] <= int(ip) <= rs[i][1]


ADDR_V6 = re.compile(r'^([0-9A-Fa-f:.]+)\[\d+\]$')


def state_addresses(line):
    """Every address on the first line of a state in `pfctl -ss -vv`: both ends, and the translated
    one in parentheses. IPv4 is written address:port, IPv6 address[port]."""
    out = []
    for tok in line.split()[2:]:
        tok = tok.strip('()')
        m = ADDR_V6.match(tok)
        if m:
            cand = m.group(1)
        elif tok.count(':') == 1 and '.' in tok:
            cand = tok.split(':', 1)[0]
        else:
            cand = tok
        try:
            out.append(str(ipaddress.ip_address(cand)))
        except ValueError:
            continue
    return out


def states(text):
    """[(id, [addresses])] from `pfctl -ss -vv`."""
    out, addrs = [], None
    for line in text.splitlines():
        if line and not line[0].isspace():
            addrs = state_addresses(line)
            continue
        m = re.match(r'\s+id: ([0-9a-f]+)', line)
        if m and addrs is not None:
            out.append((m.group(1), addrs))
            addrs = None
    return out


def load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save(path, data):
    """Through a temporary file of this run's own beside it, renamed over it: a reader never meets half
    a file, and two runs never write into the same temporary one."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def snapshot_path(name):
    return os.path.join(STATE_DIR, re.sub(r'[^A-Za-z0-9_.-]', '_', name) + '.json')


def forget(watched):
    """What is kept for a list no longer watched, deleted, so the list starts from nothing when it is
    watched again (see the top); and a temporary file a stopped run left behind - only the run holding
    the lock writes here."""
    keep = {os.path.basename(snapshot_path(name)) for name in watched}
    for entry in os.listdir(STATE_DIR):
        if entry.startswith('.') or (entry.startswith(PREFIX) and entry.endswith('.json') and entry not in keep):
            try:
                os.unlink(os.path.join(STATE_DIR, entry))
            except OSError:
                pass


def run():
    status = load(STATUS, {})
    lists = watched_lists()
    read = lists is not None
    lists = lists or []
    summary = {'lists': {}, 'cut': 0, 'run': int(time.time()), 'watched': lists}
    added, current, kept = {}, {}, {}
    for name in lists:
        now = table_entries(name)
        if now is None:
            summary['lists'][name] = {'error': 'no pf table by this name - is the alias loaded?'}
            continue
        before = load(snapshot_path(name), None)
        kept[name] = None if before is None else set(before)
        new = now if kept[name] is None else now - kept[name]
        added[name], current[name] = new, now
        summary['lists'][name] = {'entries': len(now), 'added': len(new), 'cut': 0}

    if any(added.values()):
        try:
            text = subprocess.run([PFCTL, '-ss', '-vv'], capture_output=True, text=True, timeout=120).stdout
        except (OSError, subprocess.SubprocessError):
            text = ''
        all_states = states(text)
        killed = set()
        for name, new in added.items():
            if not new:
                continue
            match = Matcher(new)
            for sid, addrs in all_states:
                if sid in killed or not any(a in match for a in addrs):
                    continue
                r = subprocess.run([PFCTL, '-k', 'id', '-k', sid], capture_output=True, timeout=30)
                if r.returncode == 0:
                    killed.add(sid)
                    summary['lists'][name]['cut'] += 1
        summary['cut'] = len(killed)

    for name in added:
        # what was compared, not a second reading: an entry added since is new at the next run; and
        # written only when it is not what was kept already
        if current[name] != kept[name]:
            save(snapshot_path(name), sorted(current[name]))
        info = summary['lists'][name]
        if info.get('added') or info.get('cut'):
            log(f"{name}: {info['added']} new entr{'y' if info['added'] == 1 else 'ies'} of {info['entries']}, "
                f"{info['cut']} open connection{'' if info['cut'] == 1 else 's'} cut")
    if read:
        forget(lists)

    totals = status.get('totals', {})
    for name, info in summary['lists'].items():
        totals[name] = totals.get(name, 0) + info.get('cut', 0)
    summary['totals'] = totals
    if not read:
        summary['message'] = 'cut when listed: config.xml could not be read'
    elif not lists:
        summary['message'] = 'cut when listed: no list watched'
    else:
        parts = []
        for name in lists:
            info = summary['lists'].get(name, {})
            parts.append(f"{name} ({info['error']})" if 'error' in info else
                         f"{name} ({info['entries']} entries, {info['cut']} cut now, {totals.get(name, 0)} in all)")
        summary['message'] = 'cut when listed: ' + ', '.join(parts)
    save(STATUS, summary)
    return summary


def take(lock, wait=WAIT):
    """The lock, or False after `wait` seconds. One run at a time (2026-10-29): the page's Apply runs
    this too, and could meet the minute's run over the same snapshots and temporary files. The minute's
    run lasts a second or two, and one begun before the Apply has not seen a list just chosen, so a run
    that meets another waits for it rather than giving up at once - then leaves it to the next minute."""
    until = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= until:
                return False
            time.sleep(0.5)


def main(argv):
    if '--status' in argv:
        print(json.dumps(load(STATUS, {}), sort_keys=True))
        return 0
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOCK, 'w') as lock:
            if not take(lock):
                last = load(STATUS, {})
                print(json.dumps({'message': last.get('message', 'cut when listed: another run is cutting'),
                                  'cut': 0}, sort_keys=True))
                return 0
            print(json.dumps(run(), sort_keys=True))
    except Exception as e:      # never fail the caller: cron or the settings page
        log(f'stopped: {e}')
        print(json.dumps({'message': f'cut when listed: stopped - {e}', 'cut': 0}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
