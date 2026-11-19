#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""What the Intrusion Detection's IPS policy drops, blocked and cut for a while (ff-10, 2026-11-19).

    ids_list.py                 one reading: what the log gained, taken in, the old taken out (the page's
                                Apply, configctl blocklists ids)
    ids_list.py --for 58        the same every EVERY seconds for 58 seconds (cron, every minute), so a
                                source is in the table within seconds of its drop
    ids_list.py --list          the addresses held now, for the page's grid
    ids_list.py --remove ADDR   one taken out now (the grid's button, configctl blocklists ids_remove)
    ids_list.py --status        the last run's record

WHAT ENTERS, with "Block what the IPS drops" on (general.ids, off by default): the source (src_ip) of
each alert Suricata logged as blocked - its IPS policy dropped what that side sent - for "Keep an address"
minutes after its last such alert (general.ids_minutes: 60 by default, 5 to 10080). Blocked alerts are
logged only in IPS mode (Netmap or Divert); in IDS mode, which listens, none is, and the page says so. Not
every blocked alert enters, for os-xgs-npu's reasons ("Cut what the IPS drops", its ja4_cut.py): only TCP -
a UDP or ICMP frame is easily forged with another's address, to have it blocked - and none of Suricata's
own decoder, stream and application-layer event rules (signature ids 2200000-2299999), which drop one
frame, not a connection. And never: an address of the firewall's own (every interface, IPv4 and IPv6,
read from ifconfig as it runs - none is entered where they cannot be read), loopback, multicast,
unspecified, link-local, this network, reserved and broadcast; and, with "Outside addresses only" on (the
default), a private one (RFC 1918's 10/8, 172.16/12 and 192.168/16; shared 100.64/10, where VPN overlays
live too; IPv6's unique local fc00::/7), so a false alarm never cuts a device of the owner's own
networks off.

THE TABLE is blocklists_ids, an external alias of the plugin's (apply.php makes it while the setting is
on, as ThreatFox's): OPNsense declares the table at every filter reload and leaves its addresses to this
script, which puts the list into it (pfctl -T replace -f -, the list on stdin) whenever it does not hold
it - after a reboot too, where /var kept the state. The rules hook blocks it as the plugin's other lists,
in the Direction the page says, and cut.py cuts the connections of an address it gains - run here at once
for the new ones, so os-xgs-npu's hardware drop applies where it is installed - and hands an address
back from hardware when it leaves. At most CAP addresses: past it, those whose last drop is the oldest
leave first.

THE LOG is read from where the last reading stopped (its inode and offset, kept in memory and in STATE),
from its start after a rotation, and a last line not yet ended is left for the next reading. Turned on,
it begins at the log's end: nothing logged before is taken. Turned off - or Block Lists off - every
address leaves at the next run and the table is emptied. STATE is in /var/db/os-blocklists: where /var is
in memory, a reboot starts it empty.

Its texts for the page are categories.T(), translated by the page's controller. Never fails its caller:
prints one JSON object and exits 0; what it could not do is in the answer, in STATE and in the system log,
under blocklists-ids.
"""
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import categories                                                        # noqa: E402
import cut                                                               # noqa: E402
import ja4_cut                                                           # noqa: E402
from categories import T, english                                       # noqa: E402

CONFIG = '/conf/config.xml'
EVE = '/var/log/suricata/eve.json'
STATE_DIR = '/var/db/os-blocklists/ids'
STATE = os.path.join(STATE_DIR, 'state.json')
LOCK = os.path.join(STATE_DIR, 'lock')
REMOVE = os.path.join(STATE_DIR, 'remove')      # one file a request to take an address out, by its bytes
PFCTL = '/sbin/pfctl'
IFCONFIG = '/sbin/ifconfig'
TAG = 'blocklists-ids'
ALIAS = 'blocklists_ids'
EVERY = 3                   # seconds between two readings of the log in --for
CAP = 10000                 # addresses the table may hold; the oldest leave first
MINUTES = (60, 5, 10080)    # "Keep an address": its default, its least and its most
CUT_WAIT = 5                # seconds a reading waits for cut.py's lock to cut what it entered
CHECK_TABLE = 60            # seconds between two looks at pf's table when the list has not changed
REMOVE_WAIT = 2 * EVERY + 2  # seconds --remove waits for the minute's watcher to take its request
# Suricata's capture modes that make it an IPS (OPNsense 26.7's IDS model, general.mode: pcap is IDS);
# general.ips is older OPNsense's, read as os-xgs-npu reads it
IPS_MODES = ('netmap', 'divert')
# Suricata's own event rules - decoder, stream and application-layer events - take signature ids
# 2200000-2299999 by its convention, and drop the frame, not the connection (os-xgs-npu's ja4_cut.py)
EVENT_SIDS = range(2200000, 2300000)


def network(text):
    return ipaddress.ip_network(text)


# never entered: no host has them, or every host does
NEVER = [network(n) for n in (
    '0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
    '::/128', '::1/128', 'fe80::/10', 'ff00::/8')]
# a network of the owner's own, left out with "Outside addresses only"
PRIVATE = [network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7')]
INET = re.compile(r'^\s+inet6?\s+([0-9A-Fa-f:.]+)(%\S+)?(\s|$)')


def log(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save(path, data):
    """Through a temporary file beside it, renamed over it: a reader never meets half a file."""
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


def stamp(t):
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t)) if t else '-'


def settings(path=None):
    """What config.xml says: {'read', 'on', 'minutes', 'outside', 'problem' (T or None), 'alias'
    ('ready', 'missing', 'off', 'not external')}."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return {'read': False, 'on': False, 'minutes': MINUTES[0], 'outside': True,
                'problem': T('config.xml could not be read'), 'alias': 'missing'}
    general = root.find('OPNsense/BlockLists/general')

    def value(tag, default):
        return ((general.findtext(tag) if general is not None else None) or default).strip()

    try:
        minutes = int(value('ids_minutes', str(MINUTES[0])))
    except ValueError:
        minutes = MINUTES[0]
    minutes = minutes if MINUTES[1] <= minutes <= MINUTES[2] else MINUTES[0]
    ids = root.find('OPNsense/IDS/general')
    problem = None
    if ids is None or (ids.findtext('enabled') or '0').strip() != '1':
        problem = T('the Intrusion Detection is off: nothing is dropped, so nothing is entered')
    elif (ids.findtext('mode') or '').strip() not in IPS_MODES and (ids.findtext('ips') or '0').strip() != '1':
        problem = T('the Intrusion Detection is in IDS mode, which drops nothing: nothing is entered')
    alias = next((a for a in root.findall('OPNsense/Firewall/Alias/aliases/alias') if a.findtext('name') == ALIAS), None)
    if alias is None:
        state = 'missing'
    elif (alias.findtext('enabled') or '1').strip() != '1':
        state = 'off'
    elif (alias.findtext('type') or '').strip() != 'external':
        state = 'not external'
    else:
        state = 'ready'
    return {'read': True, 'on': value('enabled', '1') == '1' and value('ids', '0') == '1',
            'minutes': minutes, 'outside': value('ids_outside', '1') != '0', 'problem': problem, 'alias': state}


def own_addresses():
    """The firewall's own addresses now, every interface's, IPv4 and IPv6, from ifconfig; None where
    they cannot be read - nothing is entered then."""
    try:
        r = subprocess.run([IFCONFIG, '-a'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return addresses_of(r.stdout)


def addresses_of(text):
    """The addresses of `ifconfig -a`'s inet and inet6 lines, each without its scope."""
    found = set()
    for line in text.splitlines():
        m = INET.match(line)
        if m:
            try:
                found.add(str(ipaddress.ip_address(m.group(1))))
            except ValueError:
                continue
    return found


def why_not(event, own, outside):
    """Why a blocked alert's source does not enter, a T(), or None where it does."""
    if event['proto'] != 'tcp':
        return T('not TCP')
    if event['sid'] in EVENT_SIDS:
        return T('an event rule of Suricata, which drops one frame')
    address = event['src']
    if own is None:
        return T('the firewall addresses could not be read')
    if str(address) in own:
        return T('an address of the firewall')
    if any(address in n for n in NEVER):
        return T('an address no host has, or every host has')
    if outside and any(address in n for n in PRIVATE):
        return T('a private address (Outside addresses only)')
    return None


def alerts(fh, at):
    """Every alert the IPS logged as blocked from fh's position, as an event (ja4_cut.eve_lines())."""
    for start, raw in ja4_cut.eve_lines(fh, at, (b'"event_type":"alert"', b'"blocked"')):
        try:
            ev = json.loads(raw)
            alert = ev.get('alert')
            if ev.get('event_type') != 'alert' or not isinstance(alert, dict) or alert.get('action') != 'blocked':
                continue
            address = ipaddress.ip_address(str(ev['src_ip']))
            if getattr(address, 'ipv4_mapped', None):
                address = address.ipv4_mapped
            yield {
                'src': address, 'proto': str(ev.get('proto', '')).lower(), 'at': ja4_cut.stamp(ev.get('timestamp')),
                'sid': int(alert.get('signature_id') or 0),
                'msg': categories.plain(alert.get('signature'), 200), 'offset': start,
            }
        except (ValueError, KeyError, TypeError, AttributeError):
            continue


def table_now():
    """What pf's table holds now, as addresses; None where pfctl does not show it."""
    try:
        r = subprocess.run([PFCTL, '-t', ALIAS, '-T', 'show'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    found = set()
    for line in r.stdout.splitlines():
        try:
            found.add(str(ipaddress.ip_network(line.strip(), strict=False).network_address))
        except ValueError:
            continue
    return found


def fill(addresses):
    """pf's table made to hold these addresses where it does not: (put, error T or None)."""
    if table_now() == set(addresses):
        return False, None
    try:
        r = subprocess.run([PFCTL, '-t', ALIAS, '-T', 'replace', '-f', '-'], input=''.join(a + '\n' for a in sorted(addresses)),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False, T('pfctl could not be run')
    if r.returncode != 0:
        return False, T('pfctl did not fill the table: %s', (r.stderr or r.stdout or '').strip()[:200])
    return True, None


def flush():
    """pf's table emptied, where it is there."""
    try:
        subprocess.run([PFCTL, '-t', ALIAS, '-T', 'flush'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass


def cut_now():
    """cut.py run at once for the addresses just entered - their open connections cut, on the coprocessor
    too where os-xgs-npu is installed - rather than at its next minute; its summary, or None where its
    lock stayed taken."""
    try:
        os.makedirs(cut.STATE_DIR, exist_ok=True)
        with open(cut.LOCK, 'a') as lock:
            if not cut.take(lock, CUT_WAIT):
                return None
            return cut.run()
    except Exception as e:      # the addresses are in the table all the same: the minute's cut.py cuts
        log('the new addresses not cut at once: %s' % e)
        return None


def requested():
    """The addresses asked to be taken out (--remove while the watcher ran), its files read and removed."""
    out = []
    try:
        names = os.listdir(REMOVE)
    except OSError:
        return out
    for name in names:
        try:
            out.append(str(ipaddress.ip_address(bytes.fromhex(name))))
        except ValueError:
            pass
        try:
            os.unlink(os.path.join(REMOVE, name))
        except OSError:
            pass
    return out


class Watch:
    """The readings of one run: the state in memory, saved when the addresses change and at the end."""

    def __init__(self):
        state = load(STATE, {})
        self.state = state if isinstance(state, dict) else {}
        if not isinstance(self.state.get('entries'), dict):
            self.state['entries'] = {}
        self.config_mtime, self.conf, self.own = None, settings(), None
        self.own_at, self.table_at = 0, None

    def reload(self, now):
        try:
            m = os.stat(CONFIG).st_mtime
        except OSError:
            m = None
        if m != self.config_mtime:
            self.config_mtime, self.conf = m, settings()
        if self.own is None or now - self.own_at > 60:
            self.own, self.own_at = own_addresses(), now

    def once(self, now=None):
        now = time.time() if now is None else now
        self.reload(now)
        conf, st, entries = self.conf, self.state, self.state['entries']
        summary = {'run': int(now), 'entered': [], 'again': 0, 'expired': 0, 'removed': 0, 'capped': 0,
                   'refused': {}}
        changed = False
        for address in requested():
            if entries.pop(address, None) is not None:
                summary['removed'] += 1
                changed = True
        if not conf['on']:
            # off: every address leaves, the table is emptied, and the log is taken from its end when it
            # is turned on again
            if entries or st.get('since'):
                entries.clear()
                st.update(since=None, inode=None, offset=None)
                flush()
                changed = True
            self.changed = changed
            return summary
        if not st.get('since'):
            # turned on now: the log from its end, nothing logged before taken
            st['since'] = now
            try:
                info = os.stat(EVE)
                st['inode'], st['offset'] = info.st_ino, info.st_size
            except OSError:
                st['inode'], st['offset'] = None, 0
            changed = True
        for address in [a for a, e in entries.items() if e.get('until', 0) <= now]:
            del entries[address]
            summary['expired'] += 1
            changed = True
        changed |= self.read(now, summary)
        if len(entries) > CAP:
            for address in sorted(entries, key=lambda a: (entries[a].get('last', 0), a))[:len(entries) - CAP]:
                del entries[address]
                summary['capped'] += 1
            summary['entered'] = [a for a in summary['entered'] if a in entries]
        table = {}
        # pf's table looked at when the list changed, at the run's first reading (a reboot empties it) and
        # once a minute - not every few seconds, which would list it each time
        if conf['alias'] == 'ready' and (changed or self.table_at is None or now - self.table_at >= CHECK_TABLE):
            self.table_at = now
            put, error = fill(entries)
            if error:
                table['error'] = error
                log('the table %s not filled: %s' % (ALIAS, english(error)))
            elif put and summary['entered']:
                summary['cut'] = cut_now()
        if table or self.table_at == now or conf['alias'] != 'ready':
            st['table'] = table
        self.changed = changed
        return summary

    def read(self, now, summary):
        """The log from where the last reading stopped: each blocked alert taken in or refused."""
        conf, st, entries = self.conf, self.state, self.state['entries']
        try:
            info = os.stat(EVE)
        except OSError:
            summary['error'] = T('no Suricata log at %s', EVE)
            return False
        same = st.get('inode') == info.st_ino and (st.get('offset') or 0) <= info.st_size
        start = (st.get('offset') or 0) if same else 0      # a new log: from its start
        if start >= info.st_size and same:
            return False
        changed = False
        at = {}
        keep = conf['minutes'] * 60
        with open(EVE, 'rb') as fh:
            fh.seek(start)
            for event in alerts(fh, at):
                if event['at'] is not None and event['at'] < st['since']:
                    continue        # logged before it was turned on
                why = why_not(event, self.own, conf['outside'])
                if why is not None:
                    key = why['text']
                    summary['refused'][key] = summary['refused'].get(key, 0) + 1
                    continue
                address = str(event['src'])
                entry = entries.get(address)
                if entry is None:
                    entries[address] = entry = {'at': event['at'] or now, 'count': 0}
                    summary['entered'].append(address)
                    log('%s entered for %d minutes: signature %d, %s' % (address, conf['minutes'], event['sid'],
                                                                          event['msg']))
                else:
                    summary['again'] += 1
                entry.update(last=event['at'] or now, until=now + keep, sid=event['sid'], msg=event['msg'],
                             count=entry.get('count', 0) + 1)
                changed = True
        st['inode'], st['offset'] = info.st_ino, at.get('end', start)
        return changed

    def message(self):
        """The page's line, a list of T()."""
        conf, st = self.conf, self.state
        parts = []
        if not conf['on']:
            parts.append(T('off: nothing the IPS drops is entered'))
            return parts
        n = len(st['entries'])
        parts.append(T('%s addresses held, each for %s minutes after its last drop', format(n, ','), conf['minutes']))
        if conf['problem']:
            parts.append(conf['problem'])
        if conf['alias'] != 'ready':
            parts.append(T('its alias is not there yet, or not as Apply makes it: Apply makes it'))
        if (st.get('table') or {}).get('error'):
            parts.append(st['table']['error'])
        return parts

    def save(self):
        save(STATE, self.state)


def take(lock, wait):
    until = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= until:
                return False
            time.sleep(0.2)


def entries_list():
    """The addresses held now, the latest drop first, for the page's grid."""
    state = load(STATE, {})
    entries = state.get('entries') if isinstance(state, dict) and isinstance(state.get('entries'), dict) else {}
    rows = []
    for address, e in entries.items():
        if not isinstance(e, dict):
            continue
        rows.append({'address': address, 'at': stamp(e.get('at')), 'last': stamp(e.get('last')),
                     'until': stamp(e.get('until')), 'sid': e.get('sid'), 'msg': str(e.get('msg') or ''),
                     'count': e.get('count', 0), 'sort': e.get('last', 0)})
    rows.sort(key=lambda r: (-r.pop('sort'), r['address']))
    return {'entries': rows}


def page():
    """The IPS drops tab's line, for status.py."""
    conf = settings()
    state = load(STATE, {})
    state = state if isinstance(state, dict) else {}
    entries = state.get('entries') if isinstance(state.get('entries'), dict) else {}
    last = state.get('last') if isinstance(state.get('last'), dict) else {}
    return {'on': conf['on'], 'minutes': conf['minutes'], 'outside': conf['outside'], 'problem': conf['problem'],
            'alias': conf['alias'], 'entries': len(entries) if conf['on'] else 0,
            'message': state.get('message') if isinstance(state.get('message'), list) else [],
            'last_run': last.get('run')}


def remove(text):
    """One address taken out now: by this run where the watcher is not running, else by the watcher
    within seconds (a request in REMOVE)."""
    try:
        address = ipaddress.ip_address(text or '')
    except ValueError:
        return {'removed': False, 'message': T('not an address')}
    address = address.ipv4_mapped if getattr(address, 'ipv4_mapped', None) else address
    held = load(STATE, {}).get('entries') or {}
    if str(address) not in held:
        return {'removed': False, 'address': str(address), 'message': T('%s is not held', str(address))}
    os.makedirs(REMOVE, exist_ok=True)
    request = os.path.join(REMOVE, address.packed.hex())
    with open(request, 'w'):
        pass
    with open(LOCK, 'a') as lock:
        if take(lock, 0):
            run_once()
            return {'removed': True, 'address': str(address), 'message': T('%s taken out', str(address))}
    until = time.monotonic() + REMOVE_WAIT
    while os.path.exists(request) and time.monotonic() < until:
        time.sleep(0.2)
    if os.path.exists(request):
        return {'removed': False, 'address': str(address),
                'message': T('%s is taken out at the next reading, within a minute', str(address))}
    return {'removed': True, 'address': str(address), 'message': T('%s taken out', str(address))}


def finish(w, summary):
    w.state['message'] = w.message()
    w.state['last'] = {k: summary[k] for k in ('run', 'expired', 'removed', 'capped') if k in summary}
    w.state['last'].update(entered=len(summary.get('entered', [])), refused=summary.get('refused', {}))
    w.save()
    return dict(summary, message=english(w.state['message']))


def run_once():
    w = Watch()
    return finish(w, w.once())


def main(argv):
    if '--status' in argv:
        print(json.dumps(load(STATE, {}).get('last', {}), sort_keys=True))
        return 0
    if '--list' in argv:
        print(json.dumps(entries_list(), sort_keys=True))
        return 0
    seconds = 0
    if '--for' in argv:
        try:
            seconds = max(0, int(argv[argv.index('--for') + 1]))
        except (IndexError, ValueError):
            seconds = 0
    try:
        if not os.path.isdir(STATE_DIR) and ('--remove' in argv or not settings()['on']):
            # never turned on: nothing made, nothing read, nothing held to take out
            print(json.dumps({'removed': False, 'message': english([T('off: nothing the IPS drops is entered')])}))
            return 0
        os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
        if '--remove' in argv:
            i = argv.index('--remove')
            print(json.dumps(remove(argv[i + 1] if i + 1 < len(argv) else ''), sort_keys=True))
            return 0
        with open(LOCK, 'a') as lock:
            # the minute's run waits a little for the last one to end, at the turn of the minute
            if not take(lock, 5 if seconds else 10):
                # the minute's watcher is reading: it takes a changed setting within seconds
                print(json.dumps({'message': english(load(STATE, {}).get('message') or []), 'busy': True}))
                return 0
            w = Watch()
            until = time.monotonic() + seconds
            total = {'entered': [], 'expired': 0, 'removed': 0, 'capped': 0, 'refused': {}}
            while True:
                summary = w.once()
                for key in ('expired', 'removed', 'capped'):
                    total[key] += summary.get(key, 0)
                total['entered'] += summary.get('entered', [])
                for key, n in summary.get('refused', {}).items():
                    total['refused'][key] = total['refused'].get(key, 0) + n
                if w.changed:
                    w.save()
                # off, or nothing to be dropped: the next minute's run looks again (and expires then)
                if seconds and (not w.conf['on'] or w.conf['problem']):
                    break
                if time.monotonic() + EVERY > until:
                    break
                time.sleep(EVERY)
            total['run'] = summary['run']
            print(json.dumps(finish(w, total), sort_keys=True))
    except Exception as e:      # never fail the caller: cron or the page
        log('stopped: %s' % e)
        print(json.dumps({'message': 'stopped: %s' % e}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
