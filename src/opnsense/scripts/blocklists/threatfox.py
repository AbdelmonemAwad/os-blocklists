#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""ThreatFox's command-and-control addresses, fetched with the owner's abuse.ch Auth-Key into a list of
the plugin's own, blocklists_threatfox (2026-11-17).

    threatfox.py            cron, every five minutes: the list put back into pf's table where the table
                            lost it (a reboot), and fetched again where abuse.ch's pace allows (below)
    threatfox.py --apply    the page's Apply (configctl blocklists threatfox, detached): the same, and an
                            export whose last try failed tried again now - a refused Auth-Key too, as it
                            may have just been replaced

WHAT IS FETCHED, over HTTPS with the server's certificate checked: ThreatFox's exports
https://threatfox-api.abuse.ch/v2/files/exports/<Auth-Key>/full.csv.zip - every indicator ThreatFox
holds, those of the last six months (it expires older ones) - and .../recent.csv, its recent additions;
either a CSV, zipped or not. abuse.ch takes the Auth-Key in the address of an export (its export page),
so the key goes to abuse.ch with every request, as abuse.ch asks; nothing else of the firewall's does,
but the address the request comes from and a User-Agent of os-blocklists. Of an export only the
indicators of type ip:port with the threat botnet_cc are taken - command-and-control servers - and of
them only their addresses, IPv4 and IPv6, each once. A line that is not one is dropped, and so is an
address no server on the internet has (NEVER: private, shared, loopback, link-local, multicast, this
network, reserved), which blocked both ways could cut the firewall off its own networks. The list is
the whole export's addresses and those of the recent additions fetched since.

THE PACE, as abuse.ch asks. Its API changelog (2026-11-12): an export whose name holds "full" is served
up to four times its size per account and UTC day - partial and cancelled downloads counted - and
answered 429 after that, until 00:00 UTC; each full export is to be downloaded once a day, and the
matching recent export used for the updates in between. Its Terms of Use: export volumes as reasonably
expected for non-commercial or non-profit purposes, and no high-volume automatic harvesting. So the
whole export is fetched once a day - 24 hours after the last one fetched, and no more than twice begun
in a UTC day, a download that broke off included - and the recent additions as often as "Fetch the
lists" says (every two hours by default; never more often than feeds.json's min_hours for this list,
an hour). An export that failed is tried again after as long as its pace; one answered 429 not before
the time abuse.ch gives (Retry-After); after an Auth-Key refused (401, 403) nothing is sent for a day,
or until the next Apply.

ON A FAILURE THE LAST GOOD LIST IS KEPT: a download that fails or breaks off, an answer that is not an
export, a whole export with no command-and-control address in it - the lists kept here and pf's table
stay as they were.

PF. blocklists_threatfox is an external alias (OPNsense's "External (advanced)"), which apply.php makes
while the list is chosen and an Auth-Key saved: OPNsense declares its table at every filter reload and
leaves its addresses alone (pf keeps the addresses of a table declared without any). This puts the list
into it - `pfctl -t blocklists_threatfox -T replace -f -`, the list on stdin - whenever the table does
not hold it, and only while the alias is there, switched on and external.

THE KEY is read from config.xml (general.threatfox_key) and written nowhere else: not to the system
log, not to this script's answer or its files, not on a command line. A text that would carry it - an
error naming the address it was in - has it taken out first (scrub()).

Never fails its caller: prints one JSON object and exits 0; what it could not do is in the answer, in
STATUS (which the page shows) and in the system log, under blocklists.
"""
import calendar
import csv
import email.utils
import fcntl
import http.client
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

CONFIG = '/conf/config.xml'
FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'feeds.json')
STATE_DIR = '/var/db/os-blocklists/threatfox'
STATUS = os.path.join(STATE_DIR, 'status.json')
LOCK = os.path.join(STATE_DIR, 'lock')
LISTS = {'full': os.path.join(STATE_DIR, 'full.txt'), 'recent': os.path.join(STATE_DIR, 'recent.txt')}
PFCTL = '/sbin/pfctl'
TAG = 'blocklists'
ID = 'threatfox'
ALIAS = 'blocklists_' + ID
EXPORTS = 'https://threatfox-api.abuse.ch/v2/files/exports/'
FILES = {'full': 'full.csv.zip', 'recent': 'recent.csv'}
NAMES = {'full': 'whole export', 'recent': 'recent additions'}
AGENT = 'os-blocklists'
TIMEOUT = 30                                        # seconds to connect, and for each read
DEADLINE = {'full': 300, 'recent': 120}             # seconds a whole download may take
LIMIT = {'full': 128 << 20, 'recent': 32 << 20}     # bytes a download may have
UNZIPPED = 1 << 30                                  # bytes the CSV in a zip may have
FULL_EVERY = 86400                                  # the whole export once a day,
FULL_TRIES = 2                                      # and no more than twice begun in a UTC day
REFUSED_WAIT = 86400                                # a refused Auth-Key: nothing sent for a day
WAIT = 10                                           # seconds a run waits for another to end
# the Auth-Key as the model's Mask takes it: the characters an address carries as they are (RFC 3986's
# unreserved), so it can never change the path it is put in
KEY = re.compile(r'^[A-Za-z0-9._~-]{8,128}$')
REFRESH = {'h2': 2, 'h6': 6, 'h12': 12, 'h24': 24}  # "Fetch the lists", as updatefreq.php reads it
REFRESH_DEFAULT = 'h2'

# ThreatFox's CSV: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, ... - the
# columns are found by the line that names them, a comment at the top of an export, and taken at
# these places where an export has no such line
WANTED = ('ioc_value', 'ioc_type', 'threat_type')
POSITIONS = {'ioc_value': 2, 'ioc_type': 3, 'threat_type': 4}
IOC_TYPES = ('ip:port', 'domain', 'url', 'md5_hash', 'sha1_hash', 'sha256_hash', 'sha3_384_hash')
BRACKETED = re.compile(r'^\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?$')
PORT = re.compile(r'^[0-9]{1,5}$')


def network(text):
    """A network as RFCs write them, IPv4 shortened: '10/8' is 10.0.0.0/8."""
    if ':' not in text:
        address, length = text.split('/')
        text = '.'.join((address.split('.') + ['0', '0', '0'])[:4]) + '/' + length
    return ipaddress.ip_network(text)


# addresses no server on the internet has: this network, RFC 1918, shared (RFC 6598, a WAN's own side
# behind carrier NAT), loopback, link-local, multicast, reserved and broadcast; IPv6's unspecified,
# loopback, IPv4-mapped, unique local, link-local and multicast
NEVER = [network(n) for n in (
    '0/8', '10/8', '100.64/10', '127/8', '169.254/16', '172.16/12', '192.168/16', '224/4', '240/4',
    '::/128', '::1/128', '::ffff:0:0/96', 'fc00::/7', 'fe80::/10', 'ff00::/8')]

NOT_READY = {
    'unread': 'config.xml could not be read: nothing fetched',
    'off': 'Block Lists is off: nothing fetched',
    'not chosen': 'ThreatFox is not chosen: nothing fetched',
    'no alias': 'its alias is not there yet, Apply makes it: nothing fetched',
    'alias off': 'its alias is switched off: nothing fetched',
    'not external': 'its alias is not an external one, Apply makes it one: nothing fetched',
    'no key': 'no abuse.ch Auth-Key saved: nothing fetched',
    'bad key': 'abuse.ch Auth-Key saved is not one (letters, digits, . _ ~ -): nothing fetched',
}

_secrets = []       # the Auth-Key read, taken out of every text written or printed (scrub())


class Refused(Exception):
    """abuse.ch refused the Auth-Key: 401 or 403."""

    def __init__(self, code):
        super().__init__(f'HTTP {code}')
        self.code = code


class Held(Exception):
    """429: abuse.ch's limit reached; retry is its Retry-After, as it came."""

    def __init__(self, retry):
        super().__init__('HTTP 429')
        self.retry = retry


class Failed(Exception):
    """A download that failed or broke off."""


class NotExport(Exception):
    """An answer that is not a ThreatFox export, or a whole one with nothing to take."""


def scrub(text):
    """text with the Auth-Key, as read and as put in an address, taken out."""
    text = str(text)
    for secret in _secrets:
        for form in {secret, urllib.parse.quote(secret, safe='')}:
            if form:
                text = text.replace(form, '<Auth-Key>')
    return text


def say(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def log(message):
    say(scrub('threatfox: ' + message))


def load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write(path, text):
    """Through a temporary file of this run's own beside it, renamed over it: a reader never meets half
    a file."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save(path, data):
    write(path, scrub(json.dumps(data, indent=1, sort_keys=True)))


def read_list(path):
    """A list kept here, as a set of addresses; empty when there is none."""
    found = set()
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                try:
                    found.add(str(ipaddress.ip_address(line.strip())))
                except ValueError:
                    continue
    except OSError:
        pass
    return found


def write_list(path, addresses):
    write(path, ''.join(a + '\n' for a in sorted(addresses)))


def stamp(t):
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t))


def pace(refresh, feed):
    """Hours between two fetches of the recent additions: "Fetch the lists" (general.refresh) or the
    list's min_hours in feeds.json, the longer - as updatefreq.php gives the URL tables theirs; a
    minimum that is missing or not a positive number counts as a day."""
    hours = REFRESH.get(refresh, REFRESH[REFRESH_DEFAULT])
    low = feed.get('min_hours') if isinstance(feed, dict) else None
    if isinstance(low, bool) or not isinstance(low, (int, float)) or low <= 0:
        low = 24
    return max(hours, low)


def settings(path=None):
    """(state, key, hours) from config.xml: state 'ready', or why nothing is fetched (NOT_READY); the
    saved Auth-Key and the recent additions' pace in hours when ready, None else."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return 'unread', None, None
    general = root.find('OPNsense/BlockLists/general')

    def value(tag, default=''):
        return ((general.findtext(tag) if general is not None else None) or default).strip()

    if value('enabled', '1') != '1':
        return 'off', None, None
    if ID not in value('feeds').split(','):
        return 'not chosen', None, None
    # the key before the alias: Apply makes no alias without a key, so "Apply makes it" would send the owner
    # to a button that does nothing for it (found on the second XGS 3300, 2026-11-17)
    key = value('threatfox_key')
    if not key:
        return 'no key', None, None
    _secrets.append(key)
    if not KEY.fullmatch(key):
        return 'bad key', None, None
    alias = next((a for a in root.findall('OPNsense/Firewall/Alias/aliases/alias')
                  if a.findtext('name') == ALIAS), None)
    if alias is None:
        return 'no alias', None, None
    if (alias.findtext('enabled') or '1') != '1':
        return 'alias off', None, None
    if (alias.findtext('type') or '') != 'external':
        return 'not external', None, None
    feeds = load(FEEDS, {})
    return 'ready', key, pace(value('refresh'), feeds.get(ID) if isinstance(feeds, dict) else None)


def network_of(text):
    """An entry of pf's table, or an address of a list, as one network: 198.51.100.7 is .../32."""
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        return None


def pfctl(args, text=None):
    try:
        return subprocess.run([PFCTL] + args, input=text, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None


def table_now():
    """What pf's table holds now, as networks; None when pfctl does not show it."""
    r = pfctl(['-t', ALIAS, '-T', 'show'])
    if r is None or r.returncode != 0:
        return None
    return {n for n in (network_of(line) for line in r.stdout.splitlines() if line.strip()) if n}


def fill(addresses):
    """pf's table made to hold these addresses, where it does not: (put, error)."""
    if table_now() == {network_of(a) for a in addresses}:
        return False, None
    r = pfctl(['-t', ALIAS, '-T', 'replace', '-f', '-'], ''.join(a + '\n' for a in sorted(addresses)))
    if r is None:
        return False, 'pfctl could not be run'
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or '').strip()[:200] or 'pfctl failed'
    return True, None


def address_of(value):
    """The address of a ThreatFox ip:port - 198.51.100.7:443, [2001:db8::7]:443, or 2001:db8::7:443 as
    an IPv6 one may come without brackets - in its canonical form; None where it is not one, its port
    is not one, or it is an address no server on the internet has (NEVER)."""
    value = value.strip()
    if '%' in value:
        return None
    found = BRACKETED.match(value)
    if found:
        candidates = [(found.group(1), found.group(2))]
    elif value.count(':') == 1:
        candidates = [tuple(value.split(':'))]
    elif value.count(':') > 1:
        host, _, port = value.rpartition(':')
        candidates = [(host, port), (value, None)]      # with its port, or an address alone
    else:
        candidates = [(value, None)]
    for host, port in candidates:
        if port is not None and not (PORT.match(port) and 0 < int(port) < 65536):
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        return None if any(ip in net for net in NEVER) else str(ip)
    return None


def columns(row):
    """{name: place} of the columns WANTED, from a line naming ThreatFox's columns - commented or not,
    `# "first_seen_utc","ioc_id","ioc_value",...` - or None where the line is not one."""
    names = [field.strip().lstrip('#').strip().strip('"').strip() for field in row]
    if all(name in names for name in WANTED):
        return {name: names.index(name) for name in WANTED}
    return None


def read(text):
    """The command-and-control addresses of a ThreatFox CSV export, from its lines (a text file):
    (addresses, counts). NotExport where it is not one: no line naming its columns, and no line of an
    indicator where they are expected."""
    found, counts = set(), {'indicators': 0, 'c2': 0, 'dropped': 0}
    where, known = None, False
    try:
        for row in csv.reader(text, skipinitialspace=True):
            if not any(field.strip() for field in row):
                continue
            named = columns(row)
            if named:
                where, known = named, True
                continue
            if row[0].lstrip().startswith('#'):
                continue
            at = where or POSITIONS
            if len(row) <= max(at.values()):
                continue
            kind, threat = row[at['ioc_type']].strip(), row[at['threat_type']].strip()
            if where is None and kind not in IOC_TYPES:
                continue
            known = True
            counts['indicators'] += 1
            if kind != 'ip:port' or threat != 'botnet_cc':
                continue
            counts['c2'] += 1
            address = address_of(row[at['ioc_value']])
            if address is None:
                counts['dropped'] += 1
            else:
                found.add(address)
    except csv.Error as e:
        raise NotExport(f'not a CSV file ({e})') from e
    if not known:
        raise NotExport('no line of a ThreatFox export in it')
    return found, counts


def read_export(spool):
    """read() of an export as downloaded, zipped or not (a seekable binary file)."""
    zipped = spool.read(4) == b'PK\x03\x04'
    spool.seek(0)
    if not zipped:
        return read(io.TextIOWrapper(spool, encoding='utf-8', errors='replace', newline=''))
    try:
        with zipfile.ZipFile(spool) as archive:
            members = [m for m in archive.infolist() if m.filename.lower().endswith('.csv')]
            if len(members) != 1:
                raise NotExport('%s CSV files in the zip, not one' % len(members))
            if members[0].file_size > UNZIPPED:
                raise NotExport('its CSV is larger than %d MB' % (UNZIPPED >> 20))
            with archive.open(members[0]) as member:
                return read(io.TextIOWrapper(member, encoding='utf-8', errors='replace', newline=''))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, NotImplementedError) as e:
        raise NotExport(f'a damaged zip ({e})') from e


def reason(e):
    """What went wrong on the way, in a few words."""
    if isinstance(e, TimeoutError):
        return f'no answer within {TIMEOUT} s'
    if isinstance(e, urllib.error.URLError):
        return str(e.reason)
    return f'{type(e).__name__}: {e}'


URLOPEN = urllib.request.urlopen


def download(url, spool, which, begun):
    """url's body written into spool; begun() called once abuse.ch answered 200. Raises Refused,
    Held or Failed."""
    deadline = time.monotonic() + DEADLINE[which]
    request = urllib.request.Request(url, headers={'User-Agent': AGENT})
    try:
        response = URLOPEN(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        code = e.code
        retry = e.headers.get('Retry-After') if e.headers is not None else None
        e.close()
        if code in (401, 403):
            raise Refused(code) from None
        if code == 429:
            raise Held(retry) from None
        raise Failed(f'abuse.ch answered HTTP {code}') from None
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
        raise Failed(f'abuse.ch not reached: {reason(e)}') from None
    size = 0
    with response:
        if getattr(response, 'status', 200) != 200:
            raise Failed(f'abuse.ch answered HTTP {response.status}')
        begun()
        while True:
            if time.monotonic() > deadline:
                raise Failed(f'not done within {DEADLINE[which]} s')
            try:
                chunk = response.read(1 << 16)
            except (OSError, http.client.HTTPException, ValueError) as e:
                raise Failed(f'the download broke off: {reason(e)}') from None
            if not chunk:
                break
            size += len(chunk)
            if size > LIMIT[which]:
                raise Failed(f'larger than {LIMIT[which] >> 20} MB')
            spool.write(chunk)
    return size


def retry_after(value, now):
    """When abuse.ch's 429 says to come back: its Retry-After, in seconds or as a date; the next 00:00
    UTC, where its changelog says it points, when it gives neither or a time past; two days at most."""
    at = None
    value = (value or '').strip()
    if re.match(r'^[0-9]{1,9}$', value):
        at = now + int(value)
    elif value:
        try:
            at = int(email.utils.parsedate_to_datetime(value).timestamp())
        except (TypeError, ValueError, IndexError, OverflowError):
            at = None
    if at is None or at <= now:
        at = (now // 86400 + 1) * 86400
    return min(at, now + 2 * 86400)


def day_end(day):
    """00:00 UTC after a UTC day, written 2026-11-17."""
    return calendar.timegm(time.strptime(day, '%Y-%m-%d')) + 86400


def when(which, status, hours, apply=False):
    """The earliest time an export may be fetched, by its pace (see the top); apply: the page's Apply,
    which tries again now an export that failed last, and sends a refused Auth-Key again."""
    every = int(hours * 3600)
    full, st = status.get('full') or {}, status.get(which) or {}
    at = st.get('held', 0)
    if status.get('refused') and not apply:
        at = max(at, status['refused'] + REFUSED_WAIT)
    if which == 'full':
        if full.get('ok'):
            at = max(at, full['ok'] + FULL_EVERY)
        if full.get('tried', 0) > full.get('ok', 0) and not apply:
            at = max(at, full['tried'] + every)
        if full.get('tries', 0) >= FULL_TRIES and full.get('day'):
            at = max(at, day_end(full['day']))
    else:
        failed = st.get('tried', 0) > max(st.get('ok', 0), full.get('ok', 0))
        if not (apply and failed):
            at = max(at, max(full.get('ok', 0), st.get('tried', 0)) + every)
    return at


def fetch(which, key, now, status):
    """One export downloaded and read, its outcome in status: its addresses, or None where it failed -
    why in status[which]['error'], the lists kept here as they were."""
    st = status.setdefault(which, {})
    st['tried'] = now
    day = time.strftime('%Y-%m-%d', time.gmtime(now))

    def begun():
        if which == 'full':     # a download of the whole export begun: one of the day's
            if st.get('day') != day:
                st['day'], st['tries'] = day, 0
            st['tries'] = st.get('tries', 0) + 1

    url = EXPORTS + urllib.parse.quote(key, safe='') + '/' + FILES[which]
    try:
        with tempfile.TemporaryFile(dir=STATE_DIR) as spool:
            size = download(url, spool, which, begun)
            spool.seek(0)
            found, counts = read_export(spool)
        if which == 'full' and not found:
            raise NotExport('no command-and-control address in it')
    except Refused as e:
        status['refused'], status['refused_code'] = now, e.code
        st['error'] = f'abuse.ch refused the Auth-Key (HTTP {e.code})'
        return None
    except Held as e:
        st['held'] = retry_after(e.retry, now)
        st['error'] = f'abuse.ch answered HTTP 429, its limit reached, until {stamp(st["held"])}'
        return None
    except NotExport as e:
        st['error'] = scrub(f'not a ThreatFox export: {e}')
        return None
    except (Failed, OSError) as e:
        st['error'] = scrub(str(e))
        return None
    st.pop('error', None)
    st['ok'] = now
    st.update(size=size, indicators=counts['indicators'], c2=counts['c2'], entries=len(found),
              dropped=counts['dropped'])
    status['refused'] = 0
    log(f"{NAMES[which]} fetched, {size:,} bytes: {counts['c2']:,} command-and-control indicators of "
        f"{counts['indicators']:,}, {len(found):,} addresses, {counts['dropped']:,} dropped")
    return found


def describe(status, entries):
    """The page's line: what the list holds and from when, and what failed last."""
    full, recent = status.get('full') or {}, status.get('recent') or {}
    parts = []
    if full.get('ok'):
        parts.append('the whole export fetched ' + stamp(full['ok']))
    if recent.get('ok') and recent['ok'] > full.get('ok', 0):
        parts.append('the recent additions fetched ' + stamp(recent['ok']))
    text = (f"{entries:,} address{'' if entries == 1 else 'es'}, from " + ' and '.join(parts) if parts
            else 'nothing fetched yet')
    if status.get('refused'):
        text += (f"; abuse.ch refused the Auth-Key at {stamp(status['refused'])} (HTTP "
                 f"{status.get('refused_code', '?')}): nothing is sent before "
                 f"{stamp(status['refused'] + REFUSED_WAIT)}, or the next Apply")
    else:
        for which in ('full', 'recent'):
            st = status.get(which) or {}
            if st.get('error'):
                text += f"; the {NAMES[which]} not fetched at {stamp(st['tried'])}: {st['error']}"
    if entries and any((status.get(w) or {}).get('error') for w in ('full', 'recent')):
        text += ' - the list is kept'
    table = status.get('table') or {}
    if table.get('error'):
        text += f"; pf's table not filled: {table['error']}"
    return text


def run(now=None, apply=False):
    now = int(time.time() if now is None else now)
    state, key, hours = settings()
    status = load(STATUS, {})
    status = status if isinstance(status, dict) else {}
    for part in ('full', 'recent', 'table'):
        if not isinstance(status.get(part, {}), dict):
            del status[part]
    before = json.dumps(status, sort_keys=True)
    if state != 'ready':
        # nothing fetched, and pf's table left as it is: the alias goes with Apply
        status['message'] = NOT_READY[state]
        if json.dumps(status, sort_keys=True) != before:
            save(STATUS, status)
        return {'run': now, 'ready': False, 'message': status['message']}
    lists = {which: read_list(path) for which, path in LISTS.items()}
    fetched = {}
    for which in ('full', 'recent'):
        if status.get('refused') == now or when(which, status, hours, apply) > now:
            continue
        found = fetch(which, key, now, status)
        fetched[which] = found is not None
        if found is None:
            log(f"{NAMES[which]} not fetched: {status[which]['error']}; the list is kept "
                f"({len(lists['full'] | lists['recent']):,} addresses)")
            continue
        lists[which] = found
        write_list(LISTS[which], found)
        if which == 'full':
            # the whole export holds what the recent additions before it had
            lists['recent'] = set()
            write_list(LISTS['recent'], set())
    addresses = lists['full'] | lists['recent']
    table, said = {}, 'nothing to put'
    if addresses:
        put, error = fill(addresses)
        if error:
            table['error'] = said = scrub(error)
            log(f"pf's table {ALIAS} not filled: {table['error']}")
        elif put:
            said = 'filled'
            log(f"{len(addresses):,} addresses put into pf's table {ALIAS}")
        else:
            said = 'holds the list'
    status['table'] = table
    status['entries'] = len(addresses)
    status['message'] = describe(status, len(addresses))
    if json.dumps(status, sort_keys=True) != before:
        save(STATUS, status)
    return {'run': now, 'ready': True, 'fetched': fetched, 'entries': len(addresses), 'table': said,
            'message': status['message']}


def take(lock, wait=WAIT):
    """The lock, or False after `wait` seconds: one run at a time, as the page's Apply and the cron
    entry both run this, and a download may take minutes."""
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
    try:
        os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
        with open(LOCK, 'w') as lock:
            if not take(lock):
                last = load(STATUS, {})
                print(scrub(json.dumps({'message': last.get('message', 'another run is fetching'),
                                        'busy': True}, sort_keys=True)))
                return 0
            print(scrub(json.dumps(run(apply='--apply' in argv), sort_keys=True)))
    except Exception as e:      # never fail the caller: cron or the page's Apply
        log(f'stopped: {e}')
        print(scrub(json.dumps({'message': f'stopped: {e}'})))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
