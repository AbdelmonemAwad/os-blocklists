#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""UT1's web categories, fetched by the firewall and applied through OPNsense's own Unbound blocklist
(2026-11-19).

    categories.py              cron, every five minutes: each chosen category checked with UT1 as often as
                               "Fetch the lists" says, and what changed applied
    categories.py --apply      the page's Apply (configctl blocklists categories, detached): the same, and
                               a category just chosen, or one whose last fetch failed, fetched now
    categories.py --installed  install/install.sh and pkg/post-install.sh: Unbound's blocklist rebuilt
                               where categories are applied, so the handler just installed is the one read;
                               nothing fetched

WHAT: the categories of UT1 (Universite Toulouse 1 Capitole), each a folder of names. The categories
offered are those of the catalogue shipped beside this script (categories.json), and those of UT1's own
catalogue, global_usage, where it could be fetched (CATALOGUE). Every one can be chosen but adult (decision
d2): about 4.6 million names, about 2.3 GiB held by Unbound's blocklist module - refused here whatever
config.xml or a catalogue says, and so is any archive with more than MAX_NAMES names.

HOW IT REACHES UNBOUND: not through the owner's Unbound settings, which are left as they are. OPNsense's
blocklists.py (configctl unbound dnsbl) runs every handler in /usr/local/opnsense/scripts/unbound/blocklists/;
this plugin's, blocklists_ut1.py, reads ACTIVE - the categories applied, the file each reads (and its
SHA-256) and the exceptions - and the files beside it, and gives Unbound one policy of its own for every
client. Unbound reads the new dnsbl.json within 60 seconds, without a restart. This script writes ACTIVE
and the files, and runs configctl unbound dnsbl once a run, only when ACTIVE changed, or a rebuild is still
owed (pending, or MARKER after an install).

A REBUILD IS DONE WHEN DNSBL.JSON SAYS SO, not when configctl answers: configctl gives up on its socket
after 120 s and answers 0 while blocklists.py goes on, and blocklists.py leaves at once, with nothing
written, when another runs (its lock, CORE_LOCK); the configd action ends in || true either way. So the
handler stamps its policy with the SHA-256 of its own source and of the ACTIVE it read (OPNsense copies a
policy into dnsbl.json whole), and this waits - RELOAD_TIMEOUT at the most - while CORE_LOCK is held, then
reads the policy's stamp there: the rebuild is done when it is the stamp of this ACTIVE and this handler
(or, with nothing applied, when the policy is gone), and owed - tried at the next run - while it is not.
A rebuild that began before ACTIVE was written and ends after it is so told from one that read it.

FETCHING: https://dsi.ut-capitole.fr/blacklists/download/<archive>.tar.gz over HTTPS with the server's
certificate checked, with If-Modified-Since and If-None-Match where a copy is kept: UT1 answers 304 when
it has not changed, which costs nothing and changes nothing here. Malware and phishing are one archive at
UT1 (the same file, its folder phishing/): one download serves both, one file is kept and its names are
held once. Of an archive only its <folder>/domains member is read - by its name, a plain file, the one of
that name - and never written where the archive says: its names are written, one a line, lowercased and
each once, into this plugin's own STATE_DIR/<archive>.domains. A line that is a bare IPv4 address is
left out (DNS cannot use it), and so is one that is not a name as OPNsense's blocklist takes it.

ON A FAILURE THE LAST GOOD COPY IS KEPT: a download that fails or breaks off, an answer that is not an
archive, an archive without its domains file - the copy kept stays applied, and the page says so. A
category no longer chosen, or Block Lists turned off, is taken out at the next run: its file deleted, and
Unbound's blocklist rebuilt without it.

Never fails its caller: prints one JSON object and exits 0; what it could not do is in the answer, in
STATUS (the page shows it) and in the system log, under blocklists.

TEXTS FOR THE PAGE are kept as T(msgid, args...): the English msgid and what fills it, which the page's
controller translates with OPNsense's catalogue (gettext) and the system log reads in English
(english()). Every msgid is a literal of T() here, so tools/check-strings.py finds it and asks for its
Arabic; the categories' names, descriptions and reasons come from categories.json, which it reads too.
"""
import fcntl
import hashlib
import http.client
import ipaddress
import json
import mmap
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zlib

CONFIG = '/conf/config.xml'
HERE = os.path.dirname(os.path.abspath(__file__))
SHIPPED = os.path.join(HERE, 'categories.json')
STATE_DIR = '/var/db/os-blocklists/categories'
STATUS = os.path.join(STATE_DIR, 'status.json')
ACTIVE = os.path.join(STATE_DIR, 'unbound.json')        # what blocklists_ut1.py reads
CATALOGUE = os.path.join(STATE_DIR, 'catalogue.json')   # UT1's global_usage, as read here
LOCK = os.path.join(STATE_DIR, 'lock')
MARKER = os.path.join(STATE_DIR, 'rebuild')             # a rebuild owed by an install that found a run going
EMPTY = {'categories': {}, 'exceptions': [], 'files': {}}   # ACTIVE with nothing applied, or none at all
HANDLER = '/usr/local/opnsense/scripts/unbound/blocklists/blocklists_ut1.py'
POLICY = 'f188da6c-137b-41dd-b504-fe5d96a73483'         # the handler's policy id, as it writes it
DNSBL = '/var/unbound/data/dnsbl.json'                  # what OPNsense's blocklists.py writes
CORE_LOCK = '/tmp/unbound-download_blocklists.tmp'      # blocklists.py's lock, held while it runs
TAIL = 4 << 20                  # bytes of dnsbl.json's end read first: its "config", the policies, is last
CONFIGCTL = '/usr/local/sbin/configctl'
DOWNLOAD = 'https://dsi.ut-capitole.fr/blacklists/download/'
CATALOGUE_URL = DOWNLOAD + 'global_usage'
TAG = 'blocklists'
AGENT = 'os-blocklists'
TIMEOUT = 30                    # seconds to connect, and for each read
DEADLINE = 300                  # seconds a whole download may take
LIMIT = 16 << 20                # bytes an archive may have: the largest offered was 2.4 MB on 2026-11-19
UNPACKED = 128 << 20            # bytes its domains file may have: 4.7 MB then
MAX_NAMES = 1000000             # names an archive may hold: 241,045 the most then; adult 4.6 million
CATALOGUE_LIMIT = 1 << 20       # bytes global_usage may have: 29,804 then
CATALOGUE_EVERY = 86400         # global_usage checked once a day,
CATALOGUE_RETRY = 3600          # and within the hour where a category chosen is in no catalogue
MEMBERS = 64                    # members an archive may have: 4 the most then
LINE = 1024                     # bytes a line of a domains file may have; a longer one is left out
RELOAD_TIMEOUT = 900            # seconds configctl unbound dnsbl may take
WAIT = {'cron': 10, 'apply': 120, 'installed': 60}  # seconds a run waits for another to end
REFRESH = {'h2': 2, 'h6': 6, 'h12': 12, 'h24': 24}     # "Fetch the lists", as updatefreq.php reads it
REFRESH_DEFAULT = 'h2'
# never, whatever config.xml or a catalogue says: decision d2
REFUSED = {'adult': "about 4.6 million names, about 2.3 GiB held by Unbound's blocklist module: too much "
                    "for a firewall"}
ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}\Z')
# a validator header as a server may send it, and as it may be sent back: printable, one line
VALIDATOR = re.compile(r'^[\x20-\x7e]{1,200}\Z')
# a name as OPNsense 26.7.9's BaseBlocklistHandler takes one (scripts/unbound/blocklists/__init__.py L54-57)
DOMAIN = re.compile(
    r'^(\*\.){,1}(([\da-zA-Z_])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})'
    r'?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))$'
)
# an exception: a name of two labels or more, each letters, digits, - and _, as the model's mask takes it
EXCEPTION = re.compile(r'^(?=.{1,253}\Z)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\Z')
TEXT = re.compile(r'[^\x20-\x7e\u00a0-\uffff]')


def T(text, *args):
    """A text for the page: a msgid of the catalogue and what fills its %s, each a value or a T()."""
    return {'text': text, 'args': list(args)}


def data_text(text):
    """A text of categories.json for the page - a category's name, description or reason - as a T()
    whose msgid is not a literal here: tools/check-strings.py takes those from categories.json."""
    return {'text': str(text or ''), 'args': []}


def english(value):
    """A T(), or a list of them (one line, '; ' between), as English: for the log and the command line."""
    if isinstance(value, list):
        return '; '.join(english(v) for v in value)
    if isinstance(value, dict) and isinstance(value.get('text'), str):
        args = tuple(english(a) for a in (value.get('args') or []))
        try:
            return value['text'] % args
        except (TypeError, ValueError):
            return value['text']
    return str(value)


class Failed(Exception):
    """A download that failed, broke off, or was not an archive of UT1's; text: what the page says, a T()."""

    def __init__(self, text):
        self.text = text
        super().__init__(english(text))


def say(message):
    try:
        subprocess.run(['/usr/bin/logger', '-t', TAG, '-p', 'daemon.notice', 'categories: ' + message], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


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
    write(path, json.dumps(data, indent=1, sort_keys=True))


def stamp(t):
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t))


def data_path(archive):
    """The file kept for an archive: its name built here from a checked id, never taken from anywhere."""
    if not ID.match(archive or ''):
        raise ValueError('not an archive name: %r' % (archive,))
    return os.path.join(STATE_DIR, archive + '.domains')


def plain(value, limit=300):
    """A text from a catalogue as the page may show it: one line, no control characters and no < or >
    (UT1's global_usage is read from the network), not too long."""
    return TEXT.sub('', ' '.join(str(value or '').replace('<', ' ').replace('>', ' ').split()))[:limit]


def catalogue(shipped=None, fetched=None):
    """Every category offered, {id: entry}: the shipped catalogue's, then those of UT1's global_usage
    that it does not have (their own English name and description, no count). Each entry: name,
    description, use (block or allow, UT1's default), names (an int, or None where not counted),
    approximate, refused (why it cannot be chosen, or ''), archive (the archive it is in)."""
    found = {}
    base = load(shipped or SHIPPED, {})
    base = base.get('categories') if isinstance(base, dict) else None
    extra = load(fetched or CATALOGUE, {})
    extra = extra.get('categories') if isinstance(extra, dict) else None
    for source, entries in (('shipped', base), ('ut1', extra)):
        if not isinstance(entries, dict):
            continue
        for cid, entry in entries.items():
            if not isinstance(cid, str) or not ID.match(cid) or cid in found or not isinstance(entry, dict):
                continue
            archive = entry.get('archive') if isinstance(entry.get('archive'), str) else cid
            names = entry.get('names')
            found[cid] = {
                'name': plain(entry.get('name'), 80) or cid,
                'description': plain(entry.get('description')),
                'use': 'allow' if entry.get('use') == 'allow' else 'block',
                'names': names if isinstance(names, int) and not isinstance(names, bool) and names >= 0 else None,
                'approximate': entry.get('approximate') is True,
                'refused': REFUSED.get(cid) or REFUSED.get(archive) or plain(entry.get('refused')),
                'archive': archive if ID.match(archive) else cid,
                'source': source,
            }
    return found


def settings(path=None):
    """What config.xml says, or None where it cannot be read: enabled, the categories chosen (as
    written), the exceptions (checked, lowercased, each once) and the pace in hours."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return None
    general = root.find('OPNsense/BlockLists/general')

    def value(tag, default=''):
        return ((general.findtext(tag) if general is not None else None) or default).strip()

    return {
        'enabled': value('enabled', '1') == '1',
        'categories': [c for c in re.split(r'[\s,]+', value('categories')) if c],
        'exceptions': exceptions(value('exceptions')),
        'hours': REFRESH.get(value('refresh'), REFRESH[REFRESH_DEFAULT]),
        'unbound': (root.findtext('OPNsense/unboundplus/general/enabled') or '0').strip() == '1',
    }


def exceptions(text):
    """The exceptions as names: each lowercased, a trailing dot dropped, each once; what is not a name
    of two labels or more is left out."""
    out = []
    for item in re.split(r'[\s,]+', text or ''):
        name = item.strip().lower().rstrip('.')
        if name and EXCEPTION.match(name) and name not in out:
            out.append(name)
    return out


def why_not(cid, entry):
    """Why a category chosen is not taken, a T(), or None where it is."""
    if not ID.match(cid):
        return T('not a category name')
    if cid in REFUSED:
        return T('cannot be chosen: %s', data_text(REFUSED[cid]))
    if entry is None:
        return T('not in the catalogue of UT1')
    if entry['refused']:
        return T('cannot be chosen: %s', data_text(entry['refused']))
    return None


URLOPEN = urllib.request.urlopen


def reason(e):
    """What went wrong on the way: a T(), or the system's own words."""
    if isinstance(e, TimeoutError):
        return T('no answer within %s s', TIMEOUT)
    if isinstance(e, urllib.error.URLError):
        return str(e.reason)
    return '%s: %s' % (type(e).__name__, e)


def download(url, spool, limit, validators=None):
    """url's body written into spool: (status, headers) - 304 where the validators say it has not
    changed. Raises Failed."""
    headers = {'User-Agent': AGENT}
    for header, value in (validators or {}).items():
        if isinstance(value, str) and VALIDATOR.match(value):
            headers[header] = value
    deadline = time.monotonic() + DEADLINE
    try:
        response = URLOPEN(urllib.request.Request(url, headers=headers), timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        code = e.code
        e.close()
        if code == 304:
            return 304, {}
        raise Failed(T('UT1 answered HTTP %s', code)) from None
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
        raise Failed(T('UT1 not reached: %s', reason(e))) from None
    size = 0
    with response:
        status = getattr(response, 'status', 200)
        if status == 304:
            return 304, {}
        if status != 200:
            raise Failed(T('UT1 answered HTTP %s', status))
        got = {}
        for header in ('Last-Modified', 'ETag'):
            value = response.headers.get(header) if response.headers is not None else None
            if isinstance(value, str) and VALIDATOR.match(value.strip()):
                got[header] = value.strip()
        while True:
            if time.monotonic() > deadline:
                raise Failed(T('not done within %s s', DEADLINE))
            try:
                chunk = response.read(1 << 16)
            except (OSError, http.client.HTTPException, ValueError) as e:
                raise Failed(T('the download broke off: %s', reason(e))) from None
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise Failed(T('larger than %s MB', limit >> 20))
            spool.write(chunk)
    return 200, dict(got, size=size)


def lines(source):
    """The lines of a file read from an archive, each LINE bytes at the most: a longer one is given as
    None, whole, so no piece of it is ever taken for a name."""
    while True:
        line = source.readline(LINE)
        if not line:
            return
        if len(line) >= LINE and not line.endswith(b'\n'):
            while True:
                rest = source.readline(LINE)
                if not rest or rest.endswith(b'\n'):
                    break
            yield None
            continue
        yield line


def unpack(spool, members, out):
    """The names of an archive's domains file, written into out (a text file of this script's own),
    one a line, lowercased, each once. members: the member names taken for it, e.g. {'phishing/domains'};
    any other member is passed over unread, and one of those names that is not a plain file - a link, a
    folder, a device - or is there twice refuses the archive, as does one larger than UNPACKED or more
    than MEMBERS members. Nothing of the archive is written to disk by its own name.
    (names, ipv4, dropped, sha256). Raises Failed."""
    try:
        archive = tarfile.open(fileobj=spool, mode='r:gz')
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise Failed(T('not a category archive (%s)', str(e))) from None
    taken, names, ipv4, dropped, count = None, 0, 0, 0, 0
    digest, seen = hashlib.sha256(), set()
    deadline = time.monotonic() + DEADLINE
    try:
        with archive:
            for member in archive:
                count += 1
                if count > MEMBERS:
                    raise Failed(T('more than %s members in the archive', MEMBERS))
                if member.size > UNPACKED:
                    raise Failed(T('its %s is larger than %s MB', member.name[:80], UNPACKED >> 20))
                if member.name not in members:
                    continue
                if taken is not None:
                    raise Failed(T('two %s files in the archive', member.name))
                if not member.isreg():
                    raise Failed(T('its %s is not a plain file', member.name))
                taken = member.name
                source = archive.extractfile(member)
                for raw in lines(source):
                    if raw is None:
                        dropped += 1
                        continue
                    if names % 50000 == 0 and time.monotonic() > deadline:
                        raise Failed(T('not read within %s s', DEADLINE))
                    line = raw.decode('utf-8', 'replace').split('#', 1)[0].strip().lower()
                    if not line:
                        continue
                    if line.startswith('*.'):
                        line = line[2:]
                    line = line.rstrip('.')
                    try:
                        ipaddress.IPv4Address(line)
                        ipv4 += 1
                        continue
                    except ValueError:
                        pass
                    if not DOMAIN.match(line):
                        dropped += 1
                        continue
                    if line in seen:
                        continue
                    seen.add(line)
                    names += 1
                    if names > MAX_NAMES:
                        raise Failed(T('more than %s names: larger than any category offered', format(MAX_NAMES, ',')))
                    text = line + '\n'
                    out.write(text)
                    digest.update(text.encode())
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise Failed(T('a damaged archive (%s)', str(e))) from None
    if taken is None:
        raise Failed(T('no %s in the archive', ' or '.join(sorted(members))))
    return names, ipv4, dropped, digest.hexdigest()


def members_of(archive, cids):
    """The member names an archive's domains file is taken by: <archive>/domains, and <category>/domains
    for each category it serves (malware and phishing are one archive at UT1, its folder phishing/)."""
    return {name + '/domains' for name in {archive, *cids}}


def fetch(archive, cids, st, now, keep):
    """One archive checked with UT1, its outcome in st: 'unchanged' (304, or the same names), 'changed'
    (a new copy kept) or 'failed' (the copy kept as it was; why in st['error'])."""
    st['tried'] = now
    path = data_path(archive)
    validators = {}
    if keep and os.path.isfile(path):
        if st.get('last_modified'):
            validators['If-Modified-Since'] = st['last_modified']
        if st.get('etag'):
            validators['If-None-Match'] = st['etag']
    try:
        with tempfile.TemporaryFile(dir=STATE_DIR) as spool:
            code, got = download(DOWNLOAD + archive + '.tar.gz', spool, LIMIT, validators)
            if code == 304:
                st['checked'] = now
                st.pop('error', None)
                return 'unchanged'
            spool.seek(0)
            fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix='.' + archive + '.')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
                    names, ipv4, dropped, sha = unpack(spool, members_of(archive, cids), out)
                if sha == st.get('sha256') and os.path.isfile(path):
                    os.unlink(tmp)
                    outcome = 'unchanged'
                else:
                    os.replace(tmp, path)
                    outcome = 'changed'
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
    except Failed as e:
        st['error'] = e.text
        return 'failed'
    except OSError as e:
        st['error'] = str(e)
        return 'failed'
    st.pop('error', None)
    st.update(checked=now, fetched=now, names=names, ipv4=ipv4, dropped=dropped, sha256=sha, size=got.get('size'))
    for header, key in (('Last-Modified', 'last_modified'), ('ETag', 'etag')):
        if got.get(header):
            st[key] = got[header]
        else:
            st.pop(key, None)
    if outcome == 'changed':
        st['changed'] = now
        say('%s fetched, %s bytes: %s names kept, %s bare IPv4 lines and %s other lines left out'
            % (archive, format(got.get('size') or 0, ','), format(names, ','), format(ipv4, ','), format(dropped, ',')))
    return outcome


def parse_catalogue(text):
    """UT1's global_usage: {id: {name, description, use}}, from its NAME:, DEFAULT_TYPE:, NAME EN: and
    DESC EN: lines; an id or a text that is not one is left out."""
    found, current = {}, None
    for line in text.splitlines():
        if line.lstrip().startswith('#'):
            continue
        m = re.match(r'^\s*([A-Z_]+(?: [A-Z]{2})?)\s*:\s*(.*?)\s*$', line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if key == 'NAME':
            current = value.lower() if ID.match(value.lower()) else None
            if current is not None:
                found.setdefault(current, {'name': current, 'description': '', 'use': 'block'})
        elif current is None:
            continue
        elif key == 'DEFAULT_TYPE':
            found[current]['use'] = 'allow' if value.lower() == 'white' else 'block'
        elif key == 'NAME EN':
            found[current]['name'] = plain(value, 80) or current
        elif key == 'DESC EN':
            found[current]['description'] = plain(value)
    return found


def fetch_catalogue(st, now):
    """UT1's global_usage fetched, conditionally, into CATALOGUE; st its outcome. The categories it
    names beside the shipped ones are offered on the page; one that is not an id is left out."""
    st['tried'] = now
    validators = {}
    if os.path.isfile(CATALOGUE):
        if st.get('last_modified'):
            validators['If-Modified-Since'] = st['last_modified']
        if st.get('etag'):
            validators['If-None-Match'] = st['etag']
    try:
        with tempfile.TemporaryFile(dir=STATE_DIR) as spool:
            code, got = download(CATALOGUE_URL, spool, CATALOGUE_LIMIT, validators)
            if code == 304:
                st['checked'] = now
                st.pop('error', None)
                return
            spool.seek(0)
            entries = parse_catalogue(spool.read().decode('utf-8', 'replace'))
    except Failed as e:
        st['error'] = e.text
        return
    except OSError as e:
        st['error'] = str(e)
        return
    if len(entries) < 10:
        # UT1's site answers its maintenance page for global_usage now and then (2026-11-19)
        st['error'] = T('not the catalogue of UT1: %s categories in it', len(entries))
        return
    save(CATALOGUE, {'fetched': now, 'categories': entries})
    st.pop('error', None)
    st.update(checked=now, fetched=now, categories=len(entries))
    for header, key in (('Last-Modified', 'last_modified'), ('ETag', 'etag')):
        if got.get(header):
            st[key] = got[header]
        else:
            st.pop(key, None)


def expected():
    """The stamp the handler gives its policy for what is applied now - SHA-256 of its source, a newline
    and ACTIVE's bytes, as it computes it - or None where nothing is applied (it then gives no policy)."""
    active = load(ACTIVE, EMPTY)
    if not isinstance(active, dict) or not active.get('categories'):
        return None
    try:
        with open(HANDLER, 'rb') as handle:
            source = handle.read()
        with open(ACTIVE, 'rb') as handle:
            return hashlib.sha256(source + b'\n' + handle.read()).hexdigest()
    except OSError:
        return ''


def dnsbl_config(path=None):
    """The "config" of dnsbl.json - the policies, {id: policy} - read from its end, where OPNsense's
    blocklists.py writes it; {} where there is no file or an empty one (no policy holds a name), None
    where it cannot be read. dnsbl.json may hold millions of names: only its end is read, and the whole
    file searched in place only where the end does not hold it."""
    path = path or DNSBL
    try:
        size = os.path.getsize(path)
        if size == 0:
            return {}
        with open(path, 'rb') as handle:
            handle.seek(max(0, size - TAIL))
            tail = handle.read()
            found = None
            for found in re.finditer(rb'"config"\s*:\s*\{', tail):
                pass
            if found is None and size > TAIL:
                with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as whole:
                    for found in re.finditer(rb'"config"\s*:\s*\{', whole):
                        pass
                    tail = whole[found.start():] if found is not None else b''
                    found = re.match(rb'"config"\s*:\s*\{', tail)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    if found is None:
        return None
    try:
        config, _ = json.JSONDecoder().raw_decode(tail[found.end() - 1:].decode('utf-8', 'replace'))
    except ValueError:
        return None
    return config if isinstance(config, dict) else None


def written(stamp_now, since=None):
    """Whether Unbound's data holds what is applied now: this plugin's policy with that stamp - or, with
    nothing applied (None), no policy of its own. An empty dnsbl.json (no policy of anyone's holds a name)
    counts only where it was written since the rebuild was asked for."""
    config = dnsbl_config()
    if config is None:
        return False
    if not config:
        try:
            fresh = since is not None and os.stat(DNSBL).st_mtime >= since
        except OSError:
            fresh = False
        return stamp_now is None or fresh
    policy = config.get(POLICY)
    if stamp_now is None:
        return policy is None
    return isinstance(policy, dict) and policy.get('stamp') == stamp_now


def core_busy():
    """Whether OPNsense's blocklists.py runs now: its lock held. Probed and let go at once; the lock file
    is opened for reading only - never made, emptied or removed here."""
    try:
        fd = os.open(CORE_LOCK, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def pause(seconds):
    time.sleep(seconds)


def wait_core(until):
    """While blocklists.py runs, wait for it to end - until `until` (time.monotonic()) at the most."""
    while core_busy() and time.monotonic() < until:
        pause(1)


def configctl(*args):
    return subprocess.run([CONFIGCTL] + list(args), capture_output=True, text=True, timeout=RELOAD_TIMEOUT)


def reload_unbound(stamp_now):
    """Unbound's blocklist made to hold what is applied now (stamp_now, expected()): a rebuild of
    blocklists.py's already running waited for, as it may have read an older ACTIVE; nothing more where
    dnsbl.json then holds it; else configctl unbound dnsbl, and blocklists.py waited for again, for
    RELOAD_TIMEOUT in all. (done, error T()) - not done, the next run looks again."""
    until = time.monotonic() + RELOAD_TIMEOUT
    wait_core(until)
    if written(stamp_now):
        return True, None
    asked = time.time() - 1
    try:
        r = configctl('unbound', 'dnsbl')
    except (OSError, subprocess.SubprocessError) as e:
        return False, T('configctl could not be run: %s', str(e))
    if r.returncode != 0:
        return False, T('configctl unbound dnsbl failed: %s', (r.stderr or r.stdout or '').strip()[:200])
    wait_core(until)
    if written(stamp_now, asked):
        return True, None
    if core_busy():
        return False, T('the Unbound blocklist is still being rebuilt after %s s: looked at again at the next run',
                        RELOAD_TIMEOUT)
    return False, T('the Unbound blocklist does not hold what is applied yet: rebuilt again at the next run')


def describe(archive, st):
    """What the page says of an archive chosen: a list of T()."""
    parts = []
    if st.get('fetched'):
        parts.append(T('%s names, fetched %s', format(st.get('names') or 0, ','), stamp(st['fetched'])))
        if st.get('last_modified'):
            parts.append(T('the copy of UT1 of %s', st['last_modified']))
        if st.get('checked', 0) > st['fetched']:
            parts.append(T('unchanged at %s', stamp(st['checked'])))
    else:
        parts.append(T('not fetched yet'))
    if st.get('error'):
        error = st['error'] if isinstance(st['error'], (dict, str)) else str(st['error'])
        if st.get('fetched'):
            parts.append(T('not fetched at %s: %s - the last copy is kept', stamp(st['tried']), error))
        else:
            parts.append(T('not fetched at %s: %s', stamp(st['tried']), error))
    return parts


def run(now=None, apply=False):
    now = int(time.time() if now is None else now)
    status = load(STATUS, {})
    status = status if isinstance(status, dict) else {}
    for part in ('archives', 'catalogue', 'reload'):
        if not isinstance(status.get(part), dict):
            status[part] = {}
    status['archives'] = {a: st for a, st in status['archives'].items() if ID.match(a) and isinstance(st, dict)}
    # written only when it changed: a run every five minutes with nothing to do writes nothing
    before = json.dumps(status, sort_keys=True)
    conf = settings()
    if conf is None:
        status['message'] = [T('config.xml could not be read: nothing changed')]
        if json.dumps(status, sort_keys=True) != before:
            save(STATUS, status)
        return {'run': now, 'message': english(status['message'])}
    entries = catalogue()
    chosen = conf['categories'] if conf['enabled'] else []
    # UT1's catalogue while a category is chosen: once a day; and where one chosen is in no catalogue -
    # one UT1's catalogue added, which went with /var in memory - at the page's Apply or within the hour,
    # so it is not refused for good
    unknown = [cid for cid in chosen if ID.match(cid) and cid not in entries and cid not in REFUSED]
    known = status['catalogue']
    if chosen and (now >= max(known.get('checked', 0), known.get('tried', 0)) + CATALOGUE_EVERY or
                   unknown and (apply or now >= known.get('tried', 0) + CATALOGUE_RETRY)):
        fetch_catalogue(known, now)
        entries = catalogue()
    wanted, refused = {}, {}
    for cid in chosen:
        entry = entries.get(cid)
        why = why_not(cid, entry)
        if why:
            refused[cid] = why
            continue
        wanted.setdefault(entry['archive'], []).append(cid)


    pace = conf['hours'] * 3600
    outcomes = {}
    for archive in sorted(wanted):
        st = status['archives'].setdefault(archive, {})
        kept = os.path.isfile(data_path(archive))
        failed = st.get('tried', 0) > st.get('checked', 0)
        if kept and not failed:
            due = now >= st.get('checked', 0) + pace
        else:
            due = apply or not st.get('tried') or now >= st['tried'] + pace
        if due:
            outcomes[archive] = fetch(archive, wanted[archive], st, now, kept)
            if outcomes[archive] == 'failed':
                say('%s not fetched: %s%s' % (archive, english(st['error']), ' - the last copy is kept' if kept else ''))

    removed = []
    for archive in list(status['archives']):
        if archive not in wanted:
            del status['archives'][archive]
    for name in os.listdir(STATE_DIR):
        path = os.path.join(STATE_DIR, name)
        try:
            if name.endswith('.domains') and name[:-len('.domains')] not in wanted:
                os.unlink(path)
                removed.append(name[:-len('.domains')])
            elif name.startswith('.') and now - os.stat(path).st_mtime > 2 * DEADLINE + RELOAD_TIMEOUT:
                os.unlink(path)     # a temporary file a run that was stopped left
        except OSError:
            pass

    applied = {cid: archive for archive, cids in wanted.items() if os.path.isfile(data_path(archive)) for cid in cids}
    # each file's SHA-256 in ACTIVE too: a changed copy changes ACTIVE, and so the stamp of the rebuild
    active = {'categories': dict(sorted(applied.items())), 'exceptions': conf['exceptions'] if applied else [],
              'files': {a: str(status['archives'].get(a, {}).get('sha256') or '') for a in sorted(set(applied.values()))}}
    # no ACTIVE is none applied: a firewall where nothing was ever chosen gets no file and no rebuild
    need = load(ACTIVE, EMPTY) != active
    if need:
        save(ACTIVE, active)
    owed = os.path.exists(MARKER)
    need = need or owed or status['reload'].get('pending')
    if need and applied and not os.path.isfile(HANDLER):
        need = False        # nothing to rebuild with: the line says the handler is missing
    if need:
        done, error = reload_unbound(expected())
        status['reload'] = {'at': now, 'pending': not done}
        if error:
            status['reload']['error'] = error
            say(english(error))
        else:
            say('Unbound\'s blocklist rebuilt: %d categories applied' % len(applied))
            if owed:
                try:
                    os.unlink(MARKER)
                except OSError:
                    pass

    for archive, st in status['archives'].items():
        st['message'] = describe(archive, st)
    status.update(refused=refused, applied=sorted(applied), exceptions=active['exceptions'])
    parts = []
    if not conf['enabled'] and conf['categories']:
        parts.append(T('Block Lists is off: no category applied'))
    elif applied:
        parts.append(T('%s of %s categories chosen applied, %s names', len(applied), len(chosen),
                       format(sum((status['archives'][a].get('names') or 0) for a in set(applied.values())), ',')))
    elif chosen:
        parts.append(T('no category applied yet'))
    else:
        parts.append(T('no category chosen'))
    for cid, why in sorted(refused.items()):
        parts.append(T('%s not taken: %s', cid[:64], why))
    if applied and not conf['unbound']:
        parts.append(T('Unbound DNS is off: the categories have no effect until it is the resolver'))
    if applied and not os.path.isfile(HANDLER):
        parts.append(T('the Unbound handler of the plugin is missing: install the plugin again'))
    if status['reload'].get('error'):
        parts.append(status['reload']['error'])
    status['message'] = parts
    if json.dumps(status, sort_keys=True) != before:
        save(STATUS, status)
    return {'run': now, 'fetched': outcomes, 'applied': sorted(applied), 'removed': removed,
            'refused': {cid: english(why) for cid, why in refused.items()},
            'reloaded': bool(need) and not status['reload'].get('pending'), 'message': english(status['message'])}


def owe():
    """A rebuild owed to the next run (MARKER): the handler just installed is to be the one read."""
    try:
        with open(MARKER, 'a'):
            pass
    except OSError:
        pass


def installed():
    """After an install or an update: Unbound's blocklist rebuilt where categories are applied, so the
    handler just put in place is the one Unbound's data comes from - its stamp holds its source; nothing
    else. Where it cannot be done now, it is owed to the next run (MARKER)."""
    active = load(ACTIVE, {})
    if not isinstance(active, dict) or not active.get('categories'):
        return {'message': "no category applied: Unbound's blocklist left as it is"}
    done, error = reload_unbound(expected())
    if not done:
        owe()
        return {'message': english(error) + ' (owed to the next run)'}
    return {'message': "Unbound's blocklist holds the %d categories applied" % len(active['categories'])}


def busy():
    """Whether a run holds the lock now (for the page)."""
    try:
        with open(LOCK, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)
            return False
    except OSError:
        return os.path.exists(LOCK)


def page(conf, entries=None, status=None):
    """The Categories tab's rows and line, from config.xml's settings (conf, settings()) and the last
    run's STATUS: every category offered, chosen or not, with its names - those of the copy kept where
    there is one, else the catalogue's count - and the memory they would take in Unbound, an estimate
    at about bytes_per_name a name (categories.json); and why one cannot be chosen."""
    entries = catalogue() if entries is None else entries
    status = load(STATUS, {}) if status is None else status
    status = status if isinstance(status, dict) else {}
    archives = status.get('archives') if isinstance(status.get('archives'), dict) else {}
    applied = set(status.get('applied') or [])
    meta = load(SHIPPED, {})
    per_name = meta.get('bytes_per_name') if isinstance(meta, dict) else None
    per_name = per_name if isinstance(per_name, int) and per_name > 0 else 527
    chosen = set((conf or {}).get('categories') or [])
    rows = []
    for cid, entry in sorted(entries.items()):
        st = archives.get(entry['archive']) if isinstance(archives.get(entry['archive']), dict) else {}
        names = st.get('names') if st.get('fetched') else entry['names']
        rows.append({
            'id': cid, 'name': entry['name'], 'description': entry['description'], 'use': entry['use'],
            'names': names, 'counted': bool(st.get('fetched')), 'approximate': entry['approximate'] and not st.get('fetched'),
            'memory': names * per_name if isinstance(names, int) else None,
            'refused': data_text(entry['refused']) if entry['refused'] else '',
            'chosen': cid in chosen, 'applied': cid in applied,
            'state': (st.get('message') or [T('not fetched yet')]) if cid in chosen and not entry['refused'] else '',
            # name and description are msgids of categories.json where it holds the category
            'shipped': entry['source'] == 'shipped',
        })
    held = {}
    for cid in applied:
        archive = entries.get(cid, {}).get('archive', cid)
        st = archives.get(archive) if isinstance(archives.get(archive), dict) else {}
        held[archive] = st.get('names') or 0
    return {
        'rows': rows, 'chosen': sorted(chosen), 'applied': sorted(applied),
        'refused': status.get('refused') if isinstance(status.get('refused'), dict) else {},  # cid: T()
        'exceptions': (conf or {}).get('exceptions') or [],
        'names': sum(held.values()), 'memory': sum(held.values()) * per_name, 'bytes_per_name': per_name,
        'message': status.get('message') if isinstance(status.get('message'), list) else [], 'busy': busy(),
        'unbound': bool((conf or {}).get('unbound')), 'handler': os.path.isfile(HANDLER),
    }


def take(lock, wait):
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
    mode = 'installed' if '--installed' in argv else ('apply' if '--apply' in argv else 'cron')
    try:
        os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
        with open(LOCK, 'w') as lock:
            if not take(lock, WAIT[mode]):
                if mode == 'installed':
                    # a run is fetching: it, or the next, rebuilds Unbound's blocklist with the new handler
                    owe()
                    print("Block Lists: web categories: a run is going on; Unbound's blocklist is rebuilt by "
                          'the next run, within five minutes')
                    return 0
                last = load(STATUS, {})
                print(json.dumps({'message': english(last.get('message') or 'another run is fetching'), 'busy': True}))
                return 0
            if mode == 'installed':
                # for the installer's output, as fetch-frequency.php says its own
                print('Block Lists: web categories: ' + installed()['message'])
            else:
                print(json.dumps(run(apply='--apply' in argv), sort_keys=True))
    except Exception as e:      # never fail the caller: cron, the page's Apply or an installer
        say('stopped: %s' % e)
        print(json.dumps({'message': 'stopped: %s' % e}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
