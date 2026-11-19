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
an alert Suricata logged as blocked - its IPS policy dropped what that side sent - for "Keep an address"
minutes after its last such drop (general.ids_minutes: 60 by default, 5 to 10080). Blocked alerts are
logged only in IPS mode (Netmap or Divert); in IDS mode, which listens, none is, and the page says so.
An alert's source can be forged, so only an alert that shows a real connection with it enters (the review
of 2026-11-19): over TCP; not one of Suricata's own decoder, stream and application-layer event rules
(signature ids 2200000-2299999), which drop one frame; and only where Suricata recognised the connection's
application protocol (app_proto, neither absent nor "failed") - which it does on a stream it saw
established, the handshake completed with the real address - and, where the alert carries its flow's
counts, with packets both ways past the handshake (flow.pkts_toserver 2 or more, flow.pkts_toclient 1 or
more). A lone SYN - a scan rule's, or one forged with another's address - never enters.

WHAT NEVER ENTERS (Guard): the firewall's own addresses - every interface's from ifconfig, read again
before anything enters where the last reading is older than OWN_FRESH seconds; its virtual IPs and the
external addresses of its 1:1 and outbound NAT, from config.xml - none at all where ifconfig cannot be
read; loopback, multicast, unspecified, link-local, this network, reserved and broadcast; what the
firewall depends on or is managed from: its gateways and their monitor addresses (and a dynamic gateway's,
from /tmp), its DNS servers (config.xml, /etc/resolv.conf, Unbound's DNS over TLS servers), its VPN peers
(IPsec remote gateways, WireGuard endpoints, OpenVPN remotes - a peer named by its host name resolved),
and an address with a live pf state to the firewall's own web GUI or SSH port; and "Never block"
(general.ids_never), the owner's own addresses and networks. With "Outside addresses only" on (the
default), nothing inside the firewall's own networks either: every network connected to it (each
interface's address and prefix), its delegated IPv6 prefixes, its VPN tunnel and remote networks, its
static routes' networks, and the private ones (RFC 1918's 10/8, 172.16/12 and 192.168/16; shared
100.64/10; IPv6's unique local fc00::/7). Every reading takes out an address held that is now one of
these, and so does a change of the settings.

THE TABLE is blocklists_ids, an external alias of the plugin's (apply.php makes it while the setting is
on, as ThreatFox's): OPNsense declares the table at every filter reload and leaves its addresses to this
script, which puts the list into it (pfctl -T replace -f -, the list on stdin) when it changes, and looks
once a minute to put back what it lost. The rules hook blocks it as the plugin's other lists, in the
Direction the page says. With "Cut open connections" on, a reading cuts the states of the addresses it
just entered - their ids from pfctl -ss -vv, killed one by one - and, where os-xgs-npu is installed and
outbound is blocked too, drops their connections on the coprocessor first; cut.py, every minute, hands
an address back from hardware when it leaves. At most BUDGET addresses enter in one reading (the rest at
the next) and CAP are held: past it, those whose last drop is the oldest leave first. One line in the
system log a reading.

THE LOG is read from where the last reading stopped (its inode, offset and first bytes, kept in memory and
in STATE). Rotated - the inode changed - the old file, now eve.json.0, is read to its end from that
offset first, then the new one from its start; truncated in place, or emptied and grown again past the
offset, it is read from its start. A last line not yet ended is left for the next reading. Turned on, it
begins at the log's end: nothing logged before is taken. Turned off - or Block Lists off - every address
leaves at the next run and the table is emptied. STATE is in /var/db/os-blocklists: where /var is in
memory, a reboot starts it empty.

Its texts for the page are categories.T(), translated by the page's controller. Never fails its caller:
prints one JSON object and exits 0; what it could not do is in the answer, in STATE and in the system log,
under blocklists-ids.
"""
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
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
RESOLV = '/etc/resolv.conf'
PREFIXES = '/tmp/*_prefixv6'                    # a delegated IPv6 prefix, as OPNsense keeps it
ROUTERS = ('/tmp/*_router', '/tmp/*_routerv6')  # a dynamic gateway's address, as OPNsense keeps it
TAG = 'blocklists-ids'
ALIAS = 'blocklists_ids'
EVERY = 3                   # seconds between two readings of the log in --for
CAP = 10000                 # addresses the table may hold; the oldest leave first
BUDGET = 200                # addresses one reading may enter; the rest at the next
MINUTES = (60, 5, 10080)    # "Keep an address": its default, its least and its most
OWN_FRESH = 3               # seconds: the firewall's addresses read again before entering, when older
RUNTIME_EVERY = 60          # seconds between two readings of them otherwise
PEERS_EVERY = 600           # seconds between two resolutions of VPN peers named by host name
RESOLVE_WAIT = 3            # seconds one resolution may take
REFILTER_EVERY = 3          # readings between two checks of every address held against the guard
CHECK_TABLE = 60            # seconds between two looks at pf's table when the list has not changed
LOCK_WAIT = 30              # seconds the minute's run waits for the last one to end
REMOVE_WAIT = 2 * EVERY + 2  # seconds --remove waits for the minute's watcher to take its request
HEAD = 256                  # bytes of the log's start kept, to tell it from a log emptied and grown again
# Suricata's capture modes that make it an IPS (OPNsense 26.7's IDS model, general.mode: pcap is IDS);
# general.ips is older OPNsense's, read as os-xgs-npu reads it
IPS_MODES = ('netmap', 'divert')
# Suricata's own event rules - decoder, stream and application-layer events - take signature ids
# 2200000-2299999 by its convention, and drop the frame, not the connection (os-xgs-npu's ja4_cut.py)
EVENT_SIDS = range(2200000, 2300000)
NOT_DETECTED = ('', 'failed', 'unknown')        # app_proto values that show no protocol recognised


def network(text):
    """A network as RFCs write them, IPv4 shortened: '10/8' is 10.0.0.0/8 (as threatfox.py writes them)."""
    if ':' not in text:
        address, length = text.split('/')
        text = '.'.join((address.split('.') + ['0', '0', '0'])[:4]) + '/' + length
    return str(ipaddress.ip_network(text))


# never entered: no host has them, or every host does - this network, loopback, link-local, multicast,
# reserved and broadcast; IPv6's unspecified, loopback, link-local and multicast
NEVER = [network(n) for n in ('0/8', '127/8', '169.254/16', '224/4', '240/4', '::/128', '::1/128', 'fe80::/10', 'ff00::/8')]
# inside with "Outside addresses only", whatever the firewall's own networks: RFC 1918, shared (RFC 6598,
# VPN overlays too) and IPv6's unique local
PRIVATE = [network(n) for n in ('10/8', '172.16/12', '192.168/16', '100.64/10', 'fc00::/7')]
INET = re.compile(r'^\s+inet\s+([0-9.]+)(?:\s+-->\s+([0-9.]+))?\s+netmask\s+(0x[0-9a-fA-F]+)')
INET6 = re.compile(r'^\s+inet6\s+([0-9A-Fa-f:.]+)(?:%\S+)?(?:\s+-->\s+([0-9A-Fa-f:.]+)(?:%\S+)?)?\s+prefixlen\s+(\d+)')
HOSTNAME = re.compile(r'^(?=.{1,253}\Z)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z')


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


def networks_in(text):
    """The addresses and networks written in a field - commas, spaces or new lines between - as networks;
    what is not one (a host name, a port, a word) left out."""
    found = []
    for token in re.split(r'[\s,;]+', text or ''):
        token = token.strip().strip('[]')
        if not token:
            continue
        try:
            found.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            continue
    return found


def hosts_in(text):
    """The peers written in a field - addresses, or host names to resolve - each without a port."""
    found = []
    for token in re.split(r'[\s,;]+', text or ''):
        token = token.strip()
        if not token:
            continue
        m = re.match(r'^\[([0-9A-Fa-f:.]+)\](?::\d+)?$', token)
        if m:
            token = m.group(1)
        elif token.count(':') == 1:
            token = token.split(':')[0]
        try:
            found.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            if HOSTNAME.match(token) and not token.replace('.', '').isdigit():
                found.append(token.lower())
    return found


def texts(root, *paths):
    """Every text of the elements at each path (ElementTree's './/' paths), none of them empty."""
    out = []
    for path in paths:
        for element in root.findall(path):
            if element.text and element.text.strip():
                out.append(element.text.strip())
    return out


def settings(path=None):
    """What config.xml says: {'read', 'on', 'minutes', 'outside', 'never' (networks), 'cut', 'problem'
    (T or None), 'alias' ('ready', 'missing', 'off', 'not external'), 'root' (the tree, or None)}."""
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return {'read': False, 'on': False, 'minutes': MINUTES[0], 'outside': True, 'never': [], 'cut': False,
                'problem': T('config.xml could not be read'), 'alias': 'missing', 'root': None}
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
            'minutes': minutes, 'outside': value('ids_outside', '1') != '0', 'never': networks_in(value('ids_never', '')),
            'cut': value('cut', '0') == '1', 'problem': problem, 'alias': state, 'root': root}


def from_config(root):
    """What config.xml says the firewall is, has and depends on: {'own', 'inside', 'depends' (networks),
    'names' (VPN peers by host name), 'ports' (the web GUI's and SSH's)}."""
    out = {'own': [], 'inside': [], 'depends': [], 'names': [], 'ports': set()}
    if root is None:
        return out
    # its own: virtual IPs (Proxy ARP and Other are on no interface), 1:1 and outbound NAT's external sides
    for vip in root.findall('.//virtualip/vip'):
        subnet, bits = (vip.findtext('subnet') or '').strip(), (vip.findtext('subnet_bits') or '').strip()
        whole = networks_in(subnet + ('/' + bits if bits and '/' not in subnet else ''))
        if (vip.findtext('mode') or '').strip() == 'proxyarp':
            out['own'] += whole             # Proxy ARP answers for every address of its network
        else:
            out['own'] += networks_in(subnet.split('/')[0])
            out['inside'] += whole
    for table in [*root.iter('onetoone'), *root.iter('outbound'), *root.iter('snatrules')]:
        for tag in ('external', 'target'):
            for element in table.iter(tag):
                out['own'] += networks_in(element.text or '')
    # inside: VPN tunnel and remote networks, static routes' networks
    out['inside'] += [n for t in texts(root, './/openvpn/openvpn-server/tunnel_network', './/openvpn/openvpn-server/tunnel_networkv6',
                                       './/openvpn/openvpn-server/local_network', './/openvpn/openvpn-server/local_networkv6',
                                       './/openvpn/openvpn-server/remote_network', './/openvpn/openvpn-server/remote_networkv6',
                                       './/openvpn/openvpn-client/tunnel_network', './/openvpn/openvpn-client/tunnel_networkv6',
                                       './/openvpn/openvpn-client/remote_network', './/openvpn/openvpn-client/remote_networkv6',
                                       './/OpenVPN/Instances/Instance/server', './/OpenVPN/Instances/Instance/server_ipv6',
                                       './/OpenVPN/Instances/Instance/push_route', './/OpenVPN/Instances/Instance/route',
                                       './/wireguard/server/servers/server/tunneladdress',
                                       './/wireguard/client/clients/client/tunneladdress',
                                       './/Swanctl/children/child/local_ts', './/Swanctl/children/child/remote_ts',
                                       './/ipsec/phase2/localid/address', './/ipsec/phase2/remoteid/address',
                                       './/staticroutes/route/network')
                      for n in networks_in(t)]
    # what it depends on: gateways and their monitors, DNS servers, VPN peers
    for t in texts(root, './/gateway_item/gateway', './/gateway_item/monitor', './/system/dnsserver',
                   './/unboundplus/dots/dot/server', './/ipsec/phase1/remote-gateway',
                   './/Swanctl/Connections/Connection/remote_addrs', './/wireguard/client/clients/client/serveraddress',
                   './/openvpn/openvpn-client/server_addr', './/OpenVPN/Instances/Instance/remote'):
        for peer in hosts_in(t):
            (out['names'] if '/' not in peer else out['depends']).append(peer)
    # the ports it is managed by
    webgui = root.find('system/webgui')
    protocol = (webgui.findtext('protocol') if webgui is not None else '') or 'https'
    port = (webgui.findtext('port') if webgui is not None else '') or ('443' if protocol == 'https' else '80')
    ssh = (root.findtext('system/ssh/port') or '22').strip()
    for p in (port, ssh):
        if p.strip().isdigit():
            out['ports'].add(int(p.strip()))
    return out


def ifconfig_text():
    """`ifconfig -a`, or None where it cannot be run."""
    try:
        r = subprocess.run([IFCONFIG, '-a'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def interfaces_of(text):
    """(addresses, networks) of `ifconfig -a`'s inet and inet6 lines: each interface's address, and the
    network its address and netmask or prefix make - a point-to-point one's far end too."""
    addresses, networks = set(), set()
    for line in text.splitlines():
        m = INET.match(line)
        if m:
            mask = bin(int(m.group(3), 16)).count('1')
            far, address = m.group(2), m.group(1)
        else:
            m = INET6.match(line)
            if not m:
                continue
            address, far, mask = m.group(1), m.group(2), int(m.group(3))
        try:
            addresses.add(str(ipaddress.ip_address(address)))
            networks.add(str(ipaddress.ip_network('%s/%s' % (address, mask), strict=False)))
            if far:
                networks.add(str(ipaddress.ip_network(far)))
        except ValueError:
            continue
    return addresses, networks


def read_files(pattern, parse):
    found = []
    for path in glob.glob(pattern):
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                found += parse(fh.read())
        except OSError:
            continue
    return found


def nameservers(text):
    return [n for line in text.splitlines() if line.strip().startswith('nameserver')
            for n in networks_in(line.split(None, 1)[1] if len(line.split()) > 1 else '')]


def resolve(names, wait=RESOLVE_WAIT):
    """Host names resolved to their addresses, all in RESOLVE_WAIT seconds at the most; one not resolved
    in time, or not at all, left out."""
    found = set()

    def one(name):
        try:
            for info in socket.getaddrinfo(name, None):
                found.add(str(ipaddress.ip_network(info[4][0].split('%')[0])))
        except (OSError, ValueError, UnicodeError):
            pass

    threads = [threading.Thread(target=one, args=(n,), daemon=True) for n in names]
    for t in threads:
        t.start()
    until = time.monotonic() + wait
    for t in threads:
        t.join(max(0, until - time.monotonic()))
    return set(found)


def pf_states():
    """`pfctl -ss -vv`, or '' where it cannot be read."""
    try:
        return subprocess.run([PFCTL, '-ss', '-vv'], capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


class Guard:
    """What never enters, and what is inside: from config.xml (again when it changes), from what the
    firewall holds now (ifconfig, /tmp, resolv.conf; again before entering when older than OWN_FRESH, and
    every RUNTIME_EVERY), and from pf's states (who has one to its web GUI or SSH; read before entering)."""

    def __init__(self):
        self.config = from_config(None)
        self.runtime_at = self.peers_at = self.states_at = None
        self.addresses = None           # the firewall's own, from ifconfig; None where it cannot be read
        self.connected, self.runtime, self.peers, self.managers = set(), set(), set(), set()
        self.text = ''
        self.build()

    def configure(self, root):
        self.config = from_config(root)
        self.peers_at = None
        self.build()

    def refresh(self, now, max_age, states=False):
        """What the firewall holds now, read again where older than max_age; pf's states too."""
        if self.runtime_at is None or now - self.runtime_at >= max_age:
            self.runtime_at = now
            text = ifconfig_text()
            if text is None:
                self.addresses, self.connected = None, set()
            else:
                self.addresses, self.connected = interfaces_of(text)
            self.runtime = set(read_files(PREFIXES, networks_in))
            self.dynamic = set(read_files(ROUTERS[0], networks_in) + read_files(ROUTERS[1], networks_in))
            self.dns = set(read_files(RESOLV, nameservers))
        if self.config['names'] and (self.peers_at is None or now - self.peers_at >= PEERS_EVERY):
            self.peers_at = now
            self.peers = resolve(self.config['names'])
        if states and (self.states_at is None or now - self.states_at >= OWN_FRESH):
            self.states_at = now
            self.text = pf_states()
            self.build()                # the firewall's addresses just read, to tell its own end of a state
            self.managers = self.managing(self.text)
        self.build()

    def managing(self, text):
        """The far ends of pf's states to the firewall's own web GUI or SSH port: who manages it now."""
        own = self.own
        found = set()
        for _sid, _proto, ends, _age, over in ja4_cut.states(text):
            if over:
                continue
            if any(port in self.config['ports'] and address in own for address, port in ends):
                found |= {address for address, _port in ends if address not in own}
        return found

    def build(self):
        addresses = self.addresses or set()
        self.own = cut.Matcher(sorted(addresses) + self.config['own'])
        self.never = cut.Matcher(NEVER)
        self.depends = cut.Matcher(self.config['depends'] + sorted(getattr(self, 'dynamic', set()))
                                   + sorted(getattr(self, 'dns', set())) + sorted(self.peers) + sorted(self.managers))
        self.inside = cut.Matcher(PRIVATE + sorted(self.connected) + sorted(self.runtime) + self.config['inside'])

    def never_block(self, networks):
        """The owner's Never block as a Matcher, made again only when it changes."""
        if getattr(self, '_never_block', (None,))[0] != networks:
            self._never_block = (list(networks), cut.Matcher(networks))
        return self._never_block[1]

    def why(self, address, conf):
        """Why an address never enters, a T(), or None where it may."""
        if self.addresses is None:
            return T('the firewall addresses could not be read')
        if address in self.own:
            return T('an address of the firewall')
        if address in self.never:
            return T('an address no host has, or every host has')
        if address in self.depends:
            return T('a gateway, a DNS server or a VPN peer of the firewall, or an address managing it')
        if conf['never'] and address in self.never_block(conf['never']):
            return T('in Never block')
        if conf['outside'] and address in self.inside:
            return T('inside the networks of the firewall (Outside addresses only)')
        return None


def why_not(event):
    """Why a blocked alert is not one to enter by its kind, a T(), or None where it is: TCP, not an event
    rule, and a connection Suricata saw established (see the top)."""
    if event['proto'] != 'tcp':
        return T('not TCP')
    if event['sid'] in EVENT_SIDS:
        return T('an event rule of Suricata, which drops one frame')
    app = str(event.get('app_proto') or '').strip().lower()
    if app in NOT_DETECTED:
        return T('a connection not seen established: no application protocol recognised')
    flow = event.get('flow')
    if isinstance(flow, dict) and ('pkts_toserver' in flow or 'pkts_toclient' in flow):
        try:
            ok = int(flow.get('pkts_toserver') or 0) >= 2 and int(flow.get('pkts_toclient') or 0) >= 1
        except (TypeError, ValueError):
            ok = False
        if not ok:
            return T('a connection not seen established: no packets both ways past the handshake')
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
                'src': str(address), 'proto': str(ev.get('proto', '')).lower(), 'at': ja4_cut.stamp(ev.get('timestamp')),
                'sid': int(alert.get('signature_id') or 0), 'app_proto': ev.get('app_proto'),
                'flow': ev.get('flow') if isinstance(ev.get('flow'), dict) else None,
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


def kill(state_id):
    try:
        return subprocess.run([PFCTL, '-k', 'id', '-k', state_id], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def cut_now(addresses, text):
    """The open connections of the addresses just entered cut: on the coprocessor first where os-xgs-npu
    is installed and outbound is blocked too (cut.py's rule), then their pf states by id - those of these
    addresses only, from the pf states read for this reading (text). (states cut, dropped in hardware or
    None)."""
    dropped = cut.drop_in_hardware(addresses) if cut.outbound_blocked() else None
    match = cut.Matcher(addresses)
    killed = 0
    for state_id, addrs in cut.states(text):
        if any(a in match for a in addrs) and kill(state_id):
            killed += 1
    return killed, dropped


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


def head_of(path, length=HEAD):
    """[how many bytes, their digest] of the log's start - HEAD at the most: the same file grown keeps
    them, another written over it (emptied in place and grown again) does not."""
    try:
        with open(path, 'rb') as fh:
            data = fh.read(length)
    except OSError:
        return None
    return [len(data), hashlib.sha1(data).hexdigest()]


class Watch:
    """The readings of one run: the state in memory, saved when the addresses change and at the end."""

    def __init__(self, guard=None):
        state = load(STATE, {})
        self.state = state if isinstance(state, dict) else {}
        if not isinstance(self.state.get('entries'), dict):
            self.state['entries'] = {}
        self.guard = guard or Guard()
        self.config_mtime, self.conf = None, None
        self.table_at, self.readings, self.changed = None, 0, False
        self.settings_key = None

    def reload(self, now):
        try:
            m = os.stat(CONFIG).st_mtime
        except OSError:
            m = None
        if m != self.config_mtime or self.conf is None:
            self.config_mtime, self.conf = m, settings()
            self.guard.configure(self.conf['root'])
        self.guard.refresh(now, RUNTIME_EVERY)

    def once(self, now=None):
        now = time.time() if now is None else now
        self.reload(now)
        self.readings += 1
        conf, st, entries = self.conf, self.state, self.state['entries']
        summary = {'run': int(now), 'entered': [], 'again': 0, 'expired': 0, 'removed': 0, 'capped': 0,
                   'refiltered': 0, 'refused': {}, 'deferred': 0}
        changed = False
        if not conf['on']:
            # off: every address leaves, the table is emptied, and the log is taken from its end when it
            # is turned on again
            requested()
            if entries or st.get('since'):
                entries.clear()
                st.update(since=None, inode=None, offset=None, head=None)
                flush()
                changed = True
            self.changed = changed
            return summary
        if not st.get('since'):
            # turned on now: the log from its end, nothing logged before taken
            st['since'] = now
            try:
                info = os.stat(EVE)
                st['inode'], st['offset'], st['head'] = info.st_ino, info.st_size, head_of(EVE)
            except OSError:
                st['inode'], st['offset'], st['head'] = None, 0, None
            changed = True
        keep = conf['minutes'] * 60
        # held as long as the setting says now, from each address's last drop
        for address in list(entries):
            e = entries[address]
            e['until'] = (e.get('seen') or e.get('last') or now) + keep
            if e['until'] <= now:
                del entries[address]
                summary['expired'] += 1
                changed = True
        changed |= self.read(now, summary)
        # taken out after the reading, so one just taken out does not enter again from an older line
        for address in requested():
            if entries.pop(address, None) is not None:
                summary['removed'] += 1
                changed = True
        # every address held checked again against the guard: at a change of the settings, and every
        # REFILTER_EVERY readings (what the firewall holds may have changed)
        key = json.dumps([conf['outside'], conf['never']])
        if entries and (key != self.settings_key or self.readings % REFILTER_EVERY == 0):
            for address in list(entries):
                if self.guard.why(address, conf) is not None:
                    del entries[address]
                    summary['refiltered'] += 1
                    changed = True
        self.settings_key = key
        if len(entries) > CAP:
            for address in sorted(entries, key=lambda a: (entries[a].get('seen', 0), a))[:len(entries) - CAP]:
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
            elif summary['entered'] and conf['cut']:
                killed, dropped = cut_now(summary['entered'], self.guard.text or pf_states())
                summary['cut'] = killed
                if dropped is not None:
                    summary['dropped'] = dropped
        if table or self.table_at == now or conf['alias'] != 'ready':
            st['table'] = table
        if summary['entered']:
            # one line a reading, however many entered
            shown = summary['entered'][:10]
            log('%d entered for %d minutes: %s%s' % (len(summary['entered']), conf['minutes'], ', '.join(shown),
                                                    ' and %d more' % (len(summary['entered']) - 10)
                                                    if len(summary['entered']) > 10 else ''))
        self.changed = changed
        return summary

    def position(self):
        """(path, start) pairs to read now: the old log's rest after a rotation, then the log."""
        st = self.state
        try:
            info = os.stat(EVE)
        except OSError:
            return None, []
        offset = st.get('offset') or 0
        if st.get('inode') == info.st_ino:
            head = st.get('head') if isinstance(st.get('head'), list) and len(st['head']) == 2 else None
            if info.st_size < offset or (offset and head and head[0] and head_of(EVE, head[0]) != head):
                return info, [(EVE, 0)]     # emptied in place, perhaps grown again: from its start
            return info, [(EVE, offset)]
        parts = []
        old = EVE + '.0'
        try:
            if st.get('inode') is not None and os.stat(old).st_ino == st['inode'] and os.path.getsize(old) > offset:
                parts.append((old, offset))     # rotated: its rest first
        except OSError:
            pass
        return info, parts + [(EVE, 0)]

    def read(self, now, summary):
        """The log from where the last reading stopped: each blocked alert taken in or refused; BUDGET new
        addresses at the most, the rest left for the next reading."""
        conf, st, entries = self.conf, self.state, self.state['entries']
        info, parts = self.position()
        if info is None:
            summary['error'] = T('no Suricata log at %s', EVE)
            return False
        if parts == [(EVE, st.get('offset') or 0)] and (st.get('offset') or 0) >= info.st_size:
            return False
        changed = False
        fresh = False
        for path, start in parts:
            at, stopped = {}, False
            with open(path, 'rb') as fh:
                fh.seek(start)
                for event in alerts(fh, at):
                    if event['at'] is not None and event['at'] < st['since']:
                        continue        # logged before it was turned on
                    why = why_not(event)
                    if why is None and event['src'] not in entries:
                        if not fresh:
                            # what the firewall is and who manages it, read again now, before anything enters
                            self.guard.refresh(now, OWN_FRESH, states=True)
                            fresh = True
                        why = self.guard.why(event['src'], conf)
                    if why is not None:
                        key = why['text']
                        summary['refused'][key] = summary['refused'].get(key, 0) + 1
                        continue
                    address = event['src']
                    entry = entries.get(address)
                    if entry is None:
                        if len(summary['entered']) >= BUDGET:
                            summary['deferred'] += 1
                            stopped = True
                            break       # the rest at the next reading, from this line
                        entries[address] = entry = {'at': event['at'] or now, 'count': 0}
                        summary['entered'].append(address)
                    else:
                        summary['again'] += 1
                    entry.update(last=event['at'] or now, seen=now, until=now + conf['minutes'] * 60,
                                 sid=event['sid'], msg=event['msg'], count=entry.get('count', 0) + 1)
                    changed = True
            if stopped:
                # left at this line: it is read again at the next reading, in this file
                if path == EVE:
                    st['inode'], st['offset'] = info.st_ino, event['offset']
                else:
                    st['offset'] = event['offset']      # the old log's rest, its inode kept
                st['head'] = head_of(EVE) if path == EVE else st.get('head')
                return changed
        st['inode'], st['offset'], st['head'] = info.st_ino, at.get('end', parts[-1][1]), head_of(EVE)
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
    # the line's first part as things are now, not as the last run's end recorded them: that record is written once a
    # minute under cron, and an address entered since would read "0 held" beside a grid holding it (the lab,
    # 2026-11-19); the rest of the record - a problem, the alias, the table's error - kept as recorded
    held = T('%s addresses held, each for %s minutes after its last drop', format(len(entries), ','), conf['minutes'])
    off = T('off: nothing the IPS drops is entered')
    recorded = state.get('message') if isinstance(state.get('message'), list) else []
    rest = [p for p in recorded if not (isinstance(p, dict) and p.get('text') in (held['text'], off['text']))]
    return {'on': conf['on'], 'minutes': conf['minutes'], 'outside': conf['outside'], 'problem': conf['problem'],
            'alias': conf['alias'], 'entries': len(entries) if conf['on'] else 0,
            'message': [held if conf['on'] else off] + (rest if conf['on'] else []),
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
    w.state['last'] = {k: summary[k] for k in ('run', 'expired', 'removed', 'capped', 'refiltered', 'deferred')
                       if k in summary}
    w.state['last'].update(entered=len(summary.get('entered', [])), refused=summary.get('refused', {}))
    w.save()
    return dict(summary, message=english(w.state['message']))


def run_once():
    w = Watch()
    return finish(w, w.once())


def main(argv):
    started = time.monotonic()
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
            # the minute's run waits for the last one to end, at the turn of the minute, and then reads
            # through what is left of its own minute - the log from where the last one stopped
            if not take(lock, LOCK_WAIT if seconds else 10):
                print(json.dumps({'message': english(load(STATE, {}).get('message') or []), 'busy': True}))
                return 0
            w = Watch()
            until = started + seconds
            total = {'entered': [], 'expired': 0, 'removed': 0, 'capped': 0, 'refiltered': 0, 'deferred': 0, 'refused': {}}
            while True:
                summary = w.once()
                for key in ('expired', 'removed', 'capped', 'refiltered', 'deferred'):
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
