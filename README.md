# Block Lists for OPNsense

Block lists in one place: addresses, DNS names, countries and JA4 fingerprints of TLS clients, gathered into one page - and on a Sophos XGS ~~cut by the coprocessor in hardware~~ a cut connection taken out of the coprocessor with its state (the coprocessor holds no address list of its own to block by - os-xgs-npu's hardware-drop research, issue 519).

> ~~**Planned - nothing here runs yet.** This repository was opened on 2026-10-22 to hold
> Block Lists as a plugin of its own. No code has been written or moved into it, and there is no
> release.~~
>
> ~~**Written, not released (2026-10-22).** The code is here; there is no release, and it has not been
> installed on an appliance yet. What was run is listed under [What is tested](#what-is-tested).~~
>
> **1.0.0, the first release (2026-10-25).** Installed and its page opened on an XGS 3300 (OPNsense
> 26.7.7) before the release; ~~no list has been applied through it yet~~ - since, on 2026-10-29 in
> qemu, three lists were applied through it, open connections cut, and a TLS connection cut by its
> JA4 fingerprint (see [What is tested](#what-is-tested)). Updated from XGS: Updates when os-xgs-npu
> is installed, or by its own self-update - see [Updates](#updates).

## What it does

**Firewall: Block Lists** (XGS: Block Lists when os-xgs-npu is installed), one page:

- **address lists** - chosen from a short catalogue of public feeds (`feeds.json`), each answered
  `200` and read as addresses on 2026-10-22: Spamhaus DROP (IPv4 and IPv6), abuse.ch Feodo Tracker,
  Emerging Threats compromised hosts, CINS Army, blocklist.de. Each becomes a URL Table alias of its
  own, `blocklists_<id>`, fetched by OPNsense once a day, with counters on;
- **countries** - one GeoIP alias, `blocklists_countries` (it needs a GeoIP source in Firewall:
  Aliases);
- **the block rules** - registered by the plugin at every filter reload (`plugins.inc.d/blocklists.inc`,
  as os-crowdsec does): inbound from a listed address, and by default outbound to one, on every
  interface, before the interface rules. They are never added to the owner's own rules, so turning
  the plugin off or removing it leaves nothing there;
- **open connections cut** - a block rule stops new connections only; with "Cut open connections"
  on, a connection already open to or from an address a list has just gained is cut within a
  minute (`cut.py`), and on a Sophos XGS taken out of the coprocessor with its state;
- **JA4** - TLS connections whose client shows a listed fingerprint are cut, read from the
  Intrusion Detection's TLS log every two seconds (`ja4_cut.py`); the page lists the fingerprints
  seen, to find the one to list (those in the log's last 64 MB, since 2026-10-29);
- **DNS lists** - OPNsense keeps them itself, in Unbound DNS: Blocklists; the page shows them beside
  the others and links there.

~~a page in the XGS section of OPNsense's menu~~ - it is under **Firewall**, beside Aliases and Rules
(under **XGS** when os-xgs-npu is installed): it writes the one and adds to the other, and it is not
for XGS appliances only.

FireHOL's level 1 is left out of the catalogue on purpose: it carries the private networks
(RFC 1918's 10/8, 192.168/16 ...), and blocked both ways it would cut a firewall off its own LAN.

The `blocklists_` prefix is reserved for the plugin: it makes and owns `blocklists_<id>` for each list
of `feeds.json` and `blocklists_countries`, and an alias of the owner's by one of those names is
rewritten or removed by its next Apply; one by another `blocklists_` name is left alone (until
2026-10-29 every `blocklists_*` alias was blocked, cut and removed as the plugin's).

## Beside os-xgs-npu

`cut.py` and `ja4_cut.py` came from os-xgs-npu (`scripts/xgs/lists_cut.py`, `scripts/xgs/ja4_cut.py`),
which has not been changed: they still run where it is installed, for the lists and fingerprints
XGS: Settings names. Here, a list or a fingerprint named there is left to os-xgs-npu, so nothing is
cut twice; everything else is this plugin's.

## Not yet, and why

- **a QUIC or DTLS client's JA4** - only a TLS client over TCP (`t...`) is cut: `ja4_cut.py` reads
  the Intrusion Detection's `tls` lines, and a QUIC (`q...`) or DTLS (`d...`) client's fingerprint
  is not among them. Since 2026-10-29 the field takes `t` fingerprints only; before, such a one was
  taken and never matched.
- **the command line's apply writes the aliases only** - `configctl blocklists apply` is the first
  step of the page's Apply, which then reloads the filter (`configctl filter reload skip_alias`), its
  template (`configctl template reload OPNsense/Filter`) and the aliases (`configctl filter
  refresh_aliases`), and runs the cuts once (`configctl blocklists cut`, `configctl blocklists ja4`).
  From a shell, run those after it, as the tests below did.
- **a fingerprint listed as the Intrusion Detection begins to log JA4** is watched from the next
  minute: until then the minute's watch has found nothing to read and ended. Listed while the
  Intrusion Detection already logs JA4, it is watched within two seconds - since 2026-10-29 the watch
  goes on through the minute with nothing listed; before, a fingerprint listed during the minute waited
  for the next one. Not yet tested.
- **the aliases outlive the plugin** - removed, it leaves them in Firewall: Aliases, blocking nothing,
  and OPNsense goes on fetching their lists; turn Enabled off and Apply before removing it
  ([Installation](#installation)).
- **no list is dropped in an XGS's hardware** - the coprocessor holds no address list of its own to
  block by (os-xgs-npu's hardware-drop research, issue 519); a cut connection is taken out of the
  coprocessor with its state.

## What is tested

On the second XGS 3300, 2026-10-22, from a copy in `/tmp`, nothing installed and config.xml not
written:

- every PHP file and the rules hook pass `php -l`; both Volt templates compile;
- `status.py` reads the configuration and pf's tables: no list chosen, the catalogue, Unbound;
- `cut.py` (its state pointed at `/tmp`): "no list watched";
- `ja4_cut.py`: its settings read ("Intrusion Detection is off" there), and `--seen` listed the
  fingerprints in the log, the most frequent first;
- the rules hook, called as a filter reload calls it: no rule, as no list was chosen.

On the first XGS 3300, 2026-10-25, OPNsense 26.7.7 with os-xgs-npu installed, before the release:

- installed by `install/install.sh`: rc 0, its PHP passing `php -l` in the installer;
- the page opened in the browser, its summary cards reading the status;
- its menu place: under **XGS** with os-xgs-npu installed; in its own section, **Firewall**, when
  os-xgs-npu's menu file was set aside, and back under XGS when it was put back (`place-menu.sh`).

On a plain OPNsense 26.7 in qemu, 2026-10-29: the nano image with nothing of os-xgs-npu on it, its
WAN reaching the internet. Three lists - Spamhaus DROP, Feodo Tracker and CINS Army - were chosen
through the plugin's model and applied with `configctl blocklists apply`, then the filter was
reloaded and the aliases refreshed.

- **The package.** `os-blocklists-1.0.0.pkg` and `SHA256SUMS` were fetched from the release and the
  sum checked OK. `pkg add` returned 0, and the page is under Firewall > Block Lists.
- **The aliases.** apply answered `blocklists_spamhaus_drop: added`, `blocklists_feodo: added` and
  `blocklists_cins_army: added`, and all three are in config.xml.
- **The lists fetched.** OPNsense filled the tables: CINS Army with 15,000 entries, Spamhaus DROP
  with 1,758 and Feodo Tracker with 1, the day's list.
- **The rules.** pf holds `block drop in quick inet from <blocklists_...>` and `block drop out quick
  inet from any to <blocklists_...>` for each list.
- **A cut.** Three states were open to the host's web server. Its address was added to the Feodo
  table, as a list gaining it would, and `cut.py` was run: it found 1 new entry and cut the 3 open
  connections, and none were left. The log reads `blocklists_feodo: 1 new entry of 2, 3 open
  connections cut`.

On two such machines in qemu the same day, the second a copy of the first, joined by a cable of
their own. Intrusion Detection ran on the first in IDS mode, only listening, on that cable, its eve
TLS log carrying the JA4 field. It was set through its own model and applied as its page's Apply
does (the template, the rules installed, the service started). The second machine opened TLS
connections to the first one's web server.

- **The fingerprints seen.** `ja4_cut.py --seen` listed two from the second machine: `fetch`'s,
  over three connections, and `openssl s_client`'s, over one.
- **A JA4 cut.** A TLS connection was held open by `openssl s_client`, its request sent 12 s after
  the handshake. Not listed, it was answered (`HTTP/1.0 200 OK`). Then s_client's fingerprint,
  `t13d301100_1d37bd780c83_8e6e362c5eac`, was listed through the plugin's model and the page's
  Apply. The next such connection was cut 2 s after its handshake by the job that reads the log
  every two seconds - the system log names the fingerprint and the connection, `cut (1 state)` -
  and its request was never answered. Once the fingerprint was removed and applied again, the
  connection was answered again.

Not tested: ~~`apply.php` writing the aliases (it saves config.xml), the rules with lists in them,
the lists fetched, a cut~~ (on 2026-10-29 in qemu, above), ~~a JA4 cut through this plugin~~ (on
2026-10-29 in qemu, above), ~~the page in a browser~~ (opened on 2026-10-25, above), ~~the package
(built by `tools/make-package.sh`, added with pkg), and an install on a plain OPNsense, without
os-xgs-npu~~ (on 2026-10-29 in qemu, above). ~~The JA4 cut needs Intrusion Detection running with
its TLS log, which was not set up here.~~ It was, on a second machine's connections (above).

Written after the tests above and not yet tested (2026-10-29): only the plugin's own alias names
taken for its own; a list watched again cutting what it names, and its snapshot written only when
its table changed; the JA4 watch going on through the minute with nothing listed, the log read a
line at a time, and the field taking `t` fingerprints only; the checks before the copy; and the
removal's stopping of a running cut, its deleting of the state and its emptying of stale tables.

## Installation

It is not in the OPNsense plugin repository, so there is no `pkg install os-blocklists`.

**From a checkout** of this repository, on the firewall, as root:

```sh
sh install/install.sh
```

It ~~copies `src/` onto `/usr/local` (the rules hook and the cron entry for the cuts with it), checks
the PHP and the rules hook with `php -l` and the Python with `py_compile`,~~ checks the PHP and the
rules hook with `php -l` and the Python with `py_compile` before anything is copied (since
2026-10-29: checked after the copy, a hook with an error stayed where every filter reload includes
it), then copies `src/` onto `/usr/local` (the rules hook and the cron entry for the cuts with it),
puts the page in the menu (`place-menu.sh`: XGS with os-xgs-npu, Firewall without) and records the
commit for the self-update. Safe to run again: the settings in config.xml are kept. Nothing is
blocked until lists are chosen on the page and applied. `sh install/uninstall.sh` removes the plugin
and its rules; the `blocklists_*` aliases stay in Firewall: Aliases, blocking nothing, and OPNsense
goes on fetching their lists once a day.

**Before removing it**, turn **Enabled** off and **Apply** to take the aliases away as well: the
Apply removes each alias of the plugin's that nothing else names (one that a rule of the owner's
names is switched off instead). The removal itself, by the script or by pkg, stops a cut that is
running, deletes what the cuts kept in `/var/db/os-blocklists`, and empties the pf table of each of
the plugin's aliases that is gone, when no rule uses it - a table outlives its alias, and went on
holding the addresses (all of this since 2026-10-29).

**From a release's package.** A release carries `os-blocklists-<version>.pkg` and `SHA256SUMS`,
built by `tools/make-package.sh` in the release workflow; ~~installing it has not been tested yet~~
it was added with pkg on a plain OPNsense on 2026-10-29 - see [What is tested](#what-is-tested).
Check it and read it before adding it, as root:

```sh
sha256sum -c SHA256SUMS
pkg info -lF os-blocklists-1.0.0.pkg      # every file it will write
pkg add os-blocklists-1.0.0.pkg
```

`pkg delete os-blocklists` takes the rules hook with the files and reloads the filter, so the rules
leave pf; the settings and the `blocklists_*` aliases stay, blocking nothing (see **Before removing
it**, above). The same package is built on the firewall from a checkout with
`sh tools/make-package.sh -o /tmp`.

## Updates

Taken by hand, to this repository's **releases**: from **XGS: Updates**, its *Plugins* tab, where an
[os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) that lists this plugin is installed - the
tab calls `/usr/local/opnsense/scripts/blocklists/self-update.py`, with `check` to ask and without
it to install - or by running that script. The plugin's cron entry runs the cuts every minute, never
the self-update; no cron entry runs that. It asks GitHub for the latest release and, when that is
ahead of what is installed, downloads it and runs the `install/install.sh` it carries - the same
script a hand install runs. A change merged on `main` reaches an installed firewall when it is
released, not before.

- **Only forward.** What is installed is recorded in `/usr/local/share/os-blocklists/installed.json`
  by the installer: the commit, from a git checkout or from the `.source-commit` stamp an update
  leaves in the tree. A firewall running something newer than the release is not taken back; an
  install with no commit recorded takes the latest release once.
- **A package install records no commit**, so its first self-update takes the latest release and
  installs it with `install/install.sh`, outside pkg. A package is updated with a newer package
  instead: `pkg add -f`.
- **What happened** is in the system log as `self-update`, in
  `/usr/local/share/os-blocklists/update.json`, and the installer's output in `update.log` beside it.
- `self-update.py check` says what it would do and changes nothing.

~~Not tested yet: an update taken this way - 1.0.0 is the first release, so none has been ahead of
an installed copy.~~ Tested on 2026-10-29 on a plain OPNsense 26.7 in qemu, where the package had
been added with pkg, which records no commit: `self-update.py check` found the release `v1.0.0`
(0869feba684d) and nothing installed to compare it with, so to be taken. `self-update.py` fetched
its source, ran its `install/install.sh` and answered `updated to v1.0.0 (0869feba684d)`, which the
system log has too. `installed.json` then recorded that commit, from the stamp, and a second check
found it identical: nothing to take. Not yet: a release ahead of the one installed - 1.0.0 is
still the only release.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates** (listed there since os-xgs-npu 0.1.0-alpha.8, and installed with the project's update since 0.1.0-alpha.8.2), its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE). The lists are their publishers', under their own terms, linked
from the page; the plugin fetches them and redistributes none.
