#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""cut.py and ja4_cut.py with os-xgs-npu's hardware drop: a fake hwdrop.py, in a temporary folder of its
own, stands in for /usr/local/opnsense/scripts/xgs/hwdrop.py, and pfctl and logger are stand-ins too.
No OPNsense, no network, no root:

    python3 tools/test-hwdrop.py

What is checked: without hwdrop.py nothing changes; with it, it is called once a run - before the
first pf state is killed - with every list's new entries (cut.py) or each cut state's ends and
protocol (ja4_cut.py); its count is in the summary, the message and the system log; 0 (the switch
off) is logged as 0; one that raises stops no cut; the module search path is left as it was.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src', 'opnsense', 'scripts', 'blocklists'))
if importlib.util.find_spec('fcntl') is None:     # Windows: the scripts lock with it; nothing here locks
    sys.modules['fcntl'] = types.ModuleType('fcntl')
import cut          # noqa: E402
import ja4_cut      # noqa: E402

FAILED = []
CHECKS = [0]


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


FAKE_HWDROP = '''
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flows  # noqa: E402,F401 - os-xgs-npu's hwdrop imports its flows.py this way
import hwdrop_events  # noqa: E402


def drop_addresses(contains, path='/conf/config.xml'):
    hwdrop_events.events.append(('drop_addresses', sorted(a for a in hwdrop_events.probe if a in contains)))
    if hwdrop_events.result is None:
        raise RuntimeError('no table')
    return hwdrop_events.result


def drop_ends(groups, path='/conf/config.xml'):
    hwdrop_events.events.append(('drop_ends', [(p, sorted(e)) for p, e in groups]))
    if hwdrop_events.result is None:
        raise RuntimeError('no table')
    return hwdrop_events.result
'''

EVENTS = types.ModuleType('hwdrop_events')
EVENTS.events, EVENTS.probe, EVENTS.result = [], [], 0
sys.modules['hwdrop_events'] = EVENTS


class Done:
    def __init__(self, stdout='', returncode=0):
        self.stdout, self.returncode = stdout, returncode


def fake_run(states_text):
    def run(cmd, **kw):
        if cmd[0].endswith('logger'):
            EVENTS.events.append(('log', cmd[-1]))
            return Done()
        if cmd[1:3] == ['-ss', '-vv']:
            return Done(states_text)
        if cmd[1:3] == ['-k', 'id']:
            EVENTS.events.append(('kill', cmd[-1]))
            return Done()
        raise AssertionError('unexpected command: %r' % (cmd,))
    return run


CUT_STATES = '''all tcp 192.0.2.10:50000 -> 203.0.113.5:443       ESTABLISHED:ESTABLISHED
   age 00:01:00, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000a1 creatorid: 12345678
all tcp 192.0.2.11:50001 -> 198.51.100.7:80       ESTABLISHED:ESTABLISHED
   age 00:01:00, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000a2 creatorid: 12345678
all tcp 192.0.2.12:50002 -> 192.0.2.200:22       ESTABLISHED:ESTABLISHED
   age 00:01:00, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000a3 creatorid: 12345678
'''
TABLES = {'blocklists_feodo': {'203.0.113.0/24'}, 'blocklists_cins_army': {'198.51.100.7/32'}}


def kinds(events):
    return [e[0] for e in events if e[0] != 'log']


def logs(events):
    return [e[1] for e in events if e[0] == 'log']


def cut_run(tmp, hwdrop_path, result):
    """One run of cut.py over two lists, each with a new entry, its state kept in tmp."""
    state = os.path.join(tmp, 'cut-' + str(len(os.listdir(tmp))))
    os.makedirs(state)
    cut.STATE_DIR, cut.STATUS = state, os.path.join(state, 'status.json')
    cut.HWDROP = hwdrop_path
    cut.watched_lists = lambda path=None: sorted(TABLES)
    cut.table_entries = lambda name: set(TABLES[name])
    cut.subprocess.run = fake_run(CUT_STATES)
    EVENTS.events[:], EVENTS.result = [], result
    EVENTS.probe = ['203.0.113.5', '198.51.100.7', '192.0.2.200']
    path_before = list(sys.path)
    summary = cut.run()
    check(sys.path == path_before, 'cut.py: the module search path is as it was')
    return summary, list(EVENTS.events)


def test_cut(tmp, fake):
    # without os-xgs-npu: as before
    summary, events = cut_run(tmp, os.path.join(tmp, 'absent', 'hwdrop.py'), 3)
    check('dropped' not in summary, 'cut.py without hwdrop.py: no "dropped" in the summary')
    check(kinds(events) == ['kill', 'kill'], 'cut.py without hwdrop.py: the two states killed, nothing dropped')
    check('hardware' not in summary['message'], 'cut.py without hwdrop.py: the message as before')
    check(not any('hardware' in m for m in logs(events)), 'cut.py without hwdrop.py: nothing logged of hardware')

    # with it: once, first, with both lists' new entries
    summary, events = cut_run(tmp, fake, 3)
    check(kinds(events) == ['drop_addresses', 'kill', 'kill'], 'cut.py: dropped once, before the first kill')
    check(events[0] == ('drop_addresses', ['198.51.100.7', '203.0.113.5']),
          'cut.py: every list\'s new entries in the one call, nothing else')
    check(summary.get('dropped') == 3 and summary['cut'] == 2, 'cut.py: the count in the summary, the kills as before')
    check(summary['message'].endswith('; 3 dropped in hardware now'), 'cut.py: the count in the message')
    check('3 connections dropped in hardware' in logs(events), 'cut.py: the count in the system log')

    # the switch off: 0, logged
    summary, events = cut_run(tmp, fake, 0)
    check(summary.get('dropped') == 0 and summary['cut'] == 2, 'cut.py: 0 dropped, the kills as before')
    check('0 connections dropped in hardware' in logs(events), 'cut.py: 0 logged')

    # one that raises stops nothing
    summary, events = cut_run(tmp, fake, None)
    check(kinds(events) == ['drop_addresses', 'kill', 'kill'] and summary.get('dropped') == 0,
          'cut.py: a hwdrop that raises cuts no fewer states')

    # nothing new: no call
    EVENTS.events[:] = []
    cut.run()
    check(kinds(EVENTS.events) == [], 'cut.py: nothing new, nothing dropped or killed')

    # a hwdrop.py that does not load
    broken = os.path.join(tmp, 'broken', 'hwdrop.py')
    os.makedirs(os.path.dirname(broken))
    with open(broken, 'w') as fh:
        fh.write('import no_such_module_here\n')
    summary, events = cut_run(tmp, broken, 3)
    check('dropped' not in summary and kinds(events) == ['kill', 'kill'], 'cut.py: a hwdrop.py that does not load: as without it')


FP = 't13d1516h2_8daaf6152771_02713d6af862'
JA4_STATES = '''all tcp 203.0.113.5:443 <- 192.0.2.10:50000       ESTABLISHED:ESTABLISHED
   age 00:00:05, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000b1 creatorid: 12345678
all tcp 192.0.2.10:50000 -> 203.0.113.5:443       ESTABLISHED:ESTABLISHED
   age 00:00:05, expires in 24:00:00, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000b2 creatorid: 12345678
all udp 192.0.2.10:50000 -> 203.0.113.5:443       MULTIPLE:MULTIPLE
   age 00:00:05, expires in 00:00:30, 3:2 pkts, 300:200 bytes, rule 5
   id: 00000000000000b3 creatorid: 12345678
'''


def ja4_once(tmp, hwdrop_path, result):
    state = os.path.join(tmp, 'ja4-' + str(len(os.listdir(tmp))))
    os.makedirs(state)
    ja4_cut.STATE_DIR, ja4_cut.STATUS = state, os.path.join(state, 'status.json')
    ja4_cut.HWDROP = hwdrop_path
    ja4_cut.CONFIG = os.path.join(state, 'config.xml')
    with open(ja4_cut.CONFIG, 'w') as fh:
        fh.write('<opnsense/>')
    ja4_cut.settings = lambda: ([FP], None, [], True)
    ja4_cut.EVE = os.path.join(state, 'eve.json')
    line = {'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000'),
            'event_type': 'tls', 'proto': 'TCP', 'src_ip': '192.0.2.10', 'src_port': 50000,
            'dest_ip': '203.0.113.5', 'dest_port': 443, 'tls': {'ja4': FP}}
    with open(ja4_cut.EVE, 'w') as fh:
        fh.write(json.dumps(line, separators=(',', ':')) + '\n')
    ja4_cut.subprocess.run = fake_run(JA4_STATES)
    EVENTS.events[:], EVENTS.result = [], result
    path_before = list(sys.path)
    w = ja4_cut.Watch()
    summary = w.once()
    check(sys.path == path_before, 'ja4_cut.py: the module search path is as it was')
    return w, summary, list(EVENTS.events)


def test_ja4(tmp, fake):
    w, summary, events = ja4_once(tmp, os.path.join(tmp, 'absent', 'hwdrop.py'), 2)
    check('dropped' not in summary, 'ja4_cut.py without hwdrop.py: no "dropped" in the summary')
    check(kinds(events) == ['kill', 'kill'], 'ja4_cut.py without hwdrop.py: the two TCP states killed, nothing dropped')
    check('hardware' not in w.message(summary), 'ja4_cut.py without hwdrop.py: the message as before')

    w, summary, events = ja4_once(tmp, fake, 2)
    check(kinds(events) == ['drop_ends', 'kill', 'kill'], 'ja4_cut.py: dropped once, before the first kill')
    ends = sorted([('192.0.2.10', 50000), ('203.0.113.5', 443)])
    check(events[0] == ('drop_ends', [('tcp', ends), ('tcp', ends)]),
          'ja4_cut.py: each cut state\'s ends apart, with its protocol, the UDP state not among them')
    check(summary.get('dropped') == 2 and summary['cut'] == 2, 'ja4_cut.py: the count in the summary, the kills as before')
    check('; 2 dropped in hardware now' in w.message(summary), 'ja4_cut.py: the count in the message')
    check('2 connections dropped in hardware' in logs(events), 'ja4_cut.py: the count in the system log')

    w, summary, events = ja4_once(tmp, fake, 0)
    check(summary.get('dropped') == 0 and summary['cut'] == 2 and '0 connections dropped in hardware' in logs(events),
          'ja4_cut.py: 0 dropped (the switch off), logged, the kills as before')

    w, summary, events = ja4_once(tmp, fake, None)
    check(kinds(events) == ['drop_ends', 'kill', 'kill'] and summary.get('dropped') == 0,
          'ja4_cut.py: a hwdrop that raises cuts no fewer states')


def main():
    tmp = tempfile.mkdtemp(prefix='blocklists-hwdrop-')
    try:
        xgs = os.path.join(tmp, 'xgs')
        os.makedirs(xgs)
        fake = os.path.join(xgs, 'hwdrop.py')
        with open(fake, 'w') as fh:
            fh.write(FAKE_HWDROP)
        with open(os.path.join(xgs, 'flows.py'), 'w') as fh:
            fh.write('')
        runs = os.path.join(tmp, 'runs')
        os.makedirs(runs)
        test_cut(runs, fake)
        test_ja4(runs, fake)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
