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
off) is logged as 0; one that raises stops no cut, and its count is not known; the module search
path is left as it was; under Inbound only (outbound_blocked(), read from a config.xml of each kind)
nothing is dropped in hardware.

The deadline (within()): a step past it is left there and the pf cut goes on at once, in cut.py and
in ja4_cut.py alike - one that pages slowly through the flow table is stopped at its next connection,
writes no verdict after the deadline and puts the page place back in its own thread; one stuck in a
call that never looks back holds nothing up, and no second is started beside it while it runs; the
count is "unknown" then, in the summary, the message, the system log and a minute's total. No signal
is used: after every run SIGALRM has its default handler and no timer is set.
"""
import importlib.util
import io
import json
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
import types
from contextlib import redirect_stdout
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


# result: a count, None (raises), 'slow' (pages through a flow table of EVENTS.conns connections,
# EVENTS.each seconds each, as os-xgs-npu's hwdrop does: a generator that holds the flow-table lock
# and puts the shared page place back in its finally, an `in` test for every connection, a verdict
# for each that matches) or 'stuck' (one driver call of 3 s that never looks back)
FAKE_HWDROP = '''
import os
import sys
import threading
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flows  # noqa: E402,F401 - os-xgs-npu's hwdrop imports its flows.py this way
import hwdrop_events  # noqa: E402


def pages():
    hwdrop_events.lock.append(threading.current_thread().name)
    try:
        for i in range(hwdrop_events.conns):
            time.sleep(hwdrop_events.each)
            yield i
    finally:
        hwdrop_events.events.append(('place 0', threading.current_thread().name, time.monotonic()))
        hwdrop_events.lock.clear()


def walk(match):
    dropped = 0
    for i in pages():
        if match(i):
            hwdrop_events.events.append(('verdict', i, time.monotonic()))
            dropped += 1
    return dropped


def answer(match):
    if hwdrop_events.result == 'slow':
        return walk(match)
    if hwdrop_events.result == 'stuck':
        time.sleep(3)
        return 9
    if hwdrop_events.result is None:
        raise RuntimeError('no table')
    return hwdrop_events.result


def drop_addresses(contains, path='/conf/config.xml'):
    hwdrop_events.events.append(('drop_addresses', sorted(a for a in hwdrop_events.probe if a in contains)))
    return answer(lambda i: hwdrop_events.probe[0] in contains)


def drop_ends(groups, path='/conf/config.xml'):
    hwdrop_events.events.append(('drop_ends', [(p, sorted(e)) for p, e in groups]))
    ends = groups[0][1]
    return answer(lambda i: all(end in ends for end in sorted(ends)))
'''

EVENTS = types.ModuleType('hwdrop_events')
EVENTS.events, EVENTS.probe, EVENTS.result, EVENTS.lock = [], [], 0, []
EVENTS.conns, EVENTS.each = 20, 0.3
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
    return [e[0] for e in events if e[0] in ('drop_addresses', 'drop_ends', 'kill')]


def logs(events):
    return [e[1] for e in events if e[0] == 'log']


def no_signal(what):
    """No handler left on SIGALRM and no timer running: within() uses neither."""
    if hasattr(signal, 'SIGALRM'):
        check(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL, what + ': SIGALRM has its default handler')
    if hasattr(signal, 'getitimer'):
        check(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), what + ': no real-time timer set')


def settle(module, wait=6):
    """Every hardware step the module left at its deadline, ended."""
    until = time.monotonic() + wait
    for t in list(module._left):
        t.join(max(0, until - time.monotonic()))
    module._left[:] = [t for t in module._left if t.is_alive()]
    return not module._left


def place_back(wait=3):
    """The fake's page place put back (its paging generator's finally): (thread, when), or None."""
    until = time.monotonic() + wait
    while time.monotonic() < until:
        for e in list(EVENTS.events):
            if e[0] == 'place 0':
                return e[1], e[2]
        time.sleep(0.05)
    return None


def cut_run(tmp, hwdrop_path, result):
    """One run of cut.py over two lists, each with a new entry, its state kept in tmp."""
    state = os.path.join(tmp, 'cut-' + str(len(os.listdir(tmp))))
    os.makedirs(state)
    cut.STATE_DIR, cut.STATUS = state, os.path.join(state, 'status.json')
    cut.HWDROP = hwdrop_path
    cut.watched_lists = lambda path=None: sorted(TABLES)
    cut.table_entries = lambda name: set(TABLES[name])
    cut.subprocess.run = fake_run(CUT_STATES)
    EVENTS.events[:], EVENTS.result, EVENTS.lock[:] = [], result, []
    EVENTS.probe = ['203.0.113.5', '198.51.100.7', '192.0.2.200']
    path_before = list(sys.path)
    summary = cut.run()
    check(sys.path == path_before, 'cut.py: the module search path is as it was')
    no_signal('cut.py, %r' % (result,))
    return summary, list(EVENTS.events)


def test_outbound(tmp):
    """outbound_blocked() and watched_lists() against a config.xml of each kind."""
    def config(name, text):
        path = os.path.join(tmp, name)
        with open(path, 'w') as fh:
            fh.write(text)
        return path
    general = '<opnsense><OPNsense><BlockLists><general>%s</general></BlockLists></OPNsense></opnsense>'
    check(cut.outbound_blocked(config('in.xml', general % '<direction>in</direction><cut>1</cut>')) is False,
          'outbound_blocked: Inbound only (direction "in") - False')
    check(cut.outbound_blocked(config('both.xml', general % '<direction>both</direction>')) is True,
          'outbound_blocked: Both ways (direction "both") - True')
    check(cut.outbound_blocked(config('none.xml', general % '<cut>1</cut>')) is True,
          'outbound_blocked: no direction saved - the default, Both ways')
    check(cut.outbound_blocked(config('empty.xml', general % '<direction></direction>')) is True,
          'outbound_blocked: an empty direction - the default, Both ways')
    check(cut.outbound_blocked(config('nosection.xml', '<opnsense/>')) is True,
          'outbound_blocked: no Block Lists section - the default, Both ways')
    bad = config('bad.xml', '<opnsense><OPNsense>')
    check(cut.outbound_blocked(bad) is True and cut.outbound_blocked(os.path.join(tmp, 'absent.xml')) is True,
          'outbound_blocked: config.xml not readable or not XML - True, as nothing is cut then')
    check(cut.watched_lists(bad) is None and cut.watched_lists(os.path.join(tmp, 'absent.xml')) is None,
          'watched_lists: config.xml not readable or not XML - None, nothing cut')


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

    # one that raises stops nothing, and what it dropped before is not known
    summary, events = cut_run(tmp, fake, None)
    check(kinds(events) == ['drop_addresses', 'kill', 'kill'] and summary.get('dropped') == cut.UNKNOWN,
          'cut.py: a hwdrop that raises cuts no fewer states, its count unknown')
    check(any('failed' in m and 'no table' in m for m in logs(events)), 'cut.py: the failure in the system log')

    # nothing new: no call
    EVENTS.events[:] = []
    cut.run()
    check(kinds(EVENTS.events) == [], 'cut.py: nothing new, nothing dropped or killed')

    # Inbound only, read from a config.xml as outbound_blocked() reads it: nothing dropped in hardware,
    # the pf cut as before
    saved_config = cut.CONFIG
    cut.CONFIG = os.path.join(tmp, 'inbound.xml')
    with open(cut.CONFIG, 'w') as fh:
        fh.write('<opnsense><OPNsense><BlockLists><general><direction>in</direction></general></BlockLists></OPNsense></opnsense>')
    try:
        summary, events = cut_run(tmp, fake, 3)
    finally:
        cut.CONFIG = saved_config
    check('dropped' not in summary and kinds(events) == ['kill', 'kill'],
          'cut.py: Inbound only - nothing dropped in hardware, the two states killed')

    # a step paging slowly past its deadline: left at it, the pf cut at once; stopped at its next
    # connection, no verdict after the deadline, the page place put back in its own thread
    saved, cut.HW_DEADLINE = cut.HW_DEADLINE, 1
    started = time.monotonic()
    try:
        summary, events = cut_run(tmp, fake, 'slow')
    finally:
        cut.HW_DEADLINE = saved
    returned = time.monotonic()
    check(kinds(events) == ['drop_addresses', 'kill', 'kill'] and returned - started < 1.5,
          'cut.py: a slow hardware step left at its 1 s deadline, the states killed by %.2f s' % (returned - started))
    check(summary.get('dropped') == cut.UNKNOWN and 'not known' in summary['message'],
          'cut.py: past its deadline, how many were dropped is "unknown", in the summary and the message')
    check(any('took more than 1 s' in m and 'not known' in m for m in logs(events)),
          'cut.py: past its deadline, said in the system log')
    back = place_back()
    check(back is not None and back[0] == 'blocklists-hwdrop' and back[1] - returned < 0.6 and not EVENTS.lock,
          'cut.py: the step stopped at its next connection, the page place put back and the lock let go in its own '
          'thread (%s)' % (back,))
    verdicts = [e for e in EVENTS.events if e[0] == 'verdict']
    check(verdicts and all(e[2] <= returned + 0.05 for e in verdicts),
          'cut.py: no verdict written after the deadline (%d before it)' % len(verdicts))
    check(settle(cut), 'cut.py: the step left at its deadline has ended')

    # a step stuck in one call that never looks back: nothing held up, and no second beside it
    saved, cut.HW_DEADLINE = cut.HW_DEADLINE, 1
    try:
        started = time.monotonic()
        summary, events = cut_run(tmp, fake, 'stuck')
        took = time.monotonic() - started
        check(kinds(events) == ['drop_addresses', 'kill', 'kill'] and summary.get('dropped') == cut.UNKNOWN
              and took < 1.5, 'cut.py: a step stuck in the driver left at 1 s, the states killed by %.2f s' % took)
        summary, events = cut_run(tmp, fake, 3)
        check(kinds(events) == ['kill', 'kill'] and summary.get('dropped') == cut.UNKNOWN
              and any('still runs' in m for m in logs(events)),
              'cut.py: while it runs, no second step beside it - the states killed, the count unknown, said')
    finally:
        cut.HW_DEADLINE = saved
    check(settle(cut), 'cut.py: the stuck step has ended')
    summary, events = cut_run(tmp, fake, 3)
    check(summary.get('dropped') == 3, 'cut.py: once it has ended, the hardware step runs again')

    # a hwdrop.py that does not load
    broken = os.path.join(tmp, 'broken', 'hwdrop.py')
    os.makedirs(os.path.dirname(broken))
    with open(broken, 'w') as fh:
        fh.write('import no_such_module_here\n')
    summary, events = cut_run(tmp, broken, 3)
    check('dropped' not in summary and kinds(events) == ['kill', 'kill'], 'cut.py: a hwdrop.py that does not load: as without it')


def test_within():
    """within() itself, in both scripts."""
    for name, module in (('cut.py', cut), ('ja4_cut.py', ja4_cut)):
        check(module.within(1, lambda stop, a: a + 1, 41) == 42, name + ': within() hands back the result')
        try:
            module.within(1, lambda stop: 1 / 0)
            raised = None
        except RuntimeError as e:
            raised = str(e)
        check(raised is not None and 'ZeroDivisionError' in raised, name + ': within() hands back what was raised, as text')
        started = time.monotonic()
        try:
            module.within(0.5, lambda stop: time.sleep(2))
            late = False
        except module.HardwareLate:
            late = True
        took = time.monotonic() - started
        check(late and took < 0.8, name + ': a step that never looks back is left at 0.5 s (%.2f s)' % took)
        try:
            module.within(0.5, lambda stop: 1)
            busy = False
        except module.HardwareBusy:
            busy = True
        check(busy, name + ': while it runs, no second step is started')
        check(settle(module), name + ': it ends')
        check(module.within(0.5, lambda stop: 2) == 2, name + ': then a step runs again')
        started = time.monotonic()
        try:
            module.within(0.3, lambda stop: stop.wait(5))
        except module.HardwareLate:
            pass
        check(settle(module, wait=0.5), name + ': a step waiting on its stop ends once it is set')
        no_signal(name + ', within()')


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
    EVENTS.events[:], EVENTS.result, EVENTS.lock[:] = [], result, []
    path_before = list(sys.path)
    w = ja4_cut.Watch()
    summary = w.once()
    check(sys.path == path_before, 'ja4_cut.py: the module search path is as it was')
    no_signal('ja4_cut.py, %r' % (result,))
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
    check(kinds(events) == ['drop_ends', 'kill', 'kill'] and summary.get('dropped') == ja4_cut.UNKNOWN,
          'ja4_cut.py: a hwdrop that raises cuts no fewer states, its count unknown')

    # past its deadline, as in cut.py
    saved, ja4_cut.HW_DEADLINE = ja4_cut.HW_DEADLINE, 1
    started = time.monotonic()
    try:
        w, summary, events = ja4_once(tmp, fake, 'slow')
    finally:
        ja4_cut.HW_DEADLINE = saved
    returned = time.monotonic()
    check(kinds(events) == ['drop_ends', 'kill', 'kill'] and returned - started < 1.5,
          'ja4_cut.py: a slow hardware step left at its 1 s deadline, the states killed by %.2f s' % (returned - started))
    check(summary.get('dropped') == ja4_cut.UNKNOWN and 'not known' in w.message(summary),
          'ja4_cut.py: past its deadline, how many were dropped is "unknown", in the summary and the message')
    check(any('took more than 1 s' in m and 'not known' in m for m in logs(events)),
          'ja4_cut.py: past its deadline, said in the system log')
    back = place_back()
    check(back is not None and back[0] == 'blocklists-hwdrop' and back[1] - returned < 0.6 and not EVENTS.lock,
          'ja4_cut.py: the step stopped at its next connection, the page place put back and the lock let go in its own '
          'thread (%s)' % (back,))
    verdicts = [e for e in EVENTS.events if e[0] == 'verdict']
    check(verdicts and all(e[2] <= returned + 0.05 for e in verdicts),
          'ja4_cut.py: no verdict written after the deadline (%d before it)' % len(verdicts))
    check(settle(ja4_cut), 'ja4_cut.py: the step left at its deadline has ended')

    # stuck: no second step beside it in the next reading of the minute
    saved, ja4_cut.HW_DEADLINE = ja4_cut.HW_DEADLINE, 1
    try:
        started = time.monotonic()
        w, summary, events = ja4_once(tmp, fake, 'stuck')
        took = time.monotonic() - started
        check(kinds(events) == ['drop_ends', 'kill', 'kill'] and summary.get('dropped') == ja4_cut.UNKNOWN and took < 1.5,
              'ja4_cut.py: a step stuck in the driver left at 1 s, the states killed by %.2f s' % took)
        w, summary, events = ja4_once(tmp, fake, 2)
        check(kinds(events) == ['kill', 'kill'] and summary.get('dropped') == ja4_cut.UNKNOWN
              and any('still runs' in m for m in logs(events)),
              'ja4_cut.py: while it runs, no second step beside it - the states killed, the count unknown, said')
    finally:
        ja4_cut.HW_DEADLINE = saved
    check(settle(ja4_cut), 'ja4_cut.py: the stuck step has ended')


def test_ja4_minute(tmp):
    """--for's total over the minute's readings: their sum, or "unknown" once one is not known."""
    class Readings:
        def __init__(self, counts):
            self.counts, self.on, self.problem, self.listed, self.bad = list(counts), True, None, [FP], []
            self.status = {}

        def once(self):
            summary = {'cut': 0}
            if self.counts:
                summary['dropped'] = self.counts.pop(0)
            return summary

        def message(self, summary):
            return 'cut by TLS fingerprint: ' + (ja4_cut.dropped_said(summary['dropped']) if 'dropped' in summary else '')

        def save(self):
            pass

    saved = ja4_cut.Watch, ja4_cut.EVERY, ja4_cut.STATE_DIR
    ja4_cut.EVERY = 0.05
    ja4_cut.STATE_DIR = os.path.join(tmp, 'minute')
    ja4_cut.LOCK = os.path.join(ja4_cut.STATE_DIR, 'lock')
    try:
        for counts, total in (([2, 3], 5), ([2, ja4_cut.UNKNOWN, 3], ja4_cut.UNKNOWN), ([ja4_cut.UNKNOWN, 1], ja4_cut.UNKNOWN)):
            ja4_cut.Watch = lambda c=counts: Readings(c)
            out = io.StringIO()
            with redirect_stdout(out):
                ja4_cut.main(['--for', '1'])
            summary = json.loads(out.getvalue())
            check(summary.get('dropped') == total, 'ja4_cut.py --for: readings %r make %r (%r)' % (counts, total, summary.get('dropped')))
    finally:
        ja4_cut.Watch, ja4_cut.EVERY, ja4_cut.STATE_DIR = saved
        ja4_cut.LOCK = os.path.join(ja4_cut.STATE_DIR, 'lock')


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
        test_outbound(tmp)
        test_within()
        test_cut(runs, fake)
        test_ja4(runs, fake)
        if hasattr(sys.modules['fcntl'], 'flock'):
            test_ja4_minute(tmp)
        check(threading.active_count() == 1, 'no thread left running at the end (%d)' % threading.active_count())
    finally:
        settle(cut)
        settle(ja4_cut)
        shutil.rmtree(tmp, ignore_errors=True)
    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
