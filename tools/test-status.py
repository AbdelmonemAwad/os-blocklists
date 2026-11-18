#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""status.py's "inside" for each list - whether pf was given its "from inside" rule at the last filter
reload, read from rules.debug by the rule's description - and the Lists tab's note on "Blocked in",
which shows only where one was. A config.xml, a rules.debug and pf's tables are stand-ins; no
OPNsense, no root:

    python3 tools/test-status.py
"""
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import types
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'blocklists'))
if importlib.util.find_spec('fcntl') is None:     # Windows: the scripts lock with it; nothing here locks
    sys.modules['fcntl'] = types.ModuleType('fcntl')
import status       # noqa: E402

FAILED = []
CHECKS = [0]
# an abuse.ch Auth-Key no account has: the tests' own
FAKE_KEY = 'test-only-not-a-real-auth-key-0000'


def check(ok, what):
    CHECKS[0] += 1
    if not ok:
        FAILED.append(what)
        print('FAIL ' + what)


# as OPNsense 26.7's FilterRule writes them (the rules hook's, through OPNsense's own classes)
RULES = '''# [prio: 1]
block in log quick on igb1 inet from {any} to {<blocklists_feodo>} label "0f1e2d3c" # Block Lists: blocklists_feodo from inside
block in log quick on vlan0.10 inet from {any} to {<blocklists_feodo>} label "0f1e2d3c" # Block Lists: blocklists_feodo from inside
#debug:Interface nosuch not found
# block in log quick on ##nosuch## inet from {any} to {<blocklists_dead>} label "1a2b" # Block Lists: blocklists_dead from inside
block in quick inet from {<blocklists_feodo>} to {any} label "3c4d" # Block Lists: blocklists_feodo in
block out quick inet from {any} to {<blocklists_spamhaus_drop>} label "5e6f" # Block Lists: blocklists_spamhaus_drop out
block in quick inet from {any} to {<blocklists_mine>} label "7a8b" # Block Lists: blocklists_mine from inside here
'''

CONFIG = '''<opnsense><OPNsense>
<BlockLists><general><enabled>1</enabled><direction>both</direction></general></BlockLists>
<Firewall><Alias><aliases>
<alias uuid="u1"><name>blocklists_feodo</name><enabled>1</enabled><type>urltable</type><proto>IPv4</proto></alias>
<alias uuid="u2"><name>blocklists_spamhaus_drop</name><enabled>1</enabled><type>urltable</type><proto>IPv4</proto></alias>
</aliases></Alias></Firewall>
</OPNsense></opnsense>
'''


def main():
    tmp = tempfile.mkdtemp(prefix='blocklists-status-')
    try:
        rules = os.path.join(tmp, 'rules.debug')
        with open(rules, 'w') as fh:
            fh.write(RULES)
        check(status.inside_rules(rules) == {'blocklists_feodo'},
              'inside_rules: the "from inside" rules pf was given, not one written commented out, not another '
              'description: %r' % (status.inside_rules(rules),))
        check(status.inside_rules(os.path.join(tmp, 'absent')) == set(), 'inside_rules: no rules.debug - none')

        config = os.path.join(tmp, 'config.xml')
        with open(config, 'w') as fh:
            fh.write(CONFIG)
        status.CONFIG = status.ja4_cut.CONFIG = config
        status.RULES = rules
        status.tables = lambda: {}
        status.CUT_STATUS = status.JA4_STATUS = status.THREATFOX_STATUS = os.path.join(tmp, 'none.json')
        status.PROJECT_CUT = status.PROJECT_JA4 = os.path.join(tmp, 'none')
        out = io.StringIO()
        with redirect_stdout(out):
            status.main()
        lists = {entry['name']: entry for entry in json.loads(out.getvalue())['lists']}
        check(lists.get('blocklists_feodo', {}).get('inside') is True, 'status: feodo, whose "from inside" rule is loaded - inside')
        check(lists.get('blocklists_spamhaus_drop', {}).get('inside') is False, 'status: Spamhaus DROP, no such rule - not inside')
        check(json.loads(out.getvalue()).get('threatfox') == {'chosen': False, 'key': False, 'message': ''},
              'status: ThreatFox not chosen, no key, nothing fetched')

        # ThreatFox chosen with a key: the page told a key is saved, never the key; threatfox.py's line
        status.THREATFOX_STATUS = os.path.join(tmp, 'threatfox.json')
        with open(status.THREATFOX_STATUS, 'w') as fh:
            json.dump({'message': '4 addresses, from the whole export fetched 2026-11-17 09:58 UTC', 'entries': 4}, fh)
        with open(config, 'w') as fh:
            fh.write(CONFIG.replace('<direction>both</direction>', '<direction>both</direction><feeds>feodo,threatfox'
                                    '</feeds><threatfox_key>' + FAKE_KEY + '</threatfox_key>'))
        out = io.StringIO()
        with redirect_stdout(out):
            status.main()
        check(json.loads(out.getvalue()).get('threatfox') == {
            'chosen': True, 'key': True, 'message': '4 addresses, from the whole export fetched 2026-11-17 09:58 UTC'},
            'status: ThreatFox chosen, a key saved, its line: %r' % (json.loads(out.getvalue()).get('threatfox'),))
        check(FAKE_KEY not in out.getvalue(), 'status: the key itself never in the page\'s answer')
        with open(config, 'w') as fh:
            fh.write(CONFIG.replace('<direction>both</direction>', '<direction>both</direction><feeds>threatfox</feeds>'
                                    '<threatfox_key> </threatfox_key>'))
        os.unlink(status.THREATFOX_STATUS)
        out = io.StringIO()
        with redirect_stdout(out):
            status.main()
        check(json.loads(out.getvalue()).get('threatfox') == {'chosen': True, 'key': False, 'message': ''},
              'status: chosen, no key saved (blank), threatfox.py not run yet')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    volt = open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'BlockLists', 'index.volt'),
                encoding='utf-8').read()
    note = volt.find('id="bl-inside-note"')
    check(note != -1 and 'display: none' in volt[note:note + 120], 'the page: the note on "Blocked in" hidden at first')
    check("$('#bl-inside-note').toggle(data.lists.some(function (l) { return l.inside; }));" in volt,
          'the page: the note shown only where a list\'s "from inside" rule is loaded')
    check('counts the packets of devices inside' in volt and 'counts the devices inside' not in volt,
          'the page: the note counts packets, not devices')

    # ThreatFox: the key's field says saved or not set, never the key; Remove the key; its line
    key_fn = volt[volt.find('function key_saved(saved)'):]
    key_fn = key_fn[:key_fn.find('\n        }\n')]
    check("document.getElementById('blocklists.general.threatfox_key')).attr('placeholder'," in key_fn
          and "saved ? \"{{ lang._('saved - leave empty to keep it') }}\" : \"{{ lang._('not set') }}\"" in key_fn
          and "$('#bl-key-remove').toggle(saved);" in key_fn,
          'the page: the key\'s field says saved or not set, and Remove the key shows only with a key saved')
    check('key_saved(!!tf.key);' in volt and "$('#bl-threatfox-line').toggle(!!tf.chosen);" in volt,
          'the page: both from status.py\'s answer at every reading; ThreatFox\'s line where it is chosen')
    check("$('#bl-threatfox').text(plain(!tf.key ?\n                \"{{ lang._('no abuse.ch Auth-Key saved: nothing is "
          "fetched. Enter one in Settings, then Apply.') }}\" :\n                (tf.message || \"{{ lang._('not run yet') }}\")));"
          in volt, 'the page: no key - said; a key - threatfox.py\'s line, or not run yet')
    line = volt.find('id="bl-threatfox-line"')
    check(line != -1 and 'display: none' in volt[line:line + 80] and 'ThreatFox: <span id="bl-threatfox">' in volt,
          'the page: ThreatFox\'s line hidden at first')
    button = volt[volt.find('id="bl-key-remove"') - 120:]
    check(".insertAfter(document.getElementById('blocklists.general.threatfox_key'))" in button
          and "ajaxCall('/api/blocklists/settings/forget_key', {}" in button and 'display: none' in button[:220],
          'the page: Remove the key, beside the field, hidden at first, posts forget_key')
    save = volt[volt.find("saveFormToEndpoint('/api/blocklists/settings/set'"):]
    check(save.find("getElementById('blocklists.general.threatfox_key')).val('')") != -1
          and save.find("getElementById('blocklists.general.threatfox_key')).val('')") < save.find("ajaxCall('/api/blocklists/service/apply'"),
          'the page: a key typed is cleared from the field once saved, before Apply')

    print('%d of %d checks failed' % (len(FAILED), CHECKS[0]) if FAILED else '%d checks passed' % CHECKS[0])
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
