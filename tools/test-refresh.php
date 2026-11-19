<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * How often each feed's alias is fetched again (scripts/blocklists/updatefreq.php), for every feed of
 * feeds.json and every choice of the page, as OPNsense 26.7's alias updater turns it into seconds
 * (int(updatefreq * 86400)); and the model's choices and default against the function's. No OPNsense
 * needed:
 *
 *   php tools/test-refresh.php
 */

$root = dirname(__DIR__);
require $root . '/src/opnsense/scripts/blocklists/updatefreq.php';
$failed = 0;
$checks = 0;

function check($ok, $what)
{
    global $failed, $checks;
    $checks++;
    if (!$ok) {
        $failed++;
        echo "FAIL $what\n";
    }
}

/* seconds, as OPNsense's lib/alias takes the template's <ttl>, updatefreq * 86400 */
function seconds($updatefreq)
{
    return (int)((float)$updatefreq * 86400);
}

function hours($updatefreq)
{
    return seconds($updatefreq) / 3600;
}

$feeds = json_decode(file_get_contents($root . '/src/opnsense/scripts/blocklists/feeds.json'), true);
$want = [
    /* feed => [h2, h6, h12, h24], in hours */
    'spamhaus_drop' => [24, 24, 24, 24],      /* Spamhaus: once a day (DROP FAQ) */
    'spamhaus_dropv6' => [24, 24, 24, 24],
    'feodo' => [2, 6, 12, 24],                /* abuse.ch: at least every 15 minutes */
    'et_compromised' => [24, 24, 24, 24],     /* no rule found: a day */
    'cins_army' => [24, 24, 24, 24],
    'blocklist_de' => [2, 6, 12, 24],         /* generated every 30 minutes */
];
/* ThreatFox (2026-11-17) is no URL table: threatfox.py fetches it at abuse.ch's pace (tools/test-threatfox.py);
   nor are the IPS drops (2026-11-19), which ids_list.py fills from the Intrusion Detection and never fetches */
$own = array_filter($feeds, function ($feed) {
    return !isset($feed['url']);
});
check(array_keys($own) === ['threatfox', 'ids'] && ($own['threatfox']['key'] ?? '') === 'abuse.ch'
    && ($own['ids']['local'] ?? null) === true, 'the lists without a URL: ThreatFox, fetched by the plugin with the '
    . 'abuse.ch key, and the IPS drops, filled by the plugin itself');
check(array_keys(array_diff_key($feeds, $own)) == array_keys($want), 'every URL table of feeds.json is checked here');
foreach ($feeds as $id => $feed) {
    if (($feed['local'] ?? null) === true) {
        check(!array_key_exists('min_hours', $feed), "$id: filled here, never fetched - no min_hours");
        continue;
    }
    check(is_int($feed['min_hours'] ?? null) || is_float($feed['min_hours'] ?? null), "$id: min_hours is a number");
    check(!array_key_exists('days', $feed), "$id: no days key left behind");
    if (isset($own[$id])) {
        continue;
    }
    foreach (['h2', 'h6', 'h12', 'h24'] as $i => $choice) {
        $f = blocklists_updatefreq($feed, $choice);
        $h = hours($f);
        check(abs($h - ($want[$id][$i] ?? -1)) < 0.01, "$id, $choice: every $h hours ($f), not {$want[$id][$i]}");
        check($h >= $feed['min_hours'] - 0.01, "$id, $choice: never more often than $feed[min_hours] hours");
        check(preg_match('/^[0-9]+(\.[0-9]+)?$/', $f) === 1, "$id, $choice: \"$f\" passes the alias model's NumericField");
    }
}
check(blocklists_updatefreq($feeds['feodo'], 'h2') === '0.083333', 'two hours is 0.083333 days');
check(seconds(blocklists_updatefreq($feeds['feodo'], 'h2')) === 7199, 'two hours is 7199 s to the updater');
check(blocklists_updatefreq($feeds['spamhaus_drop'], 'h2') === '1', 'a day is 1');

/* what is not as it should be */
check(hours(blocklists_updatefreq(['min_hours' => 0.25], '')) == hours(blocklists_updatefreq(['min_hours' => 0.25], 'h2')), 'no choice saved: the default, 2 hours');
check(abs(hours(blocklists_updatefreq(['min_hours' => 0.25], 'h3')) - 2) < 0.01, 'a choice not known: 2 hours');
foreach ([null, 0, -1, '2', 'x', [], true] as $bad) {
    check(blocklists_updatefreq(['min_hours' => $bad], 'h2') === '1', 'min_hours ' . json_encode($bad) . ': a day');
}
check(blocklists_updatefreq([], 'h2') === '1', 'no min_hours: a day');
check(blocklists_updatefreq(null, 'h6') === '1', 'no feed: a day');
check(abs(hours(blocklists_updatefreq(['min_hours' => 1e-9], 'h2')) - 2) < 0.01, 'a tiny minimum: still 2 hours');
foreach (['h2', 'h6', 'h12', 'h24', '', 'x'] as $choice) {
    foreach ([1e-9, 0.25, 0.5, 24, 48] as $min) {
        check(seconds(blocklists_updatefreq(['min_hours' => $min], $choice)) >= 7199, "never under 2 hours ($choice, $min): 0 would be never");
    }
}
check(abs(hours(blocklists_updatefreq(['min_hours' => 48], 'h2')) - 48) < 0.01, 'a minimum over a day is kept');

/* the model and the form */
/* read with a pattern, not an XML extension a PHP may lack: the field is a few plain lines */
$model = file_get_contents($root . '/src/opnsense/mvc/app/models/OPNsense/BlockLists/BlockLists.xml');
preg_match('#<refresh type="OptionField">(.*?)</refresh>#s', $model, $field);
$field = $field[1] ?? '';
preg_match('#<Default>([^<]*)</Default>#', $field, $default);
check(($default[1] ?? '') === BLOCKLISTS_REFRESH_DEFAULT && BLOCKLISTS_REFRESH_DEFAULT === 'h2', 'the model\'s default is every 2 hours');
preg_match('#<OptionValues>(.*?)</OptionValues>#s', $field, $values);
preg_match_all('#<([a-z0-9]+)>[^<]*</\1>#', $values[1] ?? '', $found);
$options = $found[1];
check($options === array_keys(BLOCKLISTS_REFRESH), 'the model offers what updatefreq.php reads: ' . implode(',', $options));
$form = file_get_contents($root . '/src/opnsense/mvc/app/controllers/OPNsense/BlockLists/forms/general.xml');
check(strpos($form, '<id>blocklists.general.refresh</id>') !== false, 'the form shows it');
$apply = file_get_contents($root . '/src/opnsense/scripts/blocklists/apply.php');
check(strpos($apply, "'updatefreq' => blocklists_updatefreq(\$feed, \$refresh)") !== false, 'apply.php writes it for each feed');

/*
 * The install's and the update's step (blocklists_write_frequency(), which fetch-frequency.php runs):
 * the updatefreq of the plugin's own URL table aliases switched on, and nothing else. Stand-ins for the
 * alias model (its items, its validation), the log and the save.
 */
class FreqItems
{
    public $items;

    public function iterateItems()
    {
        foreach ($this->items as $i => $item) {
            yield 'uuid-' . $i => $item;
        }
    }
}

class FreqMessage
{
    public function getField()
    {
        return 'aliases.alias.uuid-0.updatefreq';
    }

    public function getMessage()
    {
        return 'refused';
    }
}

class FreqModel
{
    public $aliases;
    public $refuse = false;

    public function __construct($aliases)
    {
        $this->aliases = (object)['alias' => new FreqItems()];
        $this->aliases->alias->items = array_map(function ($a) {
            return (object)$a;
        }, $aliases);
    }

    public function performValidation()
    {
        return $this->refuse ? [new FreqMessage()] : [];
    }

    public function state()
    {
        return array_map(function ($a) {
            return (array)$a;
        }, $this->aliases->alias->items);
    }
}

function frequency($model, $feeds, $refresh)
{
    $said = [];
    $saves = 0;
    $n = blocklists_write_frequency($model, $feeds, $refresh, function ($line) use (&$said) {
        $said[] = $line;
    }, function () use (&$saves) {
        $saves++;
    });
    return [$n, $said, $saves];
}

$alias = function ($name, $enabled, $type, $updatefreq) {
    return ['name' => $name, 'enabled' => $enabled, 'type' => $type, 'updatefreq' => $updatefreq,
        'content' => 'https://example.com/' . $name, 'description' => 'd ' . $name, 'counters' => '0', 'proto' => 'IPv4'];
};
$given = [
    $alias('blocklists_feodo', '1', 'urltable', '1'),                   /* the daily fetch of before: changed */
    $alias('blocklists_spamhaus_drop', '1', 'urltable', '1'),           /* already a day: kept */
    $alias('blocklists_cins_army', '1', 'urltable', ''),                /* none at all: a day */
    $alias('blocklists_blocklist_de', '0', 'urltable', '1'),            /* switched off: left */
    $alias('blocklists_countries', '1', 'geoip', ''),                   /* the GeoIP alias: left */
    $alias('blocklists_mine', '1', 'urltable', '0.5'),                  /* the owner's, not a feed: left */
    $alias('mine', '1', 'urltable', '0.5'),                             /* the owner's: left */
    $alias('blocklists_et_compromised', '1', 'network', '0.5'),         /* made another type by hand: left */
    $alias('blocklists_threatfox', '1', 'external', ''),               /* threatfox.py's, no URL table: left */
];
$model = new FreqModel($given);
$before = $model->state();
[$n, $said, $saves] = frequency($model, $feeds, 'h2');
$after = $model->state();
check($n === 2 && $saves === 1, "the step: 2 aliases changed and saved once ($n, $saves)");
check($after[0]['updatefreq'] === '0.083333' && $after[2]['updatefreq'] === '1',
    'the step: feodo every 2 hours, CINS Army (none before) once a day');
$others = $before;
$others[0]['updatefreq'] = '0.083333';
$others[2]['updatefreq'] = '1';
check($after === $others, 'the step: nothing else of any alias changed - none added, removed, switched on or off, '
    . 'no URL, description, counters or type; switched off, GeoIP, the owner\'s and another type left');
check(count($said) === 3 && strpos($said[0], 'blocklists_feodo: fetched every 2 hours now (updatefreq 0.083333, was 1)') === 0
    && strpos($said[1], 'blocklists_cins_army: fetched every 24 hours now (updatefreq 1, was empty)') === 0
    && strpos($said[2], 'fetch frequency written into 2 of the 3 aliases') === 0, 'the step: each change said, then the outcome: '
    . implode(' | ', $said));

[$n, $said, $saves] = frequency($model, $feeds, 'h2');
check($n === 0 && $saves === 0 && count($said) === 1 && strpos($said[0], 'already as the settings say') !== false,
    'the step again: nothing to change, nothing saved, said: ' . implode(' | ', $said));
[$n, $said, $saves] = frequency($model, $feeds, 'h24');
check($n === 1 && $saves === 1 && $model->state()[0]['updatefreq'] === '1', 'Once a day chosen: feodo once a day');

$model = new FreqModel($given);
$model->refuse = true;
[$n, $said, $saves] = frequency($model, $feeds, 'h2');
check($n === 0 && $saves === 0 && count($said) === 1 && strpos($said[0], 'refused it: aliases.alias.uuid-0.updatefreq: refused') !== false,
    'the model refuses: nothing saved, the refusal said: ' . implode(' | ', $said));
$model = new FreqModel($given);
[$n, $said, $saves] = frequency($model, null, 'h2');
check($n === 0 && $saves === 0 && $model->state() === $before && strpos($said[0] ?? '', 'feeds.json could not be read') !== false,
    'no feeds.json: nothing touched, nothing saved, said');
[$n, $said, $saves] = frequency(new FreqModel([$alias('mine', '1', 'urltable', '1'), $alias('blocklists_feodo', '0', 'urltable', '1')]), $feeds, 'h2');
check($n === 0 && $saves === 0 && strpos($said[0] ?? '', 'no alias of the plugin\'s lists is switched on') !== false,
    'none of its aliases switched on (a fresh install): nothing saved, said');

/* both installers run the step, its output kept, before their filter reload - and the whole Apply no more */
$script = $root . '/src/opnsense/scripts/blocklists/fetch-frequency.php';
$text = file_get_contents($script);
check(strpos($text, "#!/usr/local/bin/php\n") === 0, 'fetch-frequency.php is run as a script (#!, made 0755 by the package)');
check(strpos($text, 'blocklists_write_frequency(') !== false && strpos($text, "openlog('blocklists'") !== false
    && strpos($text, 'syslog(LOG_NOTICE') !== false && strpos($text, 'echo ') !== false, 'fetch-frequency.php: the step, '
    . 'its lines to the system log under blocklists and to the installer');
check(preg_match('/^exit\(0\);\s*$/m', $text) === 1 && strpos($text, 'catch (\Throwable') !== false,
    'fetch-frequency.php: never stops an install');
foreach (['pkg/post-install.sh', 'install/install.sh'] as $installer) {
    $lines = explode("\n", file_get_contents($root . '/' . $installer));
    $run = $reload = null;
    foreach ($lines as $i => $line) {
        if (preg_match('/^\s*#/', $line)) {
            continue;
        }
        if ($run === null && strpos($line, '/usr/local/opnsense/scripts/blocklists/fetch-frequency.php') !== false
            && strpos($line, 'chmod') === false && strpos($line, '[ -x') === false) {
            $run = $i;
        }
        if ($reload === null && preg_match('/configctl filter reload/', $line)) {
            $reload = $i;
        }
        check(!preg_match('#blocklists/apply\.php(\s|$)#', $line) || strpos($line, 'chmod') !== false,
            "$installer: no full Apply (line " . ($i + 1) . ')');
    }
    check($run !== null, "$installer runs fetch-frequency.php");
    check($run !== null && strpos($lines[$run], '/dev/null') === false, "$installer: its output not thrown away");
    check($run !== null && $reload !== null && $run < $reload, "$installer: before the filter reload");
}
$install = file_get_contents($root . '/install/install.sh');
check(preg_match('#chmod 755[^\n]*(\\\\\n[^\n]*)*fetch-frequency\.php#', $install) === 1, 'install.sh makes it 0755');

/*
 * fetch-frequency.php itself, run as the installers run it, with OPNsense's classes stood in for by a
 * script/load_phalcon.php of this test's own on the include path: the settings' choice read from the
 * plugin's model, the step on the alias model, the save through the model and Config, its lines printed.
 */
$stub = sys_get_temp_dir() . '/blocklists-frequency-' . getmypid();
@mkdir($stub . '/script', 0700, true);
file_put_contents($stub . '/script/load_phalcon.php', <<<'STUB'
<?php
namespace OPNsense\Core {
    class Config
    {
        private static $me;

        public static function getInstance()
        {
            return self::$me ??= new Config();
        }

        public function save()
        {
            echo "STUB saved\n";
        }
    }
}

namespace OPNsense\BlockLists {
    class BlockLists
    {
        public $general;

        public function __construct()
        {
            $this->general = (object)['refresh' => getenv('BLOCKLISTS_TEST_REFRESH')];
        }
    }
}

namespace OPNsense\Firewall {
    class StubItems
    {
        public $items = [];

        public function iterateItems()
        {
            foreach ($this->items as $i => $item) {
                yield 'uuid-' . $i => $item;
            }
        }
    }

    class Alias
    {
        public $aliases;

        public function __construct()
        {
            if (getenv('BLOCKLISTS_TEST_FAIL')) {
                throw new \RuntimeException('the model could not be read');
            }
            $this->aliases = (object)['alias' => new StubItems()];
            foreach (json_decode(getenv('BLOCKLISTS_TEST_ALIASES'), true) as $alias) {
                $this->aliases->alias->items[] = (object)$alias;
            }
        }

        public function performValidation()
        {
            return [];
        }

        public function serializeToConfig()
        {
            echo 'STUB serialized ' . json_encode(array_map(function ($a) {
                return (array)$a;
            }, $this->aliases->alias->items)) . "\n";
        }
    }
}
STUB);
function run_script($script, $stub, $aliases, $refresh, $fail = false)
{
    putenv('BLOCKLISTS_TEST_ALIASES=' . json_encode($aliases));
    putenv('BLOCKLISTS_TEST_REFRESH=' . $refresh);
    putenv('BLOCKLISTS_TEST_FAIL=' . ($fail ? '1' : ''));
    $out = [];
    exec(escapeshellarg(PHP_BINARY) . ' -d include_path=' . escapeshellarg($stub) . ' ' . escapeshellarg($script) . ' 2>&1', $out, $rc);
    return [$rc, $out];
}
[$rc, $out] = run_script($script, $stub, $given, 'h2');
$saved = array_values(array_filter($out, function ($l) {
    return strpos($l, 'STUB serialized ') === 0;
}));
$written = json_decode(substr($saved[0] ?? '', strlen('STUB serialized ')), true);
check($rc === 0 && in_array('Block Lists: blocklists_feodo: fetched every 2 hours now (updatefreq 0.083333, was 1)', $out, true)
    && in_array('STUB saved', $out, true), 'fetch-frequency.php run: feodo changed, saved through the model and Config, '
    . 'said: ' . implode(' | ', $out));
check(is_array($written) && $written === $others, 'fetch-frequency.php run: what it saved is the old aliases with feodo\'s '
    . 'and CINS Army\'s updatefreq only');
[$rc, $out] = run_script($script, $stub, $given, 'h24');
check($rc === 0 && in_array('Block Lists: blocklists_spamhaus_drop: fetched every 24 hours now (updatefreq 1, was 1)', $out, true) === false
    && in_array('Block Lists: blocklists_cins_army: fetched every 24 hours now (updatefreq 1, was empty)', $out, true)
    && !in_array('Block Lists: blocklists_feodo: fetched every 24 hours now (updatefreq 1, was 1)', $out, true),
    'fetch-frequency.php run, Once a day: the setting read from the plugin\'s model - only CINS Army changes');
[$rc, $out] = run_script($script, $stub, $given, 'h2', true);
check($rc === 0 && count($out) === 1 && $out[0] === 'Block Lists: fetch frequency not written: the model could not be read',
    'fetch-frequency.php run, the model failing: said, exit 0: ' . implode(' | ', $out));
@unlink($stub . '/script/load_phalcon.php');
@rmdir($stub . '/script');
@rmdir($stub);

echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
exit($failed ? 1 : 0);
