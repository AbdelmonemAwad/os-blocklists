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
check(array_keys($feeds) == array_keys($want), 'every feed of feeds.json is checked here');
foreach ($feeds as $id => $feed) {
    check(is_int($feed['min_hours'] ?? null) || is_float($feed['min_hours'] ?? null), "$id: min_hours is a number");
    check(!array_key_exists('days', $feed), "$id: no days key left behind");
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
check(strpos($apply, "blocklists_updatefreq(\$feeds[\$id], \$refresh)") !== false, 'apply.php writes it for each feed');

echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
exit($failed ? 1 : 0);
