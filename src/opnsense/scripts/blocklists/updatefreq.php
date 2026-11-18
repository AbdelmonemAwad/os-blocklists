<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * How often OPNsense fetches a feed's alias again: the page's "Fetch the lists" (general.refresh, every
 * 2, 6, 12 or 24 hours; 2 by default) or the feed's own minimum in feeds.json (min_hours: what its
 * publisher allows - Spamhaus DROP once a day), whichever is longer. apply.php writes it into the
 * alias's updatefreq, and so does fetch-frequency.php at every install and update, into the aliases
 * already there and nothing else (blocklists_write_frequency(), below). OPNsense 26.7 takes
 * updatefreq in days with a fraction: its alias updater, run every
 * minute, fetches a URL table again once int(updatefreq * 86400) seconds have passed, and takes 0 -
 * anything under a second - for "never again". So nothing here is ever shorter than 2 hours, and a
 * minimum that is missing or not a positive number counts as a day.
 */

const BLOCKLISTS_REFRESH = ['h2' => 2, 'h6' => 6, 'h12' => 12, 'h24' => 24];
const BLOCKLISTS_REFRESH_DEFAULT = 'h2';

/**
 * @param array $feed one feed of feeds.json
 * @param string $refresh the setting's value: h2, h6, h12 or h24
 * @return string updatefreq, in days: "0.083333" for 2 hours, "1" for a day
 */
function blocklists_updatefreq($feed, $refresh)
{
    $hours = BLOCKLISTS_REFRESH[(string)$refresh] ?? BLOCKLISTS_REFRESH[BLOCKLISTS_REFRESH_DEFAULT];
    $min = is_array($feed) ? ($feed['min_hours'] ?? null) : null;
    $min = (is_int($min) || is_float($min)) && $min > 0 ? $min : 24;
    $days = rtrim(rtrim(sprintf('%.6F', max($hours, $min) / 24), '0'), '.');
    /* never under a second, which OPNsense takes for never: a day, should it ever come to that */
    return (float)$days * 86400 >= 1 ? $days : '1';
}

/**
 * The fetch frequency the settings say, written into the plugin's own aliases already there, and
 * nothing else - fetch-frequency.php's step, at every install and update. Each alias named
 * blocklists_<id> for a list of feeds.json, switched on and a URL table, whose updatefreq is not
 * blocklists_updatefreq() of its list and $refresh, is given that one; no alias is added, removed,
 * switched on or off, and nothing else of one is changed. The model is validated (the fields changed,
 * as OPNsense's models do) and $save called only when an alias changed and nothing was refused; each
 * alias changed, and the outcome, are said to $log - after the save, so they say what was saved.
 *
 * @param object $model the alias model (OPNsense\Firewall\Alias): aliases->alias->iterateItems() and
 *                      performValidation(), whose messages have getField() and getMessage()
 * @param array|null $feeds feeds.json, decoded
 * @param string $refresh "Fetch the lists" (general.refresh)
 * @param callable $log called with each line for the system log
 * @param callable $save called once, to write config.xml
 * @return int how many aliases were changed and saved
 */
function blocklists_write_frequency($model, $feeds, $refresh, $log, $save)
{
    if (!is_array($feeds)) {
        $log('fetch frequency not written: feeds.json could not be read');
        return 0;
    }
    $lines = [];
    $seen = 0;
    foreach ($model->aliases->alias->iterateItems() as $alias) {
        $name = (string)$alias->name;
        $id = substr($name, strlen('blocklists_'));
        if (
            strpos($name, 'blocklists_') !== 0 || !isset($feeds[$id]) || !is_array($feeds[$id]) ||
            (string)$alias->enabled !== '1' || (string)$alias->type !== 'urltable'
        ) {
            continue;
        }
        $seen++;
        $want = blocklists_updatefreq($feeds[$id], $refresh);
        $have = (string)$alias->updatefreq;
        if ($have === $want) {
            continue;
        }
        $alias->updatefreq = $want;
        $lines[] = sprintf('%s: fetched every %s hours now (updatefreq %s, was %s)', $name,
            round((float)$want * 24, 2), $want, $have === '' ? 'empty' : $have);
    }
    if ($seen === 0) {
        $log('fetch frequency: no alias of the plugin\'s lists is switched on, nothing to write');
        return 0;
    }
    if (empty($lines)) {
        $log(sprintf('fetch frequency: the %d alias%s of the plugin\'s lists already as the settings say',
            $seen, $seen === 1 ? '' : 'es'));
        return 0;
    }
    $refused = [];
    foreach ($model->performValidation() as $message) {
        $refused[] = $message->getField() . ': ' . $message->getMessage();
    }
    if (!empty($refused)) {
        $log('fetch frequency not written, the alias model refused it: ' . implode('; ', $refused));
        return 0;
    }
    $save();
    foreach ($lines as $line) {
        $log($line);
    }
    $log(sprintf('fetch frequency written into %d of the %d alias%s of the plugin\'s lists, config.xml saved',
        count($lines), $seen, $seen === 1 ? '' : 'es'));
    return count($lines);
}
