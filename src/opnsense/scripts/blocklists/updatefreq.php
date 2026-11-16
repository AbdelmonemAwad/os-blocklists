<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * How often OPNsense fetches a feed's alias again: the page's "Fetch the lists" (general.refresh, every
 * 2, 6, 12 or 24 hours; 2 by default) or the feed's own minimum in feeds.json (min_hours: what its
 * publisher allows - Spamhaus DROP once a day), whichever is longer. apply.php writes it into the
 * alias's updatefreq, which OPNsense 26.7 takes in days with a fraction: its alias updater, run every
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
