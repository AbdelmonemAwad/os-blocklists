#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * At every install and update of the plugin, the fetch frequency "Fetch the lists" says, written into
 * the plugin's own aliases already there - pkg/post-install.sh and install/install.sh both run this,
 * so a package, XGS: Updates and the self-update (which run install/install.sh) and a hand install
 * alike. For an update from a version that fetched every list once a day (until 2026-11-16).
 *
 * Exactly this (blocklists_write_frequency(), updatefreq.php): each alias named blocklists_<id> for
 * a list of feeds.json that is switched on and a URL table, whose updatefreq is not what its list
 * and the setting give (blocklists_updatefreq()), is given that one. Nothing else: no alias is added,
 * removed, switched on or off, and nothing else of one changes - not its URL, its description, its
 * counters. An alias switched off, the countries' GeoIP alias and every alias of the owner's are left
 * as they are. config.xml is saved, as one revision, only when an alias changed and the alias model
 * refused nothing. Each alias changed and the outcome - nothing to write, a refusal, a failure - go
 * to the system log under blocklists, and are printed for the installer's output. Each installer
 * reloads the filter after this, which hands the aliases' settings to OPNsense's alias updater.
 *
 * Until 2026-11-17 the package's post-install ran the page's whole Apply (apply.php) instead, with
 * its output thrown away, and an update through install/install.sh ran nothing: Apply also added the
 * aliases of lists chosen and not applied, removed or switched off those no longer chosen, switched
 * back on one its owner had switched off, rewrote every one's content and saved a revision of
 * config.xml each time.
 *
 *   fetch-frequency.php     always exits 0: an install is never stopped by it
 */

require_once('script/load_phalcon.php');
require_once(__DIR__ . '/updatefreq.php');

use OPNsense\BlockLists\BlockLists;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

openlog('blocklists', LOG_ODELAY, LOG_DAEMON);
$log = function ($line) {
    syslog(LOG_NOTICE, $line);
    echo 'Block Lists: ' . $line . "\n";
};

try {
    $feeds = json_decode((string)@file_get_contents(__DIR__ . '/feeds.json'), true);
    $refresh = (string)(new BlockLists())->general->refresh;
    $model = new Alias();
    blocklists_write_frequency($model, $feeds, $refresh, $log, function () use ($model) {
        $model->serializeToConfig();
        Config::getInstance()->save();
    });
} catch (\Throwable $e) {
    $log('fetch frequency not written: ' . $e->getMessage());
}
exit(0);
