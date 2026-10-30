<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The block rules, registered at every filter reload from the aliases this plugin owns (blocklists_<id>
 * for each list of feeds.json and blocklists_countries, scripts/blocklists/apply.php) - the way
 * os-crowdsec registers its own. They are never among the owner's rules in Firewall: Rules, so turning
 * the plugin off or removing it leaves nothing behind there. Priority 1 puts them before the interface
 * rules; quick, so a block is final.
 *
 * Inbound: from a listed address, on every interface. Both ways (the default): to a listed address as
 * well, so a host inside cannot reach one either.
 */

use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Plugin;

function blocklists_firewall(Plugin $fw)
{
    global $config;

    $general = $config['OPNsense']['BlockLists']['general'] ?? [];
    if (($general['enabled'] ?? '1') !== '1') {
        return;
    }
    $both = ($general['direction'] ?? 'both') === 'both';
    $log = ($general['log'] ?? '0') === '1';

    /*
     * Only the names this plugin makes are its own - the set apply.php, cut.py and status.py use too.
     * Until 2026-10-29 every alias named blocklists_* was blocked here, so one of the owner's by such a
     * name - a list of exceptions, say - was blocked both ways before his own rules.
     */
    $owned = ['blocklists_countries' => true];
    $feeds = json_decode((string)@file_get_contents('/usr/local/opnsense/scripts/blocklists/feeds.json'), true);
    if (is_array($feeds)) {
        foreach (array_keys($feeds) as $id) {
            $owned['blocklists_' . $id] = true;
        }
    } else {
        syslog(LOG_ERR, 'Block Lists: feeds.json could not be read; only the countries are blocked');
    }

    foreach ((new Alias())->aliases->alias->iterateItems() as $alias) {
        $name = (string)$alias->name;
        if (!isset($owned[$name]) || (string)$alias->enabled !== '1') {
            continue;
        }
        $proto = (string)$alias->proto;
        $families = [];
        if ($proto === '' || strpos($proto, 'IPv4') !== false) {
            $families[] = 'inet';
        }
        if ($proto === '' || strpos($proto, 'IPv6') !== false) {
            $families[] = 'inet6';
        }
        foreach ($families as $family) {
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'descr' => 'Block Lists: ' . $name . ' in',
                'from' => '<' . $name . '>',
                'direction' => 'in',
                'type' => 'block',
                'log' => $log,
                'quick' => true,
            ]);
            if ($both) {
                $fw->registerFilterRule(1, [
                    'ipprotocol' => $family,
                    'descr' => 'Block Lists: ' . $name . ' out',
                    'to' => '<' . $name . '>',
                    'direction' => 'out',
                    'type' => 'block',
                    'log' => $log,
                    'quick' => true,
                ]);
            }
        }
    }
}
