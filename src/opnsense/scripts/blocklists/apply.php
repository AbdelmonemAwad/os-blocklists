#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the firewall's aliases say what the settings say: one URL Table alias for each feed chosen,
 * one GeoIP alias for the countries, all named blocklists_* and owned by this plugin. An alias whose
 * feed is no longer chosen is removed - or, when something else in config.xml still names it, left
 * in place switched off, so no rule of the owner's is left pointing at nothing. The block rules are
 * not written here: plugins.inc.d/blocklists.inc registers them from these aliases at every filter
 * reload, so they are never among the owner's own rules.
 *
 *   apply.php     print a JSON summary; the page's Apply then reloads the filter and the aliases
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\BlockLists\BlockLists;

const PREFIX = 'blocklists_';

$feeds = json_decode(file_get_contents(__DIR__ . '/feeds.json'), true) ?: [];
$settings = new BlockLists();
$on = (string)$settings->general->enabled === '1';

$want = [];
if ($on) {
    foreach (array_filter(explode(',', (string)$settings->general->feeds)) as $id) {
        if (isset($feeds[$id])) {
            $want[PREFIX . $id] = [
                'type' => 'urltable', 'content' => $feeds[$id]['url'], 'proto' => $feeds[$id]['proto'],
                'updatefreq' => (string)$feeds[$id]['days'], 'description' => 'Block Lists: ' . $feeds[$id]['name'],
            ];
        }
    }
    $countries = array_filter(explode(',', (string)$settings->general->countries));
    if (!empty($countries)) {
        $want[PREFIX . 'countries'] = [
            'type' => 'geoip', 'content' => implode("\n", $countries), 'proto' => 'IPv4,IPv6',
            'updatefreq' => '', 'description' => 'Block Lists: countries',
        ];
    }
}

$model = new Alias();
$text = file_get_contents('/conf/config.xml');
$report = [];

foreach (iterator_to_array($model->aliases->alias->iterateItems()) as $uuid => $alias) {
    $name = (string)$alias->name;
    if (strpos($name, PREFIX) !== 0 || isset($want[$name])) {
        continue;
    }
    /* named once by its own definition; any more is somebody else's reference */
    if (preg_match_all('/\b' . preg_quote($name, '/') . '\b/', $text) > 1) {
        $alias->enabled = '0';
        $report[] = $name . ': no longer chosen, but named elsewhere in the configuration - switched off, not removed';
    } else {
        $model->aliases->alias->del($uuid);
        $report[] = $name . ': removed';
    }
}

foreach ($want as $name => $values) {
    $node = $model->getByName($name);
    if ($node === null) {
        $node = $model->aliases->alias->Add();
        $node->name = $name;
        $report[] = $name . ': added';
    } else {
        $report[] = $name . ': kept';
    }
    $node->enabled = '1';
    $node->counters = '1';
    foreach ($values as $field => $value) {
        $node->$field = $value;
    }
}

$messages = [];
foreach ($model->performValidation() as $message) {
    $messages[] = $message->getField() . ': ' . $message->getMessage();
}
if (!empty($messages)) {
    echo json_encode(['status' => 'failed', 'changes' => [], 'errors' => $messages]) . "\n";
    exit(0);
}
$model->serializeToConfig();
Config::getInstance()->save();
echo json_encode(['status' => 'ok', 'changes' => $report]) . "\n";
