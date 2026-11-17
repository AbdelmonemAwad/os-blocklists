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
 *
 * A command-and-control list (feeds.json "c2": true) has one more rule when outbound is blocked,
 * registered before the table's others: `block in log quick ... to <blocklists_<id>>`, described
 * "Block Lists: blocklists_<id> from inside", logged whatever the "log" setting. The "out" rule
 * matches where the packet leaves the firewall, after outbound NAT, so behind NAT its log line names
 * the firewall's own WAN address (seen on an XGS 3300, 2026-11-16) and not the device; this one
 * matches where the packet enters from the LAN, before NAT, and its log line carries the device's own
 * address - os-netreport reads it by that description (from /tmp/rules.debug, so the rule keeps the
 * label OPNsense gives it). One log line per blocked packet, about 220 bytes (270 for TCP): a device
 * that keeps trying grows the filter log by that much a try.
 *
 * Order (OPNsense 26.7, Firewall\Plugin): registerFilterRule() files a rule under its priority, the
 * rules are written priority by priority (ksort), and within one priority in the order registered.
 * Every rule here is priority 1, so "from inside" is first for its table; quick, the first match is
 * the last.
 */

use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Plugin;

/*
 * The inside interfaces, as a rule's interface list: those of the firewall's own networks, where a
 * device's packet enters before outbound NAT - an address of their own (a static IPv4 address, or IPv6
 * static or tracked) and no gateway, IPv4 or IPv6, in the filter's interface mapping (filter.lib.inc
 * gives a WAN its gateway; one taking its address from DHCP or PPPoE has no static address, its lease
 * there or not). Until 2026-11-17 the rule had no interface: it blocked what came in on the WAN to an
 * address of the firewall itself on a list, ahead of the anti-lockout rule, and logged the internet's
 * senders as "from inside".
 */
function blocklists_inside(Plugin $fw)
{
    $inside = [];
    foreach ($fw->getInterfaceMapping() as $key => $intf) {
        if (!empty($intf['gateway']) || !empty($intf['gatewayv6'])) {
            continue;
        }
        $v4 = (string)($intf['ipaddr'] ?? '');
        $v6 = (string)($intf['ipaddrv6'] ?? '');
        if (is_ipaddrv4($v4) || $v6 === 'track6' || is_ipaddrv6($v6)) {
            $inside[] = $key;
        }
    }
    return $inside;
}

function blocklists_firewall(Plugin $fw)
{
    global $config;

    $general = $config['OPNsense']['BlockLists']['general'] ?? [];
    if (($general['enabled'] ?? '1') !== '1') {
        return;
    }
    $both = ($general['direction'] ?? 'both') === 'both';
    $log = ($general['log'] ?? '0') === '1';
    $inside = $both ? implode(',', blocklists_inside($fw)) : '';

    /*
     * Only the names this plugin makes are its own - the set apply.php, cut.py and status.py use too.
     * Until 2026-10-29 every alias named blocklists_* was blocked here, so one of the owner's by such a
     * name - a list of exceptions, say - was blocked both ways before his own rules.
     */
    $owned = ['blocklists_countries' => true];
    $c2 = [];
    $path = defined('BLOCKLISTS_FEEDS') ? BLOCKLISTS_FEEDS : '/usr/local/opnsense/scripts/blocklists/feeds.json';
    $feeds = json_decode((string)@file_get_contents($path), true);
    if (is_array($feeds)) {
        foreach ($feeds as $id => $feed) {
            $owned['blocklists_' . $id] = true;
            if (is_array($feed) && ($feed['c2'] ?? false) === true) {
                $c2['blocklists_' . $id] = true;
            }
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
            if ($both && isset($c2[$name]) && $inside !== '') {
                $fw->registerFilterRule(1, [
                    'ipprotocol' => $family,
                    'descr' => 'Block Lists: ' . $name . ' from inside',
                    'interface' => $inside,
                    'to' => '<' . $name . '>',
                    'direction' => 'in',
                    'type' => 'block',
                    'log' => true,
                    'quick' => true,
                ]);
            }
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
