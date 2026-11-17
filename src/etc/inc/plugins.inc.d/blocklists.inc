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
 * registered before the table's others: `block in log quick ... to <blocklists_<id>>` on the inside
 * interfaces (blocklists_inside(), below; none, no rule), described "Block Lists: blocklists_<id> from
 * inside", logged whatever the "log" setting. On an inside interface it comes before every other rule,
 * the anti-lockout rule too (priority 5, filter.lib.inc:579-595): should the firewall's own public
 * address be on the list, a device inside reaching it - the GUI by the firewall's public name, a port
 * forward through NAT reflection - is blocked and logged by it as well. The "out" rule
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
 * device's packet enters before outbound NAT. One is inside when it has an address of its own - a
 * static IPv4 address, or IPv6 static, tracked (track6) or by identity association (idassoc6), which
 * OPNsense 26.7 treats alike (interfaces.inc:709) - and nothing says it leads out:
 *
 *  - no gateway names it: none of the gateways the filter was given ($fw->getGateways(), Gateways.php:
 *    getGateways()), IPv4 or IPv6, switched off, defunct or without an address alike, and none chosen in
 *    its own gateway rules (interfaces.php: "IPv4/IPv6 gateway rules"). The filter's interface mapping
 *    alone, which this read until 2026-11-17, gives no gateway to a static WAN whose gateway rules are
 *    Disabled or whose gateway is left to auto-detect, nor to one whose gateway is switched off
 *    (filter.lib.inc:64-73, Gateways.php:591-617): such a WAN was taken for inside;
 *  - its address is not taken from outside, in either family: anything but none, a static address,
 *    track6, idassoc6 or link-local - DHCP, PPPoE, PPTP, L2TP, PPP; DHCPv6, SLAAC, 6rd, 6to4, PPPoEv6 -
 *    its lease there or not. A DHCP WAN without its lease and with a static IPv6 address was taken for
 *    inside until 2026-11-17;
 *  - it is not virtual: the loopback (pf skips it, filter.inc:373), a VPN or interface group, IPsec's
 *    enc0 - OPNsense's own bogon rules leave them out the same way (filter.lib.inc:332).
 *
 * The cost: a LAN with a router behind it, which has a gateway for that router's networks, is left out
 * too. 26.7's "Upstream Gateway" mark (Gateways.xml defaultgw) cannot tell such a router from a WAN's:
 * it is off unless ticked, a WAN on DHCP never carries it, and a gateway without it still becomes the
 * default route when no marked one is up (Gateways.php:314-324, 490-512). Its devices are still blocked
 * by the outbound rule, logged as the log setting says - behind NAT by the firewall's WAN address.
 *
 * Without the gateways (a Plugin the filter did not set up) nothing is inside. A name that would make
 * an empty element of the list - "" or "0", which OPNsense's Rule takes for no interface and writes as
 * a floating rule (Rule.php:271, 402-413) - or that holds a comma is never put in it. Until 2026-11-17
 * the rule had no interface at all: it blocked what came in on the WAN to an address of the firewall
 * itself on a list, ahead of the anti-lockout rule, and logged the internet's senders as "from inside".
 */
function blocklists_inside(Plugin $fw)
{
    global $config;

    $gateways = $fw->getGateways();
    if ($gateways === null) {
        return [];
    }
    $named = [];
    foreach ($gateways->getGateways() as $gateway) {
        if (!empty($gateway['interface'])) {
            $named[(string)$gateway['interface']] = true;
        }
    }

    $inside = [];
    foreach ($fw->getInterfaceMapping() as $key => $intf) {
        $key = (string)$key;
        if (empty($key) || strpbrk($key, ", \t") !== false || !empty($intf['virtual']) || isset($named[$key])) {
            continue;
        }
        $own = $config['interfaces'][$key] ?? [];
        $own = isset($own[0]) && is_array($own[0]) ? $own[0] : $own;
        foreach (['gateway', 'gatewayv6'] as $field) {
            if (is_array($own) && !empty($own[$field]) && $own[$field] !== 'none') {
                continue 2;
            }
        }
        $v4 = (string)($intf['ipaddr'] ?? '');
        $v6 = (string)($intf['ipaddrv6'] ?? '');
        if (!in_array($v4, ['', 'none'], true) && !is_ipaddrv4($v4)) {
            continue;
        }
        if (!in_array($v6, ['', 'none', 'track6', 'idassoc6', 'linklocal'], true) && !is_ipaddrv6($v6)) {
            continue;
        }
        if (is_ipaddrv4($v4) || is_ipaddrv6($v6) || $v6 === 'track6' || $v6 === 'idassoc6') {
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
