<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The rule set plugins.inc.d/blocklists.inc registers, with stand-ins for OPNsense's Firewall\Plugin
 * (which records each rule and orders them as 26.7's does: by priority, then in the order registered),
 * Routing\Gateways (getGateways(): the gateways given here) and Firewall\Alias (the aliases given
 * here). No OPNsense needed:
 *
 *   php tools/test-rules.php
 */

namespace OPNsense\Routing {
    /* 26.7's Gateways::getGateways(): every gateway, switched off, defunct or without an address alike,
       each with the interface it is on */
    class Gateways
    {
        public $list = [];

        public function __construct($list)
        {
            $this->list = $list;
        }

        public function getGateways()
        {
            return $this->list;
        }
    }
}

namespace OPNsense\Firewall {
    class Plugin
    {
        public $rules = [];
        /* the filter's interface mapping (filter.lib.inc:61-81), as test-rules' NET gives it */
        public $mapping = [];
        /* what setGateways() was given (filter.lib.inc:84); null, none */
        public $gateways = null;

        public function getInterfaceMapping()
        {
            foreach ($this->mapping as $key => $intf) {
                yield $key => $intf;
            }
        }

        public function getGateways()
        {
            return $this->gateways;
        }

        public function registerFilterRule($prio, $conf)
        {
            $this->rules[] = [$prio, count($this->rules), $conf];
        }

        /* 26.7: ksort() of the priorities, each priority's rules in the order registered */
        public function ordered()
        {
            $rules = $this->rules;
            usort($rules, function ($a, $b) {
                return [$a[0], $a[1]] <=> [$b[0], $b[1]];
            });
            return array_map(function ($r) {
                return $r[2];
            }, $rules);
        }
    }

    class AliasItems
    {
        public $items;

        public function iterateItems()
        {
            foreach ($this->items as $i => $item) {
                yield 'uuid-' . $i => $item;
            }
        }
    }

    class Alias
    {
        public static $given = [];
        public $aliases;

        public function __construct()
        {
            $this->aliases = (object)['alias' => new AliasItems()];
            $this->aliases->alias->items = array_map(function ($a) {
                return (object)$a;
            }, self::$given);
        }
    }
}

namespace {
    $root = dirname(__DIR__);
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

    $dir = sys_get_temp_dir() . '/blocklists-rules-' . getmypid();
    @mkdir($dir);
    define('BLOCKLISTS_FEEDS', $dir . '/feeds.json');
    file_put_contents(BLOCKLISTS_FEEDS, json_encode([
        'feodo' => ['proto' => 'IPv4', 'c2' => true],
        'spamhaus_drop' => ['proto' => 'IPv4'],
        'mixed_c2' => ['proto' => '', 'c2' => true],
        'not_c2' => ['proto' => 'IPv4', 'c2' => 'yes'],
    ]));
    /* OPNsense's util.inc, which the filter has loaded when it runs the hook */
    function is_ipaddrv4($a)
    {
        return filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    function is_ipaddrv6($a)
    {
        return filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    require $root . '/src/etc/inc/plugins.inc.d/blocklists.inc';

    /*
     * A firewall with one interface of each kind: the filter's interface mapping (filter.lib.inc:61-81
     * gives a gateway only for a gateway switched on, with an address, chosen in the interface's gateway
     * rules or dynamic - Gateways.php:591-617), the gateways the filter was given (getGateways()), and
     * each interface's own gateway rules in config.xml (26.7 stores none for "Disabled"; older configs
     * "none"). Each entry: [mapping, own gateway fields, inside or not, what it is].
     */
    function net()
    {
        $m = function ($if, $v4, $v6, $gw = null, $gw6 = null, $extra = []) {
            return array_merge(['if' => $if, 'ipaddr' => $v4, 'ipaddrv6' => $v6, 'gateway' => $gw, 'gatewayv6' => $gw6], $extra);
        };
        return [
            'lan' => [$m('igb1', '192.168.1.1', 'track6'), [], true, 'a LAN, static, IPv6 tracking the WAN'],
            'wan' => [$m('igb0', 'dhcp', 'dhcp6', '198.51.100.1', 'fe80::1'), [], false, 'a WAN on DHCP and DHCPv6, its leases there'],
            'opt1' => [$m('igb2', 'dhcp', 'dhcp6'), [], false, 'a WAN on DHCP and DHCPv6, no lease yet'],
            'opt2' => [$m('igb3', '10.0.0.2', null, '10.0.0.1'), ['gateway' => 'TRANSIT_GW'], false, 'a transit, static, its gateway chosen'],
            'opt3' => [$m('igb4', null, 'track6'), [], true, 'an IPv6-only LAN tracking the WAN'],
            'opt4' => [$m('igb5', null, '2001:db8:4::2', null, '2001:db8:4::1'), ['gatewayv6' => 'WAN6_GW'], false,
                'an IPv6-only WAN, static, its IPv6 gateway chosen and on'],
            'opt5' => [$m('igb6', null, '2001:db8:5::2'), [], false,
                'an IPv6-only WAN, static, IPv6 gateway rules Disabled, an IPv6 gateway on it'],
            'opt6' => [$m('igb7', '203.0.113.40', null), ['gateway' => 'none'], false,
                'a WAN, static, IPv4 gateway rules Disabled, a gateway on it (not marked upstream)'],
            'opt7' => [$m('igb8', '203.0.113.20', null), ['gateway' => 'WAN3_GW'], false,
                'a WAN, static, its chosen gateway switched off in System: Gateways'],
            'opt8' => [$m('igb9', '203.0.113.30', null), [], false,
                'a WAN, static, its gateway left to auto-detect (an upstream gateway on it)'],
            'opt9' => [$m('igb10', 'dhcp', '2001:db8:9::2'), [], false,
                'a WAN on DHCP, no lease yet, a static IPv6 address and no IPv6 gateway (its DHCP gateway defunct)'],
            'opt10' => [$m('igb11', 'dhcp', '2001:db8:10::2'), [], false,
                'a WAN on DHCP, no lease yet, a static IPv6 address, no gateway at all'],
            'opt11' => [$m('igb12', null, '2001:db8:11::2'), ['gatewayv6' => 'WAN11_GW6'], false,
                'an IPv6-only WAN, static, its chosen IPv6 gateway switched off'],
            'opt12' => [$m('igb13', null, '2001:db8:12::1'), [], true, 'an IPv6-only LAN, static'],
            'opt13' => [$m('igb14', null, 'idassoc6'), [], true, 'an IPv6-only LAN by identity association (idassoc6)'],
            'opt14' => [$m('igb15', null, 'linklocal'), [], false, 'link-local IPv6 only: no address of its own'],
            'opt15' => [$m('igb16', null, 'dhcp6'), [], false,
                'an IPv6-only WAN on DHCPv6 whose automatic gateway is missing (its name taken by another)'],
            'opt16' => [$m('igb17', '10.0.0.33', null), [], false, 'a LAN with a router behind it (a gateway for it): the cost'],
            'opt17' => [$m('igb18', '10.0.0.49', null), ['gateway' => 'OLD_GW'], false,
                'static, its gateway rules naming a gateway no longer there'],
            'opt18' => [$m('bridge0', '10.0.0.65', null), [], true, 'a bridge, static'],
            'opt19' => [$m('vlan0.10', '10.0.0.81', null), [], true, 'a VLAN, static'],
            'opt20' => [$m('ovpns1', null, null), [], false, 'an OpenVPN server assigned, no address'],
            'opt21' => [$m('igb19', 'none', null), [], false, 'ipaddr "none"'],
            'opt22' => [$m('pppoe0', 'pppoe', null), [], false, 'a WAN on PPPoE, its link down'],
            'opt23' => [$m('igb20', null, '2001:db8:23::2'), ['gatewayv6' => 'OLD_GW6'], false,
                'IPv6-only, static, its IPv6 gateway rules naming a gateway no longer there'],
            'opt24' => [$m('igb21', '10.0.0.97', 'slaac'), [], false,
                'static IPv4 and SLAAC, its automatic IPv6 gateway missing (its name taken by another)'],
            'opt25' => [$m('igb22', '203.0.113.50', null), [], false,
                'a WAN, static, IPv4 gateway rules Disabled, its only gateway switched off'],
            'lo0' => [$m('lo0', '127.0.0.1', '::1', null, null, ['virtual' => '1']), [], false,
                'the loopback (loopback.inc registers it, 127.0.0.1)'],
            'openvpn' => [$m('openvpn', null, null, null, null, ['virtual' => '1', 'type' => 'group']), [], false, 'the OpenVPN group'],
            'wireguard' => [$m('wireguard', null, null, null, null, ['virtual' => '1', 'type' => 'group']), [], false,
                'the WireGuard group'],
        ];
    }

    /* Gateways::getGateways() for net(): the loopback's two, dynamic ones as 26.7 adds them
       (Gateways.php:385-466), configured ones switched off or defunct included */
    function gateways()
    {
        return [
            ['name' => 'Null4', 'interface' => 'loopback', 'ipprotocol' => 'inet', 'gateway' => '127.0.0.1', 'is_loopback' => true],
            ['name' => 'Null6', 'interface' => 'loopback', 'ipprotocol' => 'inet6', 'gateway' => '::1', 'is_loopback' => true],
            ['name' => 'WAN_DHCP', 'interface' => 'wan', 'ipprotocol' => 'inet', 'gateway' => '198.51.100.1', 'dynamic' => true, 'virtual' => true],
            ['name' => 'WAN_DHCP6', 'interface' => 'wan', 'ipprotocol' => 'inet6', 'gateway' => 'fe80::1', 'dynamic' => true, 'virtual' => true],
            ['name' => 'OPT1_DHCP6', 'interface' => 'opt1', 'ipprotocol' => 'inet6', 'dynamic' => true, 'virtual' => true],
            ['name' => 'TRANSIT_GW', 'interface' => 'opt2', 'ipprotocol' => 'inet', 'gateway' => '10.0.0.1'],
            ['name' => 'OPT15_DHCP6', 'interface' => 'opt2', 'ipprotocol' => 'inet6', 'gateway' => '2001:db8:2::1'],
            ['name' => 'WAN6_GW', 'interface' => 'opt4', 'ipprotocol' => 'inet6', 'gateway' => '2001:db8:4::1'],
            ['name' => 'WAN6B_GW', 'interface' => 'opt5', 'ipprotocol' => 'inet6', 'gateway' => '2001:db8:5::1'],
            ['name' => 'WAN5_GW', 'interface' => 'opt6', 'ipprotocol' => 'inet', 'gateway' => '203.0.113.33'],
            ['name' => 'WAN3_GW', 'interface' => 'opt7', 'ipprotocol' => 'inet', 'gateway' => '203.0.113.17', 'disabled' => '1'],
            ['name' => 'WAN4_GW', 'interface' => 'opt8', 'ipprotocol' => 'inet', 'gateway' => '203.0.113.25', 'defaultgw' => '1'],
            ['name' => 'OPT9_DHCP', 'interface' => 'opt9', 'ipprotocol' => 'inet', 'dynamic' => true, 'defunct' => true],
            ['name' => 'WAN11_GW6', 'interface' => 'opt11', 'ipprotocol' => 'inet6', 'gateway' => '2001:db8:11::1', 'disabled' => '1'],
            ['name' => 'LAN_ROUTER', 'interface' => 'opt16', 'ipprotocol' => 'inet', 'gateway' => '10.0.0.34'],
            ['name' => 'OPT24_SLAAC', 'interface' => 'opt2', 'ipprotocol' => 'inet6', 'gateway' => '2001:db8:2::2'],
            ['name' => 'WAN7_GW', 'interface' => 'opt25', 'ipprotocol' => 'inet', 'gateway' => '203.0.113.49', 'disabled' => '1'],
        ];
    }

    function rules($general, $aliases, $mapping = null, $gateways = null, $interfaces = null)
    {
        global $config;
        $net = net();
        $config = ['OPNsense' => ['BlockLists' => ['general' => $general]],
            'interfaces' => $interfaces ?? array_map(function ($n) {
                return $n[1];
            }, $net)];
        \OPNsense\Firewall\Alias::$given = $aliases;
        $fw = new \OPNsense\Firewall\Plugin();
        $fw->mapping = $mapping ?? array_map(function ($n) {
            return $n[0];
        }, $net);
        $fw->gateways = $gateways === false ? null : new \OPNsense\Routing\Gateways($gateways ?? gateways());
        blocklists_firewall($fw);
        return $fw->ordered();
    }

    function described($rules, $descr)
    {
        return array_values(array_filter($rules, function ($r) use ($descr) {
            return $r['descr'] === $descr;
        }));
    }

    $aliases = [
        ['name' => 'blocklists_spamhaus_drop', 'enabled' => '1', 'proto' => 'IPv4'],
        ['name' => 'blocklists_feodo', 'enabled' => '1', 'proto' => 'IPv4'],
        ['name' => 'blocklists_mixed_c2', 'enabled' => '1', 'proto' => ''],
        ['name' => 'blocklists_not_c2', 'enabled' => '1', 'proto' => 'IPv4'],
    ];

    /* the log setting off, both ways (the defaults) */
    $rules = rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases);
    $inside = described($rules, 'Block Lists: blocklists_feodo from inside');
    check(count($inside) === 1, 'one "from inside" rule for feodo, IPv4 only');
    $r = $inside[0] ?? [];
    check(($r['to'] ?? '') === '<blocklists_feodo>' && !isset($r['from']), 'from any to <blocklists_feodo>');
    check(($r['direction'] ?? '') === 'in', 'direction in');
    $want = array_keys(array_filter(net(), function ($n) {
        return $n[2];
    }));
    check(($r['interface'] ?? '') === implode(',', $want), 'on the inside interfaces only: ' . implode(',', $want)
        . ', not ' . ($r['interface'] ?? '-'));
    $on = explode(',', $r['interface'] ?? '');
    foreach (net() as $key => $n) {
        check(in_array($key, $on, true) === $n[2], "$key, {$n[3]}: " . ($n[2] ? 'inside' : 'not inside'));
    }
    $none = described(rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases,
        ['wan' => ['if' => 'igb0', 'ipaddr' => 'dhcp', 'gateway' => '198.51.100.1', 'gatewayv6' => null]]),
        'Block Lists: blocklists_feodo from inside');
    check(count($none) === 0, 'no inside interface at all: no "from inside" rule, never a floating one');
    $none = described(rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases, null, false),
        'Block Lists: blocklists_feodo from inside');
    check(count($none) === 0, 'no gateways given to the filter: nothing taken for inside, no "from inside" rule');

    /* a name that would make an empty element of the list - "", "0" (PHP's empty()), or one with a
       comma - which OPNsense's Rule would write as a floating rule: never in it */
    $odd = ['lan' => net()['lan'][0], '' => net()['opt18'][0], 0 => net()['opt19'][0],
        'a,b' => net()['opt12'][0], 'c d' => net()['opt12'][0]];
    $odd_rule = described(rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases, $odd, [], []),
        'Block Lists: blocklists_feodo from inside')[0] ?? [];
    check(($odd_rule['interface'] ?? '') === 'lan', 'names "", "0", "a,b" and "c d" never in the list: '
        . ($odd_rule['interface'] ?? '-'));
    $odd_rules = described(rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases,
        ['' => net()['opt18'][0], 0 => net()['opt19'][0]], [], []), 'Block Lists: blocklists_feodo from inside');
    check(count($odd_rules) === 0, 'only such names: no "from inside" rule, never a floating one');
    check(($r['type'] ?? '') === 'block' && ($r['quick'] ?? false) === true, 'block, quick');
    check(($r['log'] ?? false) === true, 'logged with the log setting off');
    check(!isset($r['label']), 'no label of its own: OPNsense hashes it, and rules.debug carries the description');
    check(($r['ipprotocol'] ?? '') === 'inet', 'inet');
    $names = array_column($rules, 'descr');
    $first = array_search('Block Lists: blocklists_feodo from inside', $names, true);
    foreach (['in', 'out'] as $way) {
        $at = array_search('Block Lists: blocklists_feodo ' . $way, $names, true);
        check($at !== false && $first < $at, '"from inside" before feodo\'s ' . $way . ' rule');
    }
    foreach ($rules as $rule) {
        if (strpos($rule['descr'], 'from inside') === false) {
            check($rule['log'] === false, $rule['descr'] . ': follows the log setting (off)');
        }
    }
    check(count(described($rules, 'Block Lists: blocklists_spamhaus_drop from inside')) === 0, 'no "from inside" for a list not marked c2');
    check(count(described($rules, 'Block Lists: blocklists_not_c2 from inside')) === 0, '"c2" must be true, not just set');
    $mixed = described($rules, 'Block Lists: blocklists_mixed_c2 from inside');
    check(count($mixed) === 2 && $mixed[0]['ipprotocol'] === 'inet' && $mixed[1]['ipprotocol'] === 'inet6', 'a c2 list of both families: one per family');
    foreach (['inet', 'inet6'] as $family) {
        $of = array_values(array_filter($rules, function ($r) use ($family) {
            return $r['ipprotocol'] === $family && strpos($r['descr'], 'blocklists_mixed_c2') !== false;
        }));
        check(($of[0]['descr'] ?? '') === 'Block Lists: blocklists_mixed_c2 from inside', "$family: \"from inside\" first for its table");
    }
    check(count($rules) === 2 + 3 + 6 + 2, 'every rule accounted for (' . count($rules) . ')');

    /* the log setting on: the others log too, the inside rule as before */
    $rules = rules(['enabled' => '1', 'direction' => 'both', 'log' => '1'], $aliases);
    check(count(array_filter($rules, function ($r) {
        return $r['log'] !== true;
    })) === 0, 'log on: every rule logs');

    /* inbound only: nothing outbound is blocked, and no inside rule either */
    $rules = rules(['enabled' => '1', 'direction' => 'in', 'log' => '0'], $aliases);
    check(count(array_filter($rules, function ($r) {
        return ($r['direction'] ?? '') !== 'in' || isset($r['to']);
    })) === 0, 'inbound only: no rule to a listed address');

    /* an alias switched off, or the plugin off */
    $off = $aliases;
    $off[1]['enabled'] = '0';
    $rules = rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $off);
    check(count(described($rules, 'Block Lists: blocklists_feodo from inside')) === 0, 'feodo switched off: no inside rule');
    check(count(rules(['enabled' => '0'], $aliases)) === 0, 'plugin off: no rule');

    /* the catalogue itself: feodo is marked, a "c2" is true or absent */
    $real = json_decode(file_get_contents($root . '/src/opnsense/scripts/blocklists/feeds.json'), true);
    check(($real['feodo']['c2'] ?? null) === true, 'feeds.json: feodo is a command-and-control list');
    foreach ($real as $id => $feed) {
        check(!array_key_exists('c2', $feed) || $feed['c2'] === true, "feeds.json: $id's c2 is true or absent");
    }

    @unlink(BLOCKLISTS_FEEDS);
    @rmdir($dir);
    echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
    exit($failed ? 1 : 0);
}
