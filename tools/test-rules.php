<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The rule set plugins.inc.d/blocklists.inc registers, with stand-ins for OPNsense's Firewall\Plugin
 * (which records each rule and orders them as 26.7's does: by priority, then in the order registered)
 * and Firewall\Alias (the aliases given here). No OPNsense needed:
 *
 *   php tools/test-rules.php
 */

namespace OPNsense\Firewall {
    class Plugin
    {
        public $rules = [];
        /* the filter's interface mapping (filter.lib.inc): a LAN, a WAN with its gateway, a WAN on DHCP
           whose lease is not there yet, a transit with a gateway, an IPv6-only LAN tracking the WAN */
        public $mapping = [
            'lan' => ['if' => 'igb1', 'ipaddr' => '192.168.1.1', 'gateway' => null, 'gatewayv6' => null],
            'wan' => ['if' => 'igb0', 'ipaddr' => 'dhcp', 'gateway' => '203.0.113.1', 'gatewayv6' => null],
            'opt1' => ['if' => 'igb2', 'ipaddr' => 'dhcp', 'gateway' => null, 'gatewayv6' => null],
            'opt2' => ['if' => 'igb3', 'ipaddr' => '10.0.0.2', 'gateway' => '10.0.0.1', 'gatewayv6' => null],
            'opt3' => ['if' => 'igb4', 'ipaddr' => '', 'ipaddrv6' => 'track6', 'gateway' => null, 'gatewayv6' => null],
        ];

        public function getInterfaceMapping()
        {
            foreach ($this->mapping as $key => $intf) {
                yield $key => $intf;
            }
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

    function rules($general, $aliases, $mapping = null)
    {
        global $config;
        $config = ['OPNsense' => ['BlockLists' => ['general' => $general]]];
        \OPNsense\Firewall\Alias::$given = $aliases;
        $fw = new \OPNsense\Firewall\Plugin();
        if ($mapping !== null) {
            $fw->mapping = $mapping;
        }
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
    check(($r['interface'] ?? '') === 'lan,opt3', 'on the inside interfaces only - a static address and no gateway: '
        . 'not the WAN, not a DHCP one without its lease yet, not a transit with a gateway; an IPv6-only LAN tracking '
        . 'the WAN in');
    $none = described(rules(['enabled' => '1', 'direction' => 'both', 'log' => '0'], $aliases,
        ['wan' => ['if' => 'igb0', 'ipaddr' => 'dhcp', 'gateway' => '203.0.113.1', 'gatewayv6' => null]]),
        'Block Lists: blocklists_feodo from inside');
    check(count($none) === 0, 'no inside interface at all: no "from inside" rule, never a floating one');
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
