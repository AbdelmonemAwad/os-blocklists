<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * What the IPS drops (ff-10, 2026-11-19) on the PHP side: apply.php makes the alias blocklists_ids, an
 * external one, while "Block what the IPS drops" is on, and removes it when it is off or Block Lists is;
 * and the removers' own step (install/uninstall.sh, pkg/post-deinstall.sh) takes it out of config.xml,
 * run as they run it - its text taken from each - so no alias, and so no table, of it stays. OPNsense's
 * classes are stood in for by a script/load_phalcon.php of this test's own on the include path; no
 * OPNsense needed:
 *
 *   php tools/test-ids.php
 */

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

$stub = sys_get_temp_dir() . '/blocklists-ids-' . getmypid();
@mkdir($stub . '/script', 0700, true);
file_put_contents($stub . '/script/load_phalcon.php', <<<'STUB'
<?php
namespace OPNsense\Core {
    class Config
    {
        private static $me;

        public static function getInstance()
        {
            return self::$me ??= new Config();
        }

        public function save()
        {
            echo "STUB saved\n";
        }
    }
}

namespace OPNsense\BlockLists {
    class StubKey
    {
        public function __toString()
        {
            return '';
        }

        public function getValue()
        {
            return '';
        }
    }

    class BlockLists
    {
        public $general;

        public function __construct()
        {
            $this->general = (object)json_decode(getenv('BLOCKLISTS_TEST_SETTINGS'), true);
            $this->general->threatfox_key = new StubKey();
        }
    }
}

namespace OPNsense\Firewall {
    class StubItems
    {
        public $items = [];

        public function iterateItems()
        {
            foreach ($this->items as $uuid => $item) {
                yield $uuid => $item;
            }
        }

        public function Add()
        {
            $uuid = 'new-' . count($this->items);
            $this->items[$uuid] = new \stdClass();
            return $this->items[$uuid];
        }

        public function del($uuid)
        {
            unset($this->items[$uuid]);
        }
    }

    class Alias
    {
        public $aliases;

        public function __construct()
        {
            $this->aliases = (object)['alias' => new StubItems()];
            foreach (json_decode(getenv('BLOCKLISTS_TEST_ALIASES'), true) as $uuid => $alias) {
                $this->aliases->alias->items[$uuid] = (object)$alias;
            }
        }

        public function getByName($name)
        {
            foreach ($this->aliases->alias->items as $item) {
                if ((string)$item->name === $name) {
                    return $item;
                }
            }
            return null;
        }

        public function performValidation()
        {
            return [];
        }

        public function serializeToConfig()
        {
            echo 'STUB serialized ' . json_encode(array_map(function ($a) {
                return (array)$a;
            }, $this->aliases->alias->items)) . "\n";
        }
    }
}
STUB);

/* a script run as configd or a remover runs it: [the aliases it saved by name, or null; all it printed] */
function run_php($stub, $script, $settings, $aliases)
{
    putenv('BLOCKLISTS_TEST_SETTINGS=' . json_encode($settings));
    putenv('BLOCKLISTS_TEST_ALIASES=' . json_encode((object)$aliases));
    $out = [];
    exec(escapeshellarg(PHP_BINARY) . ' -d display_errors=stderr -d include_path=' . escapeshellarg($stub) . ' '
        . escapeshellarg($script) . ' 2>/dev/null', $out, $rc);
    $saved = null;
    foreach ($out as $line) {
        if (strpos($line, 'STUB serialized ') === 0) {
            $saved = [];
            foreach (json_decode(substr($line, strlen('STUB serialized ')), true) as $alias) {
                $saved[$alias['name']] = $alias;
            }
        }
    }
    return [$saved, implode("\n", $out)];
}

$apply = $root . '/src/opnsense/scripts/blocklists/apply.php';
$settings = ['enabled' => '1', 'feeds' => 'feodo', 'refresh' => 'h2', 'countries' => '', 'ids' => '1'];
[$aliases, $printed] = run_php($stub, $apply, $settings, []);
$ids = $aliases['blocklists_ids'] ?? [];
check(($ids['type'] ?? '') === 'external' && ($ids['content'] ?? null) === '' && ($ids['proto'] ?? null) === ''
    && ($ids['enabled'] ?? '') === '1' && ($ids['counters'] ?? '') === '1',
    'on: its alias made - external, its table ids_list.py\'s, both families, counted: ' . json_encode($ids));
check(($ids['description'] ?? '') === 'Block Lists: IPS drops', 'described as the other lists: ' . ($ids['description'] ?? '-'));
check(strpos($printed, 'blocklists_ids: added') !== false && isset($aliases['blocklists_feodo']), 'said: added; Feodo beside it');

$there = ['u-ids' => ['name' => 'blocklists_ids', 'type' => 'external', 'enabled' => '1', 'content' => '', 'proto' => '',
    'updatefreq' => '', 'description' => 'Block Lists: IPS drops', 'counters' => '1']];
[$aliases, $printed] = run_php($stub, $apply, ['ids' => '0'] + $settings, $there);
check(is_array($aliases) && !isset($aliases['blocklists_ids']) && strpos($printed, 'blocklists_ids: removed') !== false,
    'off: its alias removed');
[$aliases, $printed] = run_php($stub, $apply, ['enabled' => '0'] + $settings, $there);
check(is_array($aliases) && !isset($aliases['blocklists_ids']), 'Block Lists off: removed too');
[$aliases, $printed] = run_php($stub, $apply, ['feeds' => 'feodo,ids', 'ids' => '0'] + $settings, []);
check(is_array($aliases) && !isset($aliases['blocklists_ids']), 'ids written into the feeds by hand: no alias of it made');

/* the removers' step, as each carries it */
foreach (['install/uninstall.sh', 'pkg/post-deinstall.sh'] as $remover) {
    $text = file_get_contents($root . '/' . $remover);
    $start = strpos($text, "/usr/local/bin/php -r '\n");
    $end = strpos($text, "\n' > /dev/null 2>&1 || true", $start);
    check($start !== false && $end !== false, "$remover: the IPS drops' alias step found");
    $script = $stub . '/remove.php';
    file_put_contents($script, "<?php\n" . substr($text, $start + strlen("/usr/local/bin/php -r '\n"), $end - $start - strlen("/usr/local/bin/php -r '\n")) . "\n");
    $others = ['u-feodo' => ['name' => 'blocklists_feodo', 'type' => 'urltable', 'enabled' => '1'],
        'u-mine' => ['name' => 'my_list', 'type' => 'host', 'enabled' => '1']];
    [$aliases, $printed] = run_php($stub, $script, [], $others + $there);
    check(is_array($aliases) && !isset($aliases['blocklists_ids']) && isset($aliases['blocklists_feodo'])
        && isset($aliases['my_list']) && strpos($printed, 'STUB saved') !== false,
        "$remover: the IPS drops' alias taken out and config.xml saved; the other aliases left: " . json_encode(array_keys($aliases ?? [])));
    [$aliases, $printed] = run_php($stub, $script, [], $others);
    check($aliases === null && strpos($printed, 'STUB saved') === false, "$remover: no such alias - nothing saved");
}

array_map('unlink', glob($stub . '/script/*'));
@rmdir($stub . '/script');
@unlink($stub . '/remove.php');
@rmdir($stub);
echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
exit($failed ? 1 : 0);
