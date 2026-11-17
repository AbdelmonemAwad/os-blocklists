<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * ThreatFox's list on the PHP side: apply.php, run as configd runs it with OPNsense's classes stood in
 * for by a script/load_phalcon.php of this test's own on the include path, makes its alias an external
 * one while an abuse.ch Auth-Key is saved - the key read as OPNsense's UpdateOnlyTextField gives it,
 * by getValue(), (string) of it being always "" - and, without a key, makes none, removes the one there
 * and says why; and the Settings tab's Remove the key (SettingsController.php, forgetKeyAction()) takes
 * the key out of config.xml under its lock, and only for a POST of a user who may write. No OPNsense
 * needed:
 *
 *   php tools/test-threatfox.php
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

/* an Auth-Key no account has: the tests' own */
const FAKE_KEY = 'test-only-not-a-real-auth-key-0000';

$stub = sys_get_temp_dir() . '/blocklists-threatfox-' . getmypid();
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
    /* OPNsense's UpdateOnlyTextField: (string) always "", getValue() what is saved */
    class StubKey
    {
        private $value;

        public function __construct($value)
        {
            $this->value = $value;
        }

        public function __toString()
        {
            return '';
        }

        public function getValue()
        {
            return $this->value;
        }
    }

    class BlockLists
    {
        public $general;

        public function __construct()
        {
            $given = json_decode(getenv('BLOCKLISTS_TEST_SETTINGS'), true);
            $this->general = (object)$given;
            $this->general->threatfox_key = new StubKey($given['threatfox_key'] ?? '');
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

/* apply.php as configd runs it: [the aliases it saved, its answer, all it printed] */
function apply($stub, $settings, $aliases = [])
{
    global $root;
    putenv('BLOCKLISTS_TEST_SETTINGS=' . json_encode($settings));
    putenv('BLOCKLISTS_TEST_ALIASES=' . json_encode((object)$aliases));
    $out = [];
    /* config.xml is not there: its warning goes to stderr, apart from the answer */
    exec(escapeshellarg(PHP_BINARY) . ' -d display_errors=stderr -d include_path=' . escapeshellarg($stub) . ' '
        . escapeshellarg($root . '/src/opnsense/scripts/blocklists/apply.php') . ' 2>/dev/null', $out, $rc);
    $saved = null;
    foreach ($out as $line) {
        if (strpos($line, 'STUB serialized ') === 0) {
            $saved = json_decode(substr($line, strlen('STUB serialized ')), true);
        }
    }
    $byname = [];
    foreach ($saved ?? [] as $alias) {
        $byname[$alias['name']] = $alias;
    }
    return [$byname, json_decode(end($out) ?: 'null', true), implode("\n", $out)];
}

$settings = ['enabled' => '1', 'feeds' => 'feodo,threatfox', 'refresh' => 'h2', 'countries' => '',
    'threatfox_key' => FAKE_KEY];

[$aliases, $answer, $printed] = apply($stub, $settings);
$tf = $aliases['blocklists_threatfox'] ?? [];
check(($answer['status'] ?? '') === 'ok', 'apply.php answered: ' . json_encode($answer));
check(($tf['type'] ?? '') === 'external', 'ThreatFox chosen, a key saved: its alias made, an external one: ' . json_encode($tf));
check(($tf['enabled'] ?? '') === '1' && ($tf['counters'] ?? '') === '1' && ($tf['content'] ?? null) === ''
    && ($tf['proto'] ?? null) === '' && ($tf['updatefreq'] ?? null) === '', 'on, counted, empty - its table is '
    . 'threatfox.py\'s - both families, no fetch frequency of OPNsense\'s');
check(($tf['description'] ?? '') === 'Block Lists: ThreatFox: command-and-control addresses', 'described as the '
    . 'other lists: ' . ($tf['description'] ?? '-'));
check(($aliases['blocklists_feodo']['type'] ?? '') === 'urltable'
    && ($aliases['blocklists_feodo']['updatefreq'] ?? '') === '0.083333', 'Feodo beside it, a URL table as before');
check(in_array('blocklists_threatfox: added', $answer['changes'] ?? [], true), 'said: added');
check(strpos($printed, FAKE_KEY) === false, 'the key in nothing apply.php prints');

$settings['threatfox_key'] = '';
[$aliases, $answer, $printed] = apply($stub, $settings);
check(!isset($aliases['blocklists_threatfox']) && isset($aliases['blocklists_feodo']), 'no key saved: no ThreatFox alias '
    . 'made, Feodo as before');
check(in_array('blocklists_threatfox: no abuse.ch Auth-Key saved - not made, nothing fetched', $answer['changes'] ?? [], true)
    && ($answer['status'] ?? '') === 'ok', 'no key saved: said why: ' . json_encode($answer['changes'] ?? null));

$there = ['u-tf' => ['name' => 'blocklists_threatfox', 'type' => 'external', 'enabled' => '1', 'content' => '',
    'proto' => '', 'updatefreq' => '', 'description' => 'Block Lists: ThreatFox: command-and-control addresses',
    'counters' => '1']];
[$aliases, $answer] = apply($stub, $settings, $there);
check(!isset($aliases['blocklists_threatfox']) && in_array('blocklists_threatfox: removed', $answer['changes'] ?? [], true),
    'the key removed: the alias there removed, as an unchosen list\'s: ' . json_encode($answer['changes'] ?? null));

$settings['threatfox_key'] = FAKE_KEY;
$settings['feeds'] = 'feodo';
[$aliases, $answer] = apply($stub, $settings, $there);
check(!isset($aliases['blocklists_threatfox']) && in_array('blocklists_threatfox: removed', $answer['changes'] ?? [], true)
    && !preg_grep('/Auth-Key/', $answer['changes'] ?? []), 'ThreatFox no longer chosen, a key saved: removed, nothing '
    . 'said of the key');
$settings['feeds'] = 'feodo,threatfox';
$settings['enabled'] = '0';
[$aliases, $answer] = apply($stub, $settings, $there);
check(!isset($aliases['blocklists_threatfox']) && !preg_grep('/Auth-Key/', $answer['changes'] ?? []),
    'Block Lists off: removed');
$settings['enabled'] = '1';
[$aliases, $answer] = apply($stub, $settings, $there);
check(($aliases['blocklists_threatfox']['type'] ?? '') === 'external' && in_array('blocklists_threatfox: kept',
    $answer['changes'] ?? [], true), 'chosen again with its alias there: kept');

/*
 * Remove the key (Api/SettingsController.php, forgetKeyAction()), run with OPNsense's classes stood in
 * for: the controller base (a POST or not, a read-only user) and Config (its lock, its object, its save).
 * The configuration is a tree of plain objects here, not SimpleXML, which a PHP may lack: isset() and
 * unset() of a chain of elements read the same on both.
 */
file_put_contents($stub . '/forget.php', <<<'STUB'
<?php
namespace OPNsense\Base {
    class ApiMutableModelControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new \StubRequest();
        }

        protected function throwReadOnly()
        {
            if (getenv('BLOCKLISTS_TEST_READONLY') === '1') {
                throw new \Exception('read-only');
            }
        }
    }
}

namespace OPNsense\Core {
    class Config
    {
        private static $me;
        public $xml;
        public $did = [];

        public static function getInstance()
        {
            return self::$me ??= new Config();
        }

        public function __construct()
        {
            $this->xml = json_decode(getenv('BLOCKLISTS_TEST_CONFIG'));
        }

        public function lock()
        {
            $this->did[] = 'lock';
        }

        public function unlock()
        {
            $this->did[] = 'unlock';
        }

        public function object()
        {
            $this->did[] = 'object';
            return $this->xml;
        }

        public function save()
        {
            $this->did[] = 'save';
        }
    }
}

namespace {
    class StubRequest
    {
        public function isPost()
        {
            return getenv('BLOCKLISTS_TEST_POST') === '1';
        }
    }

    require getenv('BLOCKLISTS_TEST_CONTROLLER');
    try {
        $answer = (new \OPNsense\BlockLists\Api\SettingsController())->forgetKeyAction();
    } catch (\Exception $e) {
        $answer = ['refused' => $e->getMessage()];
    }
    $config = \OPNsense\Core\Config::getInstance();
    echo json_encode(['answer' => $answer, 'did' => $config->did, 'config' => json_encode($config->xml)]) . "\n";
}
STUB);

/* forgetKeyAction() on a config.xml: [what it answered, did and left, all it printed] */
function forget($stub, $config, $post = true, $readonly = false)
{
    global $root;
    putenv('BLOCKLISTS_TEST_CONFIG=' . $config);
    putenv('BLOCKLISTS_TEST_POST=' . ($post ? '1' : ''));
    putenv('BLOCKLISTS_TEST_READONLY=' . ($readonly ? '1' : ''));
    putenv('BLOCKLISTS_TEST_CONTROLLER=' . $root . '/src/opnsense/mvc/app/controllers/OPNsense/BlockLists/Api/SettingsController.php');
    $out = [];
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($stub . '/forget.php') . ' 2>&1', $out, $rc);
    return [json_decode(end($out) ?: 'null', true), implode("\n", $out)];
}

$general = ['enabled' => '1', 'feeds' => 'threatfox', 'threatfox_key' => FAKE_KEY];
$with = json_encode(['OPNsense' => ['BlockLists' => ['general' => $general]]]);
[$r, $printed] = forget($stub, $with);
unset($general['threatfox_key']);
check(($r['answer'] ?? null) === ['status' => 'ok', 'key' => false]
    && ($r['config'] ?? '') === json_encode(['OPNsense' => ['BlockLists' => ['general' => $general]]]),
    'Remove the key: the key taken out of the configuration, nothing else: ' . $printed);
check(($r['did'] ?? null) === ['lock', 'object', 'save'], 'under the lock, then saved once: ' . json_encode($r['did'] ?? null));
check(strpos(json_encode($r['answer'] ?? ''), FAKE_KEY) === false, 'its answer never the key');
[$r] = forget($stub, json_encode(['OPNsense' => ['BlockLists' => ['general' => ['enabled' => '1']]]]));
check(($r['answer']['status'] ?? '') === 'ok' && ($r['did'] ?? null) === ['lock', 'object', 'unlock'],
    'no key saved: nothing saved, the lock let go: ' . json_encode($r['did'] ?? null));
[$r] = forget($stub, '{}');
check(($r['answer']['status'] ?? '') === 'ok' && ($r['did'] ?? null) === ['lock', 'object', 'unlock'],
    'no Block Lists settings at all: nothing saved');
[$r] = forget($stub, $with, false);
check(($r['answer'] ?? null) === ['status' => 'failed'] && ($r['did'] ?? null) === []
    && strpos($r['config'] ?? '', FAKE_KEY) !== false, 'not a POST: refused, the key kept');
[$r] = forget($stub, $with, true, true);
check(isset($r['answer']['refused']) && ($r['did'] ?? null) === [] && strpos($r['config'] ?? '', FAKE_KEY) !== false,
    'a read-only user: refused, the key kept');

@unlink($stub . '/forget.php');
@unlink($stub . '/script/load_phalcon.php');
@rmdir($stub . '/script');
@rmdir($stub);

echo ($failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n");
exit($failed ? 1 : 0);
