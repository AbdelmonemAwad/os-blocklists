<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The web categories on the PHP side (2026-11-19): the model's CategoryField offers the categories of the
 * shipped categories.json and those UT1's own catalogue adds, never adult and never a key that is not a
 * category name, each with its size; the exceptions' mask (BlockLists.xml) takes names and nothing else;
 * and the Lookup tab's controller takes a host name or an address and nothing else. The page's texts
 * of the scripts (T()) and of the field are given in the page's language, a translation whose %s do not
 * fit falling back to the English (BlockLists::text(), CategoryField). OPNsense's BaseListField and
 * BaseModel are stood in for, and gettext by a catalogue of the test's own; no OPNsense needed:
 *
 *   php tools/test-categories.php
 */

namespace OPNsense\Base\FieldTypes {
    /* OPNsense's BaseListField, as far as CategoryField uses it: the options it sets after loading */
    abstract class BaseListField
    {
        protected $internalOptionList = [];
        protected $internalValue = '';

        public function loaded($value = '')
        {
            $this->internalValue = $value;
            $this->actionPostLoadingEvent();
            return $this->internalOptionList;
        }

        protected function actionPostLoadingEvent()
        {
        }
    }
}

namespace OPNsense\Base {
    /* OPNsense's BaseModel: nothing of it is used by BlockLists::text() */
    class BaseModel
    {
    }
}

namespace OPNsense\BlockLists {
    /* gettext as the classes of these namespaces call it, with a catalogue of the test's own */
    function gettext($text)
    {
        return $GLOBALS['translations'][$text] ?? $text;
    }
}

namespace OPNsense\BlockLists\FieldTypes {
    function gettext($text)
    {
        return $GLOBALS['translations'][$text] ?? $text;
    }
}

namespace {
    $root = dirname(__DIR__);
    $GLOBALS['translations'] = [];
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

    require $root . '/src/opnsense/mvc/app/models/OPNsense/BlockLists/FieldTypes/CategoryField.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/BlockLists/BlockLists.php';

    use OPNsense\BlockLists\BlockLists;
    use OPNsense\BlockLists\FieldTypes\CategoryField;

    /* the scripts' texts, T(), made the page's: English with no translation, then translated */
    $t = function ($text, ...$args) {
        return ['text' => $text, 'args' => $args];
    };
    $state = [$t('%s names, fetched %s', '95,180', '2026-11-19 03:41 UTC'), $t('the copy of UT1 of %s', 'Wed, 18 Nov 2026'),
        $t('not fetched at %s: %s - the last copy is kept', '2026-11-19 05:41 UTC', $t('UT1 answered HTTP %s', 500))];
    check(BlockLists::text($state) === '95,180 names, fetched 2026-11-19 03:41 UTC; the copy of UT1 of Wed, 18 Nov 2026; '
        . 'not fetched at 2026-11-19 05:41 UTC: UT1 answered HTTP 500 - the last copy is kept',
        'text: a list of T(), nested ones filled in, in English: ' . BlockLists::text($state));
    $GLOBALS['translations'] = [
        '%s names, fetched %s' => '<%s> N <%s>',
        'the copy of UT1 of %s' => 'C %s %s',               /* one %s too many: the English is used */
        'UT1 answered HTTP %s' => 'H %s',
        'not fetched at %s: %s - the last copy is kept' => 'F %s : %s K',
        'Gambling' => 'G-ar', '%s (%s): about %s names, %s' => '[%s|%s|%s|%s]', '%s MiB' => '%s M',
        'under 1 MiB' => '<1M', 'Dialers' => 'D-ar', '%s (%s)' => '{%s/%s}',
    ];
    check(BlockLists::text($state) === '<95,180> N <2026-11-19 03:41 UTC>; the copy of UT1 of Wed, 18 Nov 2026; '
        . 'F 2026-11-19 05:41 UTC : H 500 K',
        'text: translated, nested ones too; a translation whose %s do not fit gives the English: ' . BlockLists::text($state));
    check(BlockLists::text('') === '' && BlockLists::text($t('')) === '' && BlockLists::text(null) === ''
        && BlockLists::text(7) === '7' && BlockLists::text([$t('UT1 answered HTTP %s')]) === 'UT1 answered HTTP %s',
        'text: nothing, an empty msgid, a number; a T() missing its value - its English as it is, no error');
    $label = CategoryField::catalogueOptions($root . '/src/opnsense/scripts/blocklists/categories.json', '/nonexistent')['gambling'];
    check(preg_match('/^\[G-ar\|gambling\|[0-9,]+\|[0-9,]+ M\]$/', $label) === 1,
        'CategoryField: an option in the page\'s language - its name, its format, its size: ' . $label);
    check(strpos(CategoryField::catalogueOptions($root . '/src/opnsense/scripts/blocklists/categories.json', '/nonexistent')['dialer'],
        '[D-ar|dialer|') === 0, 'CategoryField: a small one translated too');
    $GLOBALS['translations'] = [];

    $shipped = $root . '/src/opnsense/scripts/blocklists/categories.json';
    $tmp = sys_get_temp_dir() . '/blocklists-categories-php-' . getmypid();
    @mkdir($tmp, 0700, true);
    $fetched = $tmp . '/catalogue.json';

    /* the shipped catalogue alone: UT1's catalogue not fetched */
    $options = CategoryField::catalogueOptions($shipped, $tmp . '/none.json');
    $catalogue = json_decode(file_get_contents($shipped), true)['categories'];
    check(!isset($options['adult']), 'CategoryField: adult never offered');
    check(count($options) === count($catalogue) - 1, sprintf('CategoryField: every other shipped category offered (%d)', count($options)));
    check(($options['gambling'] ?? '') === sprintf('Gambling (gambling): about %s names, %s MiB',
        number_format($catalogue['gambling']['names']), number_format(round($catalogue['gambling']['names'] * 820 / 1048576))),
        'CategoryField: an option says its names and the memory they take, at 820 bytes a name: ' . ($options['gambling'] ?? ''));
    check(strpos($options['dialer'] ?? '', 'under 1 MiB') !== false, 'CategoryField: a small one, under 1 MiB: ' . ($options['dialer'] ?? ''));
    $labels = array_values($options);
    $sorted = $labels;
    natcasesort($sorted);
    check($labels === array_values($sorted), 'CategoryField: the options in the order of their labels');

    /* UT1's catalogue fetched: what it adds, and what it cannot */
    file_put_contents($fetched, json_encode(['fetched' => 1, 'categories' => [
        'newcat' => ['name' => 'New <b>one</b>', 'description' => 'x', 'use' => 'block'],
        'gambling' => ['name' => 'Not the shipped label'],
        'adult' => ['name' => 'Adult (X)'],
        'porn' => ['name' => 'Porn', 'archive' => 'adult'],
        'big' => ['name' => 'Big', 'refused' => 'too large'],
        '../x' => ['name' => 'Climbing'],
        'UPPER' => ['name' => 'Upper'],
        'list' => 'not an entry',
    ]]));
    $options = CategoryField::catalogueOptions($shipped, $fetched);
    check(($options['newcat'] ?? '') === 'New b one /b (newcat)', 'CategoryField: a category UT1 adds offered, no < or > in its label: ' . ($options['newcat'] ?? ''));
    check(strpos($options['gambling'], 'Gambling (gambling)') === 0, 'CategoryField: a shipped category keeps its own label');
    check(!isset($options['adult']) && !isset($options['porn']) && !isset($options['big']),
        'CategoryField: UT1\'s catalogue cannot offer adult, a category of its archive, or one refused');
    check(!isset($options['../x']) && !isset($options['UPPER']) && !isset($options['list']), 'CategoryField: a key that is not a category name left out');
    file_put_contents($fetched, '{not json');
    check(count(CategoryField::catalogueOptions($shipped, $fetched)) === count($catalogue) - 1, 'CategoryField: a broken fetched catalogue - the shipped one');
    check(CategoryField::catalogueOptions($tmp . '/none.json', $tmp . '/none.json') === [], 'CategoryField: no catalogue at all - nothing offered, nothing fails');
    @unlink($fetched);
    @rmdir($tmp);

    /* the field as the model loads it, from the installed places */
    CategoryField::$shipped = $shipped;
    CategoryField::$fetched = $tmp . '/none.json';
    $field = new CategoryField();
    check(isset($field->loaded()['gambling']) && !isset($field->loaded()['adult']), 'CategoryField: loaded by the model, the same options');
    $kept = (new CategoryField())->loaded('gambling,newcat,adult,../x,porn');
    check(($kept['newcat'] ?? '') === 'newcat (not in the catalogue now)' && isset($kept['gambling']) && !isset($kept['adult'])
        && !isset($kept['../x']), 'CategoryField: a category saved that no catalogue holds now kept as an option, marked; '
        . 'adult and a name that is not one still not');
    check(!isset((new CategoryField())->loaded('gambling')['newcat']), 'CategoryField: and only in the field that holds it');

    /* the exceptions' mask, as CSVListField applies it to each item: the whole item must match */
    /* read from BlockLists.xml as text: the runner's PHP need not have its XML extension */
    $model = file_get_contents($root . '/src/opnsense/mvc/app/models/OPNsense/BlockLists/BlockLists.xml');
    check(preg_match('#<exceptions type="CSVListField">.*?<Mask>(.*?)</Mask>#s', $model, $found) === 1, 'exceptions: the mask found');
    $mask = html_entity_decode(trim($found[1]), ENT_XML1);
    $item = function ($value) use ($mask) {
        $matches = [];
        preg_match($mask, $value, $matches);
        return isset($matches[0]) && $matches[0] == $value;
    };
    foreach (['example.com', 'www.example.com', 'Example.COM', 'a-b.example', 'x_y.example', 'example.com.evil.net'] as $good) {
        check($item($good), "exceptions: $good taken");
    }
    foreach (['', 'example', 'a b.com', 'example.com.', '.example.com', 'a..b', '-a.com', 'a-.com', '*.example.com',
              'example.com/path', "example.com\n", 'a.com;reboot', str_repeat('a', 64) . '.com'] as $bad) {
        check(!$item($bad), 'exceptions: ' . json_encode($bad) . ' refused');
    }

    /* the Lookup tab's controller: its check of the query, run as it is written there */
    $service = file_get_contents($root . '/src/opnsense/mvc/app/controllers/OPNsense/BlockLists/Api/ServiceController.php');
    check(preg_match('/\$host = (\'[^;]+);/s', $service, $found) === 1, 'controller: the host pattern found');
    $host = eval('return ' . $found[1] . ';');
    $taken = function ($query) use ($host) {
        $query = trim($query);
        return !($query === '' || strlen($query) > 254 ||
            (filter_var($query, FILTER_VALIDATE_IP) === false && !preg_match($host, $query)));
    };
    foreach (['example.com', 'www.Example.com.', 'casino.example', '198.51.100.7', '2001:db8::7', 'localhost'] as $good) {
        check($taken($good), "controller: $good taken");
    }
    foreach (['', 'a b.com', 'a.com;reboot', '$(reboot)', '`id`', 'a.com|sh', "a'b.com", '../etc', '-rf', 'example.com:443',
              '[2001:db8::1]', 'fe80::1%em0', '192.0.2.1/24', '*.example.com', "example.com\nx", str_repeat('a.', 128) . 'com'] as $bad) {
        check(!$taken($bad), 'controller: ' . json_encode($bad) . ' refused');
    }

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
