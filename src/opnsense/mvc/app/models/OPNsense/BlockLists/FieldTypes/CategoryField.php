<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\BlockLists\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;

/**
 * UT1's web categories to choose from (2026-11-19): those of the catalogue shipped with the plugin
 * (scripts/blocklists/categories.json), then those UT1's own catalogue adds where categories.py fetched
 * it (/var/db/os-blocklists/categories/catalogue.json). Never one that cannot be chosen - adult, decision
 * d2, whatever a catalogue says - and never a key that is not a category name. Each option says the
 * category's size where it was counted: its names, and the memory they would take in Unbound, an
 * estimate at bytes_per_name a name (categories.json). A value that is not an option fails the model's
 * validation, as an OptionField's does - but a category saved that no catalogue holds now (one UT1's
 * catalogue added, where that catalogue was lost with /var in memory, until categories.py fetches it
 * again) stays an option, marked so, rather than vanish from the field and from the next save.
 */
class CategoryField extends BaseListField
{
    /* never offered, whatever a catalogue says: categories.py and the handler refuse them too */
    const REFUSED = ['adult'];

    public static $shipped = '/usr/local/opnsense/scripts/blocklists/categories.json';
    public static $fetched = '/var/db/os-blocklists/categories/catalogue.json';

    private static $cache = null;

    /* the categories a catalogue holds that cannot be chosen: never kept as a saved value either */
    private static $refused = [];

    /**
     * a translated format filled, or the English one where the translation's %s do not fit
     */
    private static function fill($format, $english, ...$args)
    {
        foreach ([$format, $english] as $candidate) {
            try {
                $result = @vsprintf($candidate, $args);
            } catch (\Throwable $e) {
                $result = false;
            }
            if (is_string($result)) {
                return $result;
            }
        }
        return $english;
    }

    /**
     * @return array id => label, sorted by label
     */
    public static function catalogueOptions($shipped = null, $fetched = null)
    {
        $meta = json_decode((string)@file_get_contents($shipped ?? self::$shipped), true);
        $extra = json_decode((string)@file_get_contents($fetched ?? self::$fetched), true);
        $per_name = is_array($meta) && is_int($meta['bytes_per_name'] ?? null) && $meta['bytes_per_name'] > 0 ?
            $meta['bytes_per_name'] : 527;
        $found = [];
        foreach ([$meta, $extra] as $source) {
            $entries = is_array($source) && is_array($source['categories'] ?? null) ? $source['categories'] : [];
            foreach ($entries as $id => $entry) {
                if (!is_string($id) || !preg_match('/^[a-z0-9][a-z0-9_-]{0,63}$/D', $id) || isset($found[$id]) ||
                    !is_array($entry)) {
                    continue;
                }
                $archive = is_string($entry['archive'] ?? null) ? $entry['archive'] : $id;
                if (in_array($id, self::REFUSED, true) || in_array($archive, self::REFUSED, true) ||
                    !empty($entry['refused'])) {
                    $found[$id] = false;    /* and no later catalogue offers it either */
                    self::$refused[$id] = true;
                    continue;
                }
                /* one line, no control characters and no < or >, as categories.py's plain() makes UT1's text */
                $name = preg_replace('/[^\x20-\x7e\x{a0}-\x{ffff}]/u', '', str_replace(['<', '>'], ' ', (string)($entry['name'] ?? '')));
                $name = trim(preg_replace('/\s+/u', ' ', $name ?? '') ?? '');
                $name = function_exists('mb_substr') ? mb_substr($name, 0, 80) : substr($name, 0, 80);
                /* in the page's language: the shipped names are msgids of the catalogue, as these texts are */
                $shown = $name !== '' ? gettext($name) : $id;
                $names = $entry['names'] ?? null;
                if (is_int($names) && $names >= 0) {
                    $bytes = $names * $per_name;
                    $size = $bytes < 1048576 ? gettext('under 1 MiB') :
                        self::fill(gettext('%s MiB'), '%s MiB', number_format(round($bytes / 1048576)));
                    $label = self::fill(gettext('%s (%s): about %s names, %s'), '%s (%s): about %s names, %s',
                        $shown, $id, number_format($names), $size);
                } else {
                    $label = self::fill(gettext('%s (%s)'), '%s (%s)', $shown, $id);
                }
                $found[$id] = $label;
            }
        }
        $found = array_filter($found, function ($label) {
            return $label !== false;
        });
        natcasesort($found);
        return $found;
    }

    protected function actionPostLoadingEvent()
    {
        if (self::$cache === null) {
            self::$cache = self::catalogueOptions();
        }
        $options = self::$cache;
        /* a category saved that no catalogue holds now: kept, marked, so it is neither hidden nor dropped */
        foreach (explode(',', (string)$this->internalValue) as $id) {
            if (
                $id !== '' && !isset($options[$id]) && preg_match('/^[a-z0-9][a-z0-9_-]{0,63}$/D', $id) &&
                !in_array($id, self::REFUSED, true) && !isset(self::$refused[$id])
            ) {
                $options[$id] = self::fill(gettext('%s (not in the catalogue now)'), '%s (not in the catalogue now)', $id);
            }
        }
        $this->internalOptionList = $options;
    }
}
