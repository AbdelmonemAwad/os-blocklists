<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\BlockLists;

use OPNsense\Base\BaseModel;

class BlockLists extends BaseModel
{
    /**
     * A text of the plugin's scripts for the page (2026-11-19): categories.py's and lookup.py's T(), a
     * msgid and what fills its %s, translated by OPNsense's catalogue (gettext) and filled with its
     * values, each made a text the same way; a list of them one line, '; ' between; anything else as it
     * is. A translation whose %s do not fit its values falls back to the English, and that to the msgid,
     * so a page is never broken by one. The msgids are catalogued in i18n/ui/source.json, where
     * tools/check-strings.py finds them in the scripts.
     *
     * @param mixed $value a T() ({"text": msgid, "args": [...]}), a list of them, or a plain value
     * @return string
     */
    public static function text($value)
    {
        if (is_array($value) && isset($value['text']) && is_string($value['text'])) {
            if ($value['text'] === '') {
                return '';
            }
            $args = [];
            foreach ((is_array($value['args'] ?? null) ? $value['args'] : []) as $arg) {
                $args[] = self::text($arg);
            }
            foreach ([gettext($value['text']), $value['text']] as $format) {
                try {
                    $result = @vsprintf($format, $args);
                } catch (\Throwable $e) {
                    $result = false;
                }
                if (is_string($result)) {
                    return $result;
                }
            }
            return $value['text'];
        }
        if (is_array($value)) {
            $parts = [];
            foreach ($value as $part) {
                $parts[] = self::text($part);
            }
            return implode('; ', array_filter($parts, 'strlen'));
        }
        if (is_bool($value)) {
            return $value ? '1' : '0';
        }
        return is_scalar($value) ? (string)$value : '';
    }
}
