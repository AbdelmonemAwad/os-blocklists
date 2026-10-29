#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Block Lists plugin files. The rules go with the next filter reload, run here, because
# they are registered by the hook removed below. Kept: the settings, and the blocklists_* aliases in
# Firewall: Aliases, which block nothing without the rules - remove them there when no longer wanted,
# or turn Block Lists off and Apply before removing it, which removes them.

# the cron entry first, and the rules hook, which would stop a filter reload if it outlived its model
rm -f /usr/local/etc/cron.d/blocklists
# A cut or the minute's JA4 watch already running stops now, rather than up to a minute after its
# files went (2026-10-29). The bracket keeps the pattern from matching a shell that carries this text.
/bin/pkill -f '/usr/local/opnsense/scripts/[b]locklists/' 2> /dev/null || true
rm -f /usr/local/etc/inc/plugins.inc.d/blocklists.inc
rm -rf /usr/local/share/os-blocklists
rm -f /usr/local/opnsense/service/conf/actions.d/actions_blocklists.conf
rm -rf /usr/local/opnsense/scripts/blocklists
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/BlockLists
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/BlockLists
# What the cuts kept - each list's snapshot, where the JA4 watch is in the log - which is no file of
# src/'s either. Left, an old snapshot hid from a reinstall the connections it should cut (2026-10-29).
rm -rf /var/db/os-blocklists
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload > /dev/null 2>&1 || true
# The pf tables of the plugin's aliases that are gone - an Apply with Block Lists off removes them -
# emptied, when no rule uses them: a table outlives its alias and its rules, and went on holding the
# addresses (2026-10-29). A table whose alias is still in Firewall: Aliases is OPNsense's to keep, and
# one a rule still uses is left as it is.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 ~ /^blocklists_/ && $1 !~ /r/ { print $2 }' |
while read -r table; do
    grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
    /sbin/pfctl -t "${table}" -T flush > /dev/null 2>&1 || true
done
echo "Block Lists removed; its aliases stay in Firewall: Aliases"
