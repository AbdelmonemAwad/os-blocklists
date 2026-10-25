#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Block Lists plugin files. The rules go with the next filter reload, run here, because
# they are registered by the hook removed below. Kept: the settings, and the blocklists_* aliases in
# Firewall: Aliases, which block nothing without the rules - remove them there when no longer wanted.

# the cron entry first, and the rules hook, which would stop a filter reload if it outlived its model
rm -f /usr/local/etc/cron.d/blocklists
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
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload > /dev/null 2>&1 || true
echo "Block Lists removed; its aliases stay in Firewall: Aliases"
