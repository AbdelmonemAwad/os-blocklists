#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-blocklists have been removed; not during an upgrade. The rules
# hook is gone with them, so a filter reload takes the rules out of pf. Kept: the settings, and the
# blocklists_* aliases, which block nothing without the rules - remove them in Firewall: Aliases.

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-blocklists > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the
# model's directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists/Menu /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml

[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload > /dev/null 2>&1 || true

echo "Block Lists removed; its aliases stay in Firewall: Aliases"
