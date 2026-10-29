#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-blocklists have been removed; not during an upgrade. The rules
# hook is gone with them, so a filter reload takes the rules out of pf. Kept: the settings, and the
# blocklists_* aliases, which block nothing without the rules - remove them in Firewall: Aliases, or
# turn Block Lists off and Apply before removing it, which removes them.

# A cut or the minute's JA4 watch already running stops now, rather than up to a minute after its
# files went (2026-10-29). The bracket keeps the pattern from matching the shell that runs this text.
/bin/pkill -f '/usr/local/opnsense/scripts/[b]locklists/' 2> /dev/null || true

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

# Nor are what Python compiles beside the scripts it imports, which kept their directory, nor what the
# cuts kept in /var/db - each list's snapshot, where the JA4 watch is in the log. Left, an old snapshot
# hid from a reinstall the connections it should cut (2026-10-29). The scripts' directories go once empty.
rm -rf /usr/local/opnsense/scripts/blocklists/__pycache__ /var/db/os-blocklists
[ -d /usr/local/opnsense/scripts/blocklists ] &&
    find /usr/local/opnsense/scripts/blocklists -depth -type d -empty -delete 2> /dev/null

[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload > /dev/null 2>&1 || true

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
