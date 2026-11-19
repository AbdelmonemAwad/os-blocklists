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
# What Python compiled of the web categories' handler (2026-11-19), in OPNsense's own folder of Unbound
# blocklist handlers, whose handler pkg removed: by its own name, never the folder, which holds OPNsense's.
rm -f /usr/local/opnsense/scripts/unbound/blocklists/__pycache__/blocklists_ut1.*.pyc
[ -d /usr/local/opnsense/scripts/blocklists ] &&
    find /usr/local/opnsense/scripts/blocklists -depth -type d -empty -delete 2> /dev/null

# The IPS drops' alias (ff-10, 2026-11-19), blocklists_ids: addresses held for a while, nothing of the
# owner's - taken out of config.xml with the plugin, where nothing else names it (switched off where
# something does), so the filter reload declares no table of it and the tables' loop below empties it.
# Through OPNsense's own alias model: the plugin's files are gone, OPNsense's are not.
/usr/local/bin/php -r '
require_once("script/load_phalcon.php");
$model = new \OPNsense\Firewall\Alias();
foreach (iterator_to_array($model->aliases->alias->iterateItems()) as $uuid => $alias) {
    if ((string)$alias->name !== "blocklists_ids") {
        continue;
    }
    $text = (string)@file_get_contents("/conf/config.xml");
    if (preg_match_all("/\\bblocklists_ids\\b/", $text) > 1 || substr_count($text, (string)$uuid) > 1) {
        $alias->enabled = "0";
    } else {
        $model->aliases->alias->del($uuid);
    }
    $model->serializeToConfig();
    \OPNsense\Core\Config::getInstance()->save();
}
' > /dev/null 2>&1 || true
[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload > /dev/null 2>&1 || true

# Unbound's blocklist rebuilt without the web categories' policy, its handler and data being gone, until
# it no longer holds it: nothing of the plugin's stays in Unbound, which reads the new file within a minute.
# OPNsense's blocklists.py runs one at a time and leaves at once, writing nothing, while another runs; and
# one running now may have read the handler before it went, and would write the policy back as it ends.
# So each try first waits for a running one to end - lockf on its lock file, up to 15 minutes, -k so the
# file is left as it is - and dnsbl.json is read again only then. Five rebuilds at the most; where it
# still holds the policy after them, this says so.
tries=0
while [ -f /usr/local/sbin/configctl ]; do
	[ -x /usr/bin/lockf ] && /usr/bin/lockf -k -t 900 /tmp/unbound-download_blocklists.tmp true > /dev/null 2>&1
	grep -qF f188da6c-137b-41dd-b504-fe5d96a73483 /var/unbound/data/dnsbl.json 2> /dev/null || break
	if [ "${tries}" -ge 5 ]; then
		echo "Block Lists: Unbound's blocklist still holds the web categories' policy; Apply in Services: Unbound DNS: Blocklists takes it out"
		break
	fi
	/usr/local/sbin/configctl unbound dnsbl > /dev/null 2>&1 || true
	tries=$((tries + 1))
done

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
