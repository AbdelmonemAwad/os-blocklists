#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Install the Block Lists plugin from a copy of this repository on the firewall:
#   sh install/install.sh
# Safe to run again after an update: settings in config.xml are kept. Nothing is blocked until lists
# are chosen on the page and applied.

set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)

# Syntax first, on the tree about to be copied, so nothing with an error is ever copied (2026-10-29):
# checked after the copy, a rules hook with an error stayed in plugins.inc.d when its check failed,
# where every filter reload includes it - and stops at it. The Python is compiled into a directory
# of its own, removed after, not beside the tree's files.
for f in $(find "${HERE}/src" -name '*.php' -o -name '*.inc'); do
    php -l "$f" > /dev/null
done
PYC=$(mktemp -d -t os-blocklists-check)
trap 'rm -rf "${PYC}"' EXIT
for f in $(find "${HERE}/src" -name '*.py'); do
    PYTHONPYCACHEPREFIX="${PYC}" python3 -m py_compile "$f"
done
rm -rf "${PYC}"
trap - EXIT

# plugin files: src/ maps to /usr/local
cp -R "${HERE}/src/" /usr/local/
chmod 755 /usr/local/opnsense/scripts/blocklists/*.py /usr/local/opnsense/scripts/blocklists/apply.php \
    /usr/local/opnsense/scripts/blocklists/place-menu.sh
chmod 644 /usr/local/opnsense/scripts/blocklists/feeds.json /usr/local/opnsense/scripts/blocklists/i18n/ui/source.json
chmod 644 /usr/local/etc/cron.d/blocklists /usr/local/etc/inc/plugins.inc.d/blocklists.inc
chmod 644 /usr/local/opnsense/service/conf/actions.d/actions_blocklists.conf

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. place-menu.sh writes the menu file and says which it chose: "xgs" or "own".
WHERE=$(/usr/local/opnsense/scripts/blocklists/place-menu.sh)

install -d -o root -g wheel -m 0750 /var/db/os-blocklists

# reload configd actions, menu and ACL caches; the filter, so the rules hook is read
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload > /dev/null 2>&1 || true

# What this install is, for the self-update: the commit, from a git checkout, or from the
# .source-commit stamp that an xgs-image-builder image or the self-update leaves in the tree.
# Without either it is recorded as unknown, and the self-update takes the latest release once.
REV=; RDATE=; RSRC=unknown
if [ -e "${HERE}/.git" ] && REV=$(git -C "${HERE}" rev-parse HEAD 2>/dev/null); then
    RDATE=$(git -C "${HERE}" log -1 --format=%cI 2>/dev/null); RSRC=git
elif [ -s "${HERE}/.source-commit" ]; then
    read -r REV RDATE _ < "${HERE}/.source-commit"; RSRC=stamp
else
    REV=
fi
case ${REV} in *[!0-9a-f]*) REV=; RDATE=; RSRC=unknown ;; esac
install -d -m 0755 /usr/local/share/os-blocklists
printf '{"commit": "%s", "date": "%s", "source": "%s", "installed_at": %s}\n' \
    "${REV}" "${RDATE}" "${RSRC}" "$(date +%s)" > /usr/local/share/os-blocklists/installed.json

if [ "${WHERE}" = xgs ]; then
    echo "Block Lists installed: XGS > Block Lists"
else
    echo "Block Lists installed: Firewall > Block Lists"
fi
