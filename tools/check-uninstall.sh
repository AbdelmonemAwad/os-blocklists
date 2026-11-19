#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Every file install/install.sh lays down from src/ is removed by install/uninstall.sh - by its own
# path, or by an `rm -rf` of a directory above it.
#
# The installer copies src/ onto /usr/local whole, so a file added to src/ is installed without
# anyone deciding to; the uninstaller names what it removes, so the same file is left behind unless
# somebody remembers. Left behind, a plugins.inc.d hook outlives the classes it calls and stops
# OPNsense's boot before the network (os-frontpanel issue 11, on an XGS 136), and a cron entry goes
# on calling a script that is gone. Nothing complains until a removal and a reboot - so this does.
#
# Since 2026-11-19 a file can also go into a folder that is OPNsense's, not the plugin's: the web
# categories' Unbound handler, in scripts/unbound/blocklists/ beside OPNsense's own handlers. Such a
# file - anywhere outside OWN, the plugin's own folders - must be removed by its own path, and no
# folder holding one, nor any folder above it, may be removed whole, by the uninstaller or by the
# package's post-deinstall: that would take OPNsense's files with it. A Python module put there that is
# imported, not run (no #! line), leaves what Python compiled of it in __pycache__ beside it, which pkg
# does not know of: both must remove that too, by its name. And a handler put into Unbound's folder
# leaves its policy in Unbound's blocklist data until that is rebuilt: both must rebuild it
# (configctl unbound dnsbl), and first wait for a rebuild of OPNsense's already running - one that read
# the handler before it went writes the policy back as it ends, and a rebuild asked for meanwhile leaves
# at once on its lock - with lockf -k on that lock (CORE_LOCK): -k, or lockf removes OPNsense's file.
#
#   tools/check-uninstall.sh [repository root]
set -eu
ROOT=${1:-.}
U="${ROOT}/install/uninstall.sh"
P="${ROOT}/pkg/post-deinstall.sh"
OWN="/usr/local/opnsense/scripts/blocklists /usr/local/opnsense/mvc/app/models/OPNsense/BlockLists
/usr/local/opnsense/mvc/app/controllers/OPNsense/BlockLists /usr/local/opnsense/mvc/app/views/OPNsense/BlockLists"
UNBOUND=/usr/local/opnsense/scripts/unbound/blocklists
CORE_LOCK=/tmp/unbound-download_blocklists.tmp

own() { # <target path>: whether it is in one of the plugin's own folders
    for d in ${OWN}; do
        case "$1" in "${d}"/*) return 0 ;; esac
    done
    return 1
}

bad=0
for f in $(cd "${ROOT}" && find src -type f | sort); do
    target="/usr/local/${f#src/}"
    if ! own "${target}"; then
        # a folder OPNsense or another package shares: this file by its own path, and no folder whole
        if ! grep -qF "${target}" "${U}"; then
            echo "not removed by its own path by install/uninstall.sh (it is in a folder the plugin does not own): ${target}"
            bad=1
        fi
        for script in "${U}" "${P}"; do
            d=$(dirname "${target}")
            while [ "${d}" != / ]; do
                if grep -qE "rm -r[f]? [^#]*${d}/?([[:space:]]|\$)" "${script}"; then
                    echo "${script#${ROOT}/} removes a folder OPNsense's files are in: ${d}"
                    bad=1
                fi
                d=$(dirname "${d}")
            done
        done
        case "${f}" in
        *.py)
            if ! head -n1 "${ROOT}/${f}" | grep -q '^#!'; then
                cache="$(dirname "${target}")/__pycache__/$(basename "${target}" .py)."
                for script in "${U}" "${P}"; do
                    grep -qF "${cache}" "${script}" || {
                        echo "${script#${ROOT}/} leaves what Python compiles of ${target} (${cache}*.pyc)"
                        bad=1
                    }
                done
            fi
            ;;
        esac
        if [ "$(dirname "${target}")" = "${UNBOUND}" ]; then
            for script in "${U}" "${P}"; do
                rebuild=$(grep -nE '^[^#]*configctl unbound dnsbl' "${script}" | head -n1 | cut -d: -f1)
                wait=$(grep -nE "^[^#]*lockf -k -t [0-9]+ ${CORE_LOCK} " "${script}" | head -n1 | cut -d: -f1)
                if [ -z "${rebuild}" ]; then
                    echo "${script#${ROOT}/} leaves ${target}'s policy in Unbound's blocklist: no configctl unbound dnsbl"
                    bad=1
                elif [ -z "${wait}" ] || [ "${wait}" -gt "${rebuild}" ]; then
                    echo "${script#${ROOT}/} rebuilds Unbound's blocklist without first waiting for one running (lockf -k -t on ${CORE_LOCK})"
                    bad=1
                fi
                if grep -E "^[^#]*lockf " "${script}" | grep -F "${CORE_LOCK}" | grep -vqE 'lockf -k '; then
                    echo "${script#${ROOT}/} takes ${CORE_LOCK} with lockf without -k: lockf would remove OPNsense's file"
                    bad=1
                fi
            done
        fi
        continue
    fi
    grep -qF "${target}" "${U}" && continue
    covered=0
    d=$(dirname "${target}")
    while [ "${d}" != /usr/local ] && [ "${d}" != / ]; do
        if grep -qE "rm -r[f]? [^#]*${d}([[:space:]]|\$)" "${U}"; then
            covered=1
            break
        fi
        d=$(dirname "${d}")
    done
    if [ "${covered}" = 0 ]; then
        echo "not removed by install/uninstall.sh: ${target}"
        bad=1
    fi
done
[ "${bad}" = 0 ] && echo "every file the installer lays down is removed by the uninstaller, and no folder of OPNsense's with it"
exit "${bad}"
