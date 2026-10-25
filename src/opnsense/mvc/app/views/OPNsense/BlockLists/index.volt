{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Block Lists (XGS: Block Lists when os-xgs-npu is installed) - the address lists, the
 # countries, the DNS lists and the JA4 fingerprints in one place, with what each blocked and cut.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #grid-lists .tabulator-tableholder, #grid-dns .tabulator-tableholder,
        #grid-seen .tabulator-tableholder { overflow-x: hidden; }
    }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        /*
         * Four cards: the address lists (the countries are one of them, an alias like the others),
         * what their rules blocked, the DNS lists and the JA4 fingerprints.
         */
        function draw(data) {
            const $cards = $('#bl-cards').empty();
            if (!data || data.error) {
                $cards.append(card('bad', 'fa-ban', "{{ lang._('Block Lists') }}", "{{ lang._('The status could not be read.') }}", ''));
                return;
            }
            const lists = data.lists.filter(function (l) { return l.enabled; });
            const entries = lists.reduce(function (n, l) { return n + (l.entries || 0); }, 0);
            const blocked = lists.reduce(function (n, l) { return n + (l.in_blocked || 0) + (l.out_blocked || 0); }, 0);
            const countries = data.countries || [];
            const no_geoip = countries.length && !data.geoip_source;
            $cards.append(card(!data.enabled ? '' : (no_geoip || !lists.length ? 'warn' : 'ok'), 'fa-list', "{{ lang._('Lists') }}",
                data.enabled ? String(lists.length) : "{{ lang._('off') }}",
                no_geoip ? "{{ lang._('no GeoIP source set') }}" :
                    count(entries) + ' ' + "{{ lang._('addresses and networks') }}" + (countries.length ? ' · ' + countries.join(' ') : '')));
            $cards.append(card(blocked ? 'ok' : '', 'fa-ban', "{{ lang._('Blocked') }}", count(blocked),
                "{{ lang._('packets since the tables were loaded') }}"));
            const dnsOn = data.dns.lists.filter(function (l) { return l.enabled; }).length;
            $cards.append(card(dnsOn && data.dns.enabled ? 'ok' : '', 'fa-filter', "{{ lang._('DNS lists') }}",
                String(dnsOn), data.dns.enabled ? "{{ lang._('in Unbound DNS') }}" : "{{ lang._('Unbound DNS is off') }}"));
            const ja4 = data.ja4.listed.length;
            $cards.append(card(ja4 && data.ja4.problem ? 'warn' : (ja4 ? 'ok' : ''), 'fa-hand-paper-o',
                "{{ lang._('JA4') }}", String(ja4), ja4 && data.ja4.problem ? data.ja4.problem :
                    (data.ja4.last && data.ja4.last.last ? data.ja4.last.last.message || '' : '')));

            $('#bl-project').toggle(!!data.project.installed);
            $('#bl-lists-none').toggle(!data.lists.length);
            $('#bl-dns-none').toggle(!data.dns.lists.length);

            const cut = data.cut.last || {};
            $('#bl-cut').text(plain(data.cut.on ? (cut.message || "{{ lang._('not run yet') }}") : "{{ lang._('Cutting open connections is off.') }}"));
            $('#bl-ja4-problem').text(plain(data.ja4.problem || '')).toggle(!!data.ja4.problem);
            $('#bl-ja4-listed').text(plain(data.ja4.listed.length ? data.ja4.listed.join(', ') : '-'));
            $('#bl-ja4-last').text(plain(data.ja4.last && data.ja4.last.last ? data.ja4.last.last.message || '-' : '-'));
        }

        function refresh() {
            ajaxGet('/api/blocklists/service/status', {}, draw);
        }

        /* The grids' rows are built by the API controller from the same status script; the API
           escapes what it returns, so nothing here escapes it again. */
        $('#grid-lists').UIBootgrid({
            search: '/api/blocklists/service/search_lists',
            options: {
                selection: false,
                formatters: {
                    alias: function (column, row) {
                        return '<code>' + row.name + '</code>';
                    },
                    list: function (column, row) {
                        const name = row.terms ? '<a href="' + row.terms + '" target="_blank" rel="noopener noreferrer">' +
                            row.list + '</a>' : row.list;
                        return '<span class="' + (row.enabled ? '' : 'text-muted') + '">' + name + '</span>' +
                            (row.what ? '<div class="text-muted small">' + row.what + '</div>' : '');
                    },
                    entries: function (column, row) {
                        return row.loaded ? count(row.entries) : "{{ lang._('not loaded') }}";
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    }
                }
            }
        });

        $('#grid-dns').UIBootgrid({
            search: '/api/blocklists/service/search_dns',
            options: {
                selection: false,
                formatters: {
                    state: function (column, row) {
                        return row.enabled ? "{{ lang._('on') }}" : '<span class="text-muted">' + "{{ lang._('off') }}" + '</span>';
                    },
                    description: function (column, row) {
                        return '<span class="' + (row.enabled ? '' : 'text-muted') + '">' + (row.description || '-') + '</span>';
                    },
                    lists: function (column, row) {
                        return row.types + ' ' + "{{ lang._('lists') }}" + (row.urls ? ' + ' + row.urls + ' URL' : '');
                    }
                }
            }
        });

        /* The fingerprints seen are read from the IDS's TLS log on request only, as before: the
           grid is made on the first press and read again on every one after. */
        let seen_open = false;
        $('#seenAct').click(function () {
            if (seen_open) {
                $('#grid-seen').bootgrid('reload');
                return;
            }
            seen_open = true;
            $('#bl-seen').show();
            $('#grid-seen').UIBootgrid({
                search: '/api/blocklists/service/search_seen',
                options: {
                    selection: false,
                    formatters: {
                        mono: function (column, row) {
                            return '<code>' + row[column.id] + '</code>';
                        },
                        number: function (column, row) {
                            return count(row[column.id]);
                        },
                        ltr: function (column, row) {
                            return '<span dir="ltr">' + row[column.id] + '</span>';
                        }
                    }
                }
            });
        });

        /* the cards, and the lists of the tab on screen */
        $('#refreshAct').click(function () {
            refresh();
            const tab = $('#maintabs li.active a').attr('href');
            if (tab === '#lists') {
                $('#grid-lists').bootgrid('reload');
            } else if (tab === '#dns') {
                $('#grid-dns').bootgrid('reload');
            } else if (tab === '#ja4' && seen_open) {
                $('#grid-seen').bootgrid('reload');
            }
        });

        mapDataToFormUI({'frm_general': '/api/blocklists/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $('#applyAct').click(function () {
            const $button = $(this).prop('disabled', true);
            const $progress = $('#frm_general_progress').addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            saveFormToEndpoint('/api/blocklists/settings/set', 'frm_general', function () {
                ajaxCall('/api/blocklists/service/apply', {}, function (data) {
                    done();
                    const lines = (data && data.changes ? data.changes : []).concat(data && data.errors ? data.errors : []);
                    $('#bl-result').attr('class', data && data.status === 'ok' ? 'text-muted' : 'alert alert-danger')
                        .text(plain(lines.length ? lines.join(' · ') : "{{ lang._('Nothing to change.') }}")).show();
                    refresh();
                    $('#grid-lists').bootgrid('reload');
                });
            }, false, done);
        });

        cards_wait('#bl-cards', ["{{ lang._('Lists') }}", "{{ lang._('Blocked') }}", "{{ lang._('DNS lists') }}", "{{ lang._('JA4') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="bl-cards"></div>
<div class="text-muted clearfix" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    <span id="bl-project" style="display: none;">{{ lang._('os-xgs-npu also cuts connections on this host, for the lists and fingerprints XGS: Settings names. A list or fingerprint named there is left to it here, so nothing is cut twice.') }}</span>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#lists">{{ lang._('Lists') }}</a></li>
    <li><a data-toggle="tab" href="#dns">{{ lang._('DNS') }}</a></li>
    <li><a data-toggle="tab" href="#ja4">{{ lang._('JA4') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="lists" class="tab-pane active">
        <table id="grid-lists" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="name" data-formatter="alias" data-type="string" data-identifier="true" data-width="14em">{{ lang._('Alias') }}</th>
                    <th data-column-id="list" data-formatter="list" data-type="string">{{ lang._('List') }}</th>
                    <th data-column-id="proto" data-type="string" data-width="8em">{{ lang._('Family') }}</th>
                    <th data-column-id="entries" data-formatter="entries" data-type="numeric" data-width="8em">{{ lang._('Entries') }}</th>
                    <th data-column-id="in_blocked" data-formatter="number" data-type="numeric" data-width="8em">{{ lang._('Blocked in') }}</th>
                    <th data-column-id="out_blocked" data-formatter="number" data-type="numeric" data-width="8em">{{ lang._('Blocked out') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div id="bl-lists-none" class="text-muted" style="display: none; padding: 0 15px 10px;">
            {{ lang._('No list is chosen. Choose lists and countries in Settings, then Apply.') }}
        </div>
        <div style="padding: 0 15px 15px;">
            {{ lang._('Open connections') }}: <span id="bl-cut">-</span>
        </div>
    </div>
    <div id="dns" class="tab-pane">
        <div class="text-muted" style="padding: 10px 15px 0;">
            {{ lang._('DNS block lists are kept by OPNsense itself, in Services: Unbound DNS: Blocklists; they are shown here so every list is in one place.') }}
        </div>
        <table id="grid-dns" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-formatter="state" data-type="string" data-width="6em">{{ lang._('State') }}</th>
                    <th data-column-id="description" data-formatter="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="types" data-formatter="lists" data-type="numeric">{{ lang._('Lists') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div id="bl-dns-none" class="text-muted" style="display: none; padding: 0 15px 10px;">
            {{ lang._('No DNS block list is set in Unbound DNS.') }}
        </div>
        <div style="padding: 0 15px 15px;"><a href="/ui/unbound/dnsbl/index">{{ lang._('Open Unbound DNS: Blocklists') }}</a></div>
    </div>
    <div id="ja4" class="tab-pane">
        <div id="bl-ja4-problem" class="alert alert-warning" role="alert" style="display: none; margin: 15px;"></div>
        <div style="padding: 15px 15px 0;">
            {{ lang._('Listed') }}: <code id="bl-ja4-listed">-</code>
        </div>
        <div style="padding: 5px 15px 0;">
            {{ lang._('Last run') }}: <span id="bl-ja4-last">-</span>
        </div>
        <div style="padding: 10px 15px;">
            <button class="btn btn-default" id="seenAct" type="button">{{ lang._('Show the fingerprints seen') }}</button>
        </div>
        <div id="bl-seen" style="display: none;">
            <table id="grid-seen" class="table table-condensed table-hover table-striped table-responsive">
                <thead>
                    <tr>
                        <th data-column-id="ja4" data-formatter="mono" data-type="string" data-identifier="true">{{ lang._('Fingerprint') }}</th>
                        <th data-column-id="connections" data-formatter="number" data-type="numeric" data-width="9em">{{ lang._('Connections') }}</th>
                        <th data-column-id="last" data-formatter="ltr" data-type="string">{{ lang._('Last connection') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
                <tfoot></tfoot>
            </table>
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="bl-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("OPNsense/BlockLists/credit") }}
