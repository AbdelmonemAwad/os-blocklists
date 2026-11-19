{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Block Lists (XGS: Block Lists when os-xgs-npu is installed) - the address lists, the
 # countries, the DNS lists, UT1's web categories, the JA4 fingerprints and what the IPS drops in one
 # place, with what each blocked and cut, and a lookup of where a name or an address is held.
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
        #grid-seen .tabulator-tableholder, #grid-categories .tabulator-tableholder,
        #grid-ids .tabulator-tableholder { overflow-x: hidden; }
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

        /* bytes as the Web categories tab says them: MiB, or GiB from one GiB */
        function size(bytes) {
            if (bytes === null || bytes === undefined || bytes === '') {
                return '-';
            }
            if (bytes >= 1073741824) {
                return plain("{{ lang._('%s GiB') }}").replace('%s', (bytes / 1073741824).toFixed(1));
            }
            return bytes < 1048576 ? plain("{{ lang._('under 1 MiB') }}") :
                plain("{{ lang._('%s MiB') }}").replace('%s', Math.round(bytes / 1048576).toLocaleString());
        }

        /* The abuse.ch Auth-Key's field (ThreatFox): the page is never given the key - OPNsense's
           write-only field answers it empty - so the field says whether one is saved, and Remove the
           key is there only where one is. */
        function key_saved(saved) {
            $(document.getElementById('blocklists.general.threatfox_key')).attr('placeholder',
                plain(saved ? "{{ lang._('saved - leave empty to keep it') }}" : "{{ lang._('not set') }}"));
            $('#bl-key-remove').toggle(saved);
        }

        /*
         * Five cards: the address lists (the countries are one of them, an alias like the others),
         * what their rules blocked, the DNS lists, the web categories and the JA4 fingerprints.
         */
        function draw(data) {
            const $cards = $('#bl-cards').empty();
            if (!data || data.error) {
                $cards.append(card('bad', 'fa-ban', "{{ lang._('Block Lists') }}", "{{ lang._('Status could not be read.') }}", ''));
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
                "{{ lang._('packets since tables loaded') }}"));
            const dnsOn = data.dns.lists.filter(function (l) { return l.enabled; }).length;
            $cards.append(card(dnsOn && data.dns.enabled ? 'ok' : '', 'fa-filter', "{{ lang._('DNS lists') }}",
                String(dnsOn), data.dns.enabled ? "{{ lang._('in Unbound DNS') }}" : "{{ lang._('Unbound DNS is off') }}"));
            /* UT1's web categories: those applied to Unbound, of those chosen */
            const web = data.categories || {};
            const webChosen = (web.chosen || []).length;
            const webApplied = (web.applied || []).length;
            $cards.append(card(!webChosen ? '' : (!data.enabled || !web.unbound || webApplied < webChosen ? 'warn' : 'ok'),
                'fa-globe', "{{ lang._('Web categories') }}", String(webApplied),
                !webChosen ? "{{ lang._('none chosen') }}" : (!data.enabled ? "{{ lang._('Block Lists is off') }}" :
                    (!web.unbound ? "{{ lang._('Unbound DNS is off') }}" : count(web.names) + ' ' + "{{ lang._('names in Unbound DNS') }}"))));
            const ja4 = data.ja4.listed.length;
            $cards.append(card(ja4 && data.ja4.problem ? 'warn' : (ja4 ? 'ok' : ''), 'fa-hand-paper-o',
                "{{ lang._('JA4') }}", String(ja4), ja4 && data.ja4.problem ? data.ja4.problem :
                    (data.ja4.last && data.ja4.last.last ? data.ja4.last.last.message || '' : '')));

            $('#bl-project').toggle(!!data.project.installed);
            $('#bl-lists-none').toggle(!data.lists.length);
            /* only where a "from inside" rule was given to pf: a command-and-control list, outbound
               blocked, an interface that counts as inside */
            $('#bl-inside-note').toggle(data.lists.some(function (l) { return l.inside; }));
            $('#bl-dns-none').toggle(!data.dns.lists.length);

            /* ThreatFox's line, where the list is chosen: threatfox.py's last word, or why it has none */
            const tf = data.threatfox || {};
            $('#bl-threatfox-line').toggle(!!tf.chosen);
            $('#bl-threatfox').text(plain(!tf.key ?
                "{{ lang._('no abuse.ch Auth-Key saved: nothing is fetched. Enter one in Settings, then Apply.') }}" :
                (tf.message || "{{ lang._('not run yet') }}")));
            key_saved(!!tf.key);

            const cut = data.cut.last || {};
            $('#bl-cut').text(plain(data.cut.on ? (cut.message || "{{ lang._('not run yet') }}") : "{{ lang._('Cutting open connections is off.') }}"));
            $('#bl-ja4-problem').text(plain(data.ja4.problem || '')).toggle(!!data.ja4.problem);
            $('#bl-ja4-listed').text(plain(data.ja4.listed.length ? data.ja4.listed.join(', ') : '-'));
            $('#bl-ja4-last').text(plain(data.ja4.last && data.ja4.last.last ? data.ja4.last.last.message || '-' : '-'));

            /* the Web categories tab: Unbound in use or not, the last run's line, what is applied */
            $('#bl-cat-unbound').toggle(!web.unbound);
            $('#bl-cat-line').text(plain((web.busy ? "{{ lang._('being fetched now') }}" + ' · ' : '') +
                (web.error || web.message || "{{ lang._('not run yet') }}")));
            $('#bl-cat-total').text(plain(webApplied ? count(web.names) + ' ' + "{{ lang._('names at the most') }}" + ', ' +
                size(web.memory) + ' ' + "{{ lang._('in Unbound, an estimate') }}" : '-'));

            /* the IPS drops tab: why nothing is entered, where something keeps it; how many are held */
            const ids = data.ids || {};
            $('#bl-ids-problem').text(plain(ids.problem || '')).toggle(!!(ids.on && ids.problem));
            $('#bl-ids-line').text(plain(ids.error || ids.message || "{{ lang._('not run yet') }}"));
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

        /* UT1's categories, every one offered: what it is, its size, its state; adult greyed with its reason */
        $('#grid-categories').UIBootgrid({
            search: '/api/blocklists/service/search_categories',
            options: {
                selection: false,
                formatters: {
                    category: function (column, row) {
                        const mark = row.refused ? '<i class="fa fa-fw fa-ban"></i> ' :
                            (row.chosen ? '<i class="fa fa-fw fa-check-square-o"></i> ' : '<i class="fa fa-fw fa-square-o"></i> ');
                        return '<span class="' + (row.refused ? 'text-muted' : '') + '">' + mark + '<b>' + row.name +
                            '</b> <code>' + row.id + '</code></span>' +
                            (row.description ? '<div class="text-muted small">' + row.description + '</div>' : '');
                    },
                    use: function (column, row) {
                        return row.use === 'allow' ? "{{ lang._('allow list') }}" : "{{ lang._('block list') }}";
                    },
                    names: function (column, row) {
                        return row.names === null ? '-' : (row.counted ? '' : '~ ') + count(row.names);
                    },
                    memory: function (column, row) {
                        return row.memory === null ? '-' : '~ ' + size(row.memory);
                    },
                    // a cell of the grid keeps to one line and cuts it with an ellipsis: adult's reason (decision
                    // d2: shown with its reason) and a category's state are wrapped instead, so they are read whole
                    state: function (column, row) {
                        if (row.refused) {
                            return '<div class="text-muted" style="white-space: normal;">' + "{{ lang._('cannot be chosen') }}" + ': ' + row.refused + '</div>';
                        }
                        if (!row.chosen) {
                            return '<span class="text-muted">' + "{{ lang._('not chosen') }}" + '</span>';
                        }
                        return '<div style="white-space: normal;">' + (row.applied ? "{{ lang._('applied') }}" : "{{ lang._('not applied') }}") +
                            (row.state ? ': ' + row.state : '') + '</div>';
                    }
                }
            }
        });

        /* What the IPS drops (ff-10): each address held, its last drop and signature, until when, and a
           button to take it out now. An address is the only value put into an attribute, and only one
           made of an address's characters. */
        $('#grid-ids').UIBootgrid({
            search: '/api/blocklists/service/search_ids',
            options: {
                selection: false,
                formatters: {
                    address: function (column, row) {
                        return '<code>' + row.address + '</code>';
                    },
                    signature: function (column, row) {
                        return (row.sid ? '<code>' + row.sid + '</code> ' : '') + row.msg;
                    },
                    remove: function (column, row) {
                        if (!/^[0-9A-Fa-f:.]+$/.test(row.address)) {
                            return '';
                        }
                        return '<button type="button" class="btn btn-xs btn-default bl-ids-remove" data-address="' + row.address +
                            '" title="' + "{{ lang._('Take it out now') }}" + '"><i class="fa fa-fw fa-trash-o"></i></button>';
                    }
                }
            }
        });
        $('#grid-ids').on('click', '.bl-ids-remove', function () {
            ajaxCall('/api/blocklists/service/ids_remove', {'address': $(this).attr('data-address')}, function (data) {
                $('#bl-ids-result').attr('class', data && data.removed ? 'text-muted' : 'text-warning')
                    .text(plain(data && typeof data.message === 'string' ? data.message : "{{ lang._('No answer could be read.') }}")).show();
                $('#grid-ids').bootgrid('reload');
                refresh();
            });
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
            } else if (tab === '#categories') {
                $('#grid-categories').bootgrid('reload');
            } else if (tab === '#ids') {
                $('#grid-ids').bootgrid('reload');
            } else if (tab === '#ja4' && seen_open) {
                $('#grid-seen').bootgrid('reload');
            }
        });

        mapDataToFormUI({'frm_general': '/api/blocklists/settings/get', 'frm_categories': '/api/blocklists/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        /* Remove the key: the one way a saved key is taken out, as an empty field keeps it */
        $('<button type="button" class="btn btn-default btn-xs" id="bl-key-remove" style="display: none; margin-top: 6px;"/>')
            .text(plain("{{ lang._('Remove the key') }}"))
            .insertAfter(document.getElementById('blocklists.general.threatfox_key'))
            .click(function () {
                ajaxCall('/api/blocklists/settings/forget_key', {}, function (data) {
                    const ok = data && data.status === 'ok';
                    $('#bl-result').attr('class', ok ? 'text-muted' : 'alert alert-danger').text(plain(ok ?
                        "{{ lang._('abuse.ch Auth-Key removed: nothing more is sent to abuse.ch. Apply removes the ThreatFox list.') }}" :
                        "{{ lang._('abuse.ch Auth-Key could not be removed.') }}")).show();
                    refresh();
                });
            });

        $('#applyAct').click(function () {
            const $button = $(this).prop('disabled', true);
            const $progress = $('#frm_general_progress').addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            saveFormToEndpoint('/api/blocklists/settings/set', 'frm_general', function () {
                /* a key typed is saved now: the page keeps no copy of it */
                $(document.getElementById('blocklists.general.threatfox_key')).val('');
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

        /* The Web categories tab's Apply: its own form saved, then the page's whole Apply, which fetches
           and applies the categories in the background (categories.py --apply) */
        $('#applyCategoriesAct').click(function () {
            const $button = $(this).prop('disabled', true);
            const $progress = $('#frm_categories_progress').addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            saveFormToEndpoint('/api/blocklists/settings/set', 'frm_categories', function () {
                ajaxCall('/api/blocklists/service/apply', {}, function (data) {
                    done();
                    const ok = data && data.status === 'ok';
                    $('#bl-cat-result').attr('class', ok ? 'text-muted' : 'alert alert-danger').text(plain(ok ?
                        "{{ lang._('Saved. The web categories are fetched and applied to Unbound DNS in the background; Unbound reads them within a minute.') }}" :
                        (data && data.errors ? data.errors.join(' · ') : "{{ lang._('The settings could not be applied.') }}"))).show();
                    const again = function () {
                        refresh();
                        $('#grid-categories').bootgrid('reload');
                    };
                    again();
                    setTimeout(again, 15000);
                    setTimeout(again, 60000);
                });
            }, false, done);
        });

        /* The Lookup tab: a name or an address, and every place of the block lists that holds it */
        function lookup_show(data) {
            const $out = $('#bl-lookup-result').empty();
            /* a failed request hands the callback what it has - nothing, an error, or the request itself */
            if (!data || data.error || !data.kind) {
                $out.append($('<div class="alert alert-warning" role="alert"/>').text(plain(data && typeof data.error === 'string' ?
                    data.error : "{{ lang._('No answer could be read.') }}")));
                return;
            }
            const $list = $('<ul/>');
            const errors = [];
            const tables = data.tables || {};
            const cats = data.categories || {};
            const unbound = data.unbound || {};
            if (data.kind === 'address') {
                $.each(tables.held || [], function (i, t) {
                    $list.append($('<li/>').text(plain("{{ lang._('pf table') }}" + ' ' + t.alias + (t.list ? ' (' + t.list + ')' : ''))));
                });
                errors.push.apply(errors, tables.errors || []);
            } else {
                $.each(cats.held || [], function (i, c) {
                    $list.append($('<li/>').text(plain("{{ lang._('Web category') }}" + ' ' + c.name + ' (' + c.id + ')' +
                        (c.entry !== data.query ? "{{ lang._(', as a name under %s') }}".replace('%s', c.entry) : '') +
                        (c.exception ? ' - ' + "{{ lang._('let through by the exception') }}" + ' ' + c.exception : ''))));
                });
                /* the policy of the web categories with its entry; a policy of the owner's by its description only */
                $.each(unbound.held || [], function (i, u) {
                    $list.append($('<li/>').text(plain("{{ lang._('Unbound DNS blocklist') }}" + ': ' + (u.mine ?
                        "{{ lang._('the policy of the web categories') }}" +
                            (u.entry !== data.query ? "{{ lang._(', as a name under %s') }}".replace('%s', u.entry) : '') +
                            (u.passes ? ' - ' + "{{ lang._('let through by an exception') }}" : '') :
                        "{{ lang._('a policy of Unbound DNS: Blocklists') }}" + (u.description ? ' "' + u.description + '"' : '')))));
                });
                errors.push.apply(errors, (cats.errors || []).concat(unbound.errors || []));
            }
            $out.append($('<div/>').append($('<b dir="ltr"/>').text(plain(data.query))).append(document.createTextNode(': ' +
                plain(data.found ? "{{ lang._('held in these places') }}" : "{{ lang._('held nowhere in these block lists') }}"))));
            if (data.found) {
                $out.append($list);
            }
            $out.append($('<div class="text-muted"/>').text(plain(data.kind === 'address' ?
                "{{ lang._('An address is looked up in the pf tables of the lists of this page. The web categories and Unbound DNS hold names.') }}" :
                "{{ lang._('A name is looked up in the web categories applied and in the blocklist data of Unbound DNS, with the names above it. The pf tables hold addresses: a name is not looked up there, and not resolved.') }}")));
            $.each(errors, function (i, e) {
                $out.append($('<div class="text-warning"/>').text(plain(e)));
            });
        }

        $('#bl-lookup-form').on('submit', function (e) {
            e.preventDefault();
            const query = String($('#bl-lookup-query').val() || '').trim();
            if (query === '') {
                return;
            }
            const $button = $('#lookupAct').prop('disabled', true);
            ajaxCall('/api/blocklists/service/lookup', {'query': query}, function (data) {
                $button.prop('disabled', false);
                lookup_show(data);
            });
        });

        cards_wait('#bl-cards', ["{{ lang._('Lists') }}", "{{ lang._('Blocked') }}", "{{ lang._('DNS lists') }}", "{{ lang._('Web categories') }}", "{{ lang._('JA4') }}"]);
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
    <li><a data-toggle="tab" href="#categories">{{ lang._('Web categories') }}</a></li>
    <li><a data-toggle="tab" href="#ja4">{{ lang._('JA4') }}</a></li>
    <li><a data-toggle="tab" href="#ids">{{ lang._('IPS drops') }}</a></li>
    <li><a data-toggle="tab" href="#lookup">{{ lang._('Lookup') }}</a></li>
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
        <div id="bl-inside-note" class="text-muted" style="display: none; padding: 0 15px 10px;">
            {{ lang._('For a command-and-control list, Blocked in also counts the packets of devices inside that tried to reach it: they are blocked where they enter the firewall.') }}
        </div>
        <div id="bl-threatfox-line" style="display: none; padding: 0 15px 10px;">
            ThreatFox: <span id="bl-threatfox">-</span>
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
    <div id="categories" class="tab-pane">
        <div id="bl-cat-unbound" class="alert alert-warning" role="alert" style="display: none; margin: 15px 15px 0;">
            {{ lang._('Unbound DNS is off: the web categories have no effect until it is the resolver the clients use.') }}
        </div>
        <div class="text-muted" style="padding: 10px 15px 0;">
            {{ lang._('Web categories block names by DNS, through the Unbound blocklist of OPNsense itself, in a policy of their own for every client, beside the policies of Unbound DNS: Blocklists, which are left as they are. The categories are those of UT1, Universite Toulouse 1 Capitole, under the licence CC BY-SA 4.0; the firewall fetches them itself.') }}
            <a href="https://dsi.ut-capitole.fr/blacklists/index_en.php" target="_blank" rel="noopener noreferrer">UT1</a>
            &middot; <a href="https://creativecommons.org/licenses/by-sa/4.0/" target="_blank" rel="noopener noreferrer">CC BY-SA 4.0</a>
        </div>
        {{ partial("layout_partials/base_form", ['fields': categoriesForm, 'id': 'frm_categories', 'apply_btn_id': 'applyCategoriesAct']) }}
        <div style="padding: 0 15px 10px;"><div id="bl-cat-result" style="display: none;"></div></div>
        <div style="padding: 0 15px 5px;">
            {{ lang._('Last run') }}: <span id="bl-cat-line">-</span>
        </div>
        <div style="padding: 0 15px 10px;">
            {{ lang._('Applied') }}: <span id="bl-cat-total">-</span>
        </div>
        <table id="grid-categories" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="name" data-formatter="category" data-type="string">{{ lang._('Category') }}</th>
                    <th data-column-id="use" data-formatter="use" data-type="string" data-width="8em">{{ lang._('Made as') }}</th>
                    <th data-column-id="names" data-formatter="names" data-type="numeric" data-width="9em">{{ lang._('Names') }}</th>
                    <th data-column-id="memory" data-formatter="memory" data-type="numeric" data-width="9em">{{ lang._('Memory') }}</th>
                    <th data-column-id="state" data-formatter="state" data-type="string">{{ lang._('State') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted" style="padding: 0 15px 15px;">
            {{ lang._('Names: those of the copy fetched, or, marked ~, the count of the catalogue. Memory: what they would take in Unbound, an estimate at about 820 bytes a name, as measured on a firewall, and more for a moment while Unbound reloads them. Made as: allow list marks a category UT1 made to let names through; chosen here, it is blocked like the others. UT1 asks that its categories be chosen, not all blocked at once.') }}
        </div>
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
            <button class="btn btn-default" id="seenAct" type="button">{{ lang._('Show fingerprints seen') }}</button>
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
    <div id="ids" class="tab-pane">
        <div id="bl-ids-problem" class="alert alert-warning" role="alert" style="display: none; margin: 15px 15px 0;"></div>
        <div style="padding: 15px 15px 5px;">
            {{ lang._('IPS drops') }}: <span id="bl-ids-line">-</span>
        </div>
        <div style="padding: 0 15px 5px;"><span id="bl-ids-result" style="display: none;"></span></div>
        <table id="grid-ids" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="address" data-formatter="address" data-type="string" data-identifier="true" data-width="14em">{{ lang._('Address') }}</th>
                    <th data-column-id="at" data-type="string" data-width="11em">{{ lang._('First dropped') }}</th>
                    <th data-column-id="last" data-type="string" data-width="11em">{{ lang._('Last dropped') }}</th>
                    <th data-column-id="until" data-type="string" data-width="11em">{{ lang._('Held until') }}</th>
                    <th data-column-id="count" data-type="numeric" data-width="6em">{{ lang._('Drops') }}</th>
                    <th data-column-id="msg" data-formatter="signature" data-type="string">{{ lang._('Signature') }}</th>
                    <th data-column-id="commands" data-formatter="remove" data-sortable="false" data-width="5em"></th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted" style="padding: 0 15px 15px;">
            {{ lang._('The sources of what the Intrusion Detection IPS policy dropped on connections it saw established over TCP, each blocked by this page until the time after its last drop is over; its open connections are cut where Cut open connections is on, and on the coprocessor of a Sophos XGS where os-xgs-npu Cut in hardware is on and Direction is Both ways. Never the firewall itself, what it depends on or who manages it, nor Never block. Set in Settings: Block what the IPS drops, Keep an address, Outside addresses only and Never block. The list starts empty after a reboot where /var is kept in memory.') }}
        </div>
    </div>
    <div id="lookup" class="tab-pane">
        <div style="padding: 15px;">
            <form id="bl-lookup-form" class="form-inline">
                <input type="text" class="form-control" id="bl-lookup-query" maxlength="254" dir="ltr" autocomplete="off"
                       placeholder="example.com &middot; 192.0.2.10" style="width: 24em; max-width: 100%;">
                <button class="btn btn-primary" id="lookupAct" type="submit">{{ lang._('Look up') }}</button>
            </form>
            <div class="text-muted" style="margin-top: 8px;">
                {{ lang._('Where a name or an address is held: the pf tables of the lists of this page, the web categories applied, and the blocklist data of Unbound DNS - its own policies and the web categories. Nothing is changed.') }}
            </div>
            <div id="bl-lookup-result" style="margin-top: 15px;"></div>
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="bl-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("OPNsense/BlockLists/credit") }}
