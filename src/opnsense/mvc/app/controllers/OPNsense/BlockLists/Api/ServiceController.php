<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\BlockLists\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function json($action)
    {
        $result = json_decode((new Backend())->configdRun('blocklists ' . $action), true);
        return is_array($result) ? $result : ['error' => gettext('No answer could be read.')];
    }

    public function statusAction()
    {
        return $this->json('status');
    }

    public function seenAction()
    {
        return $this->json('seen');
    }

    /**
     * the Lists tab's grid: each alias this plugin owns, as the status script reads it
     */
    public function searchListsAction()
    {
        $rows = [];
        foreach (($this->json('status')['lists'] ?? []) as $list) {
            $proto = (string)($list['proto'] ?? '');
            $rows[] = [
                'name' => (string)($list['name'] ?? ''),
                'list' => preg_replace('/^Block Lists: /', '', (string)($list['description'] ?? '')),
                'what' => (string)($list['what'] ?? ''),
                'terms' => (string)($list['terms'] ?? ''),
                'proto' => $proto !== '' ? $proto : 'IPv4, IPv6',
                'enabled' => !empty($list['enabled']),
                'loaded' => !empty($list['loaded']),
                'entries' => isset($list['entries']) ? (int)$list['entries'] : null,
                'in_blocked' => isset($list['in_blocked']) ? (int)$list['in_blocked'] : null,
                'out_blocked' => isset($list['out_blocked']) ? (int)$list['out_blocked'] : null,
            ];
        }
        return $this->searchRecordsetBase($rows, ['name', 'list', 'what', 'proto']);
    }

    /**
     * the DNS tab's grid: the block lists of OPNsense's Unbound, as the status script reads them
     */
    public function searchDnsAction()
    {
        $rows = [];
        foreach (($this->json('status')['dns']['lists'] ?? []) as $index => $list) {
            $rows[] = [
                'id' => (string)$index,
                'enabled' => !empty($list['enabled']),
                'description' => (string)($list['description'] ?? ''),
                'types' => count($list['types'] ?? []),
                'urls' => (int)($list['urls'] ?? 0),
            ];
        }
        return $this->searchRecordsetBase($rows, ['description']);
    }

    /**
     * the Web categories tab's grid: every category offered, chosen or not, as the status script reads it
     * (scripts/blocklists/categories.py, page()) - its names, the memory they would take in Unbound (an
     * estimate), its state, and why one cannot be chosen
     */
    public function searchCategoriesAction()
    {
        $rows = [];
        foreach (($this->json('status')['categories']['rows'] ?? []) as $row) {
            $rows[] = [
                'id' => (string)($row['id'] ?? ''),
                'name' => (string)($row['name'] ?? ''),
                'description' => (string)($row['description'] ?? ''),
                'use' => ($row['use'] ?? '') === 'allow' ? 'allow' : 'block',
                'names' => isset($row['names']) ? (int)$row['names'] : null,
                'approximate' => !empty($row['approximate']),
                'counted' => !empty($row['counted']),
                'memory' => isset($row['memory']) ? (int)$row['memory'] : null,
                'refused' => (string)($row['refused'] ?? ''),
                'chosen' => !empty($row['chosen']),
                'applied' => !empty($row['applied']),
                'state' => (string)($row['state'] ?? ''),
            ];
        }
        return $this->searchRecordsetBase($rows, ['id', 'name', 'description', 'state']);
    }

    /**
     * The Lookup tab (2026-11-19): every place of the block lists that holds a name or an address -
     * this plugin's pf tables for an address; the web categories applied and Unbound's blocklist data
     * for a name (scripts/blocklists/lookup.py). Read only. The query is checked here before it goes
     * anywhere - an address, or a host name - and again by the script; configd hands it over quoted.
     */
    public function lookupAction()
    {
        if (!$this->request->isPost()) {
            return ['error' => 'POST only'];
        }
        $query = trim((string)$this->request->getPost('query'));
        $host = '/^(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?' .
            '(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$/D';
        if ($query === '' || strlen($query) > 254 ||
            (filter_var($query, FILTER_VALIDATE_IP) === false && !preg_match($host, $query))) {
            return ['error' => gettext('Enter a name, such as example.com, or an address.')];
        }
        $result = json_decode((new Backend())->configdpRun('blocklists lookup', [$query]), true);
        return is_array($result) ? $result : ['error' => gettext('No answer could be read.')];
    }

    /**
     * the JA4 tab's grid: the fingerprints in the IDS's TLS log now, the most frequent first
     */
    public function searchSeenAction()
    {
        $rows = [];
        foreach (($this->json('seen')['seen'] ?? []) as $seen) {
            $rows[] = [
                'ja4' => (string)($seen['ja4'] ?? ''),
                'connections' => (int)($seen['connections'] ?? 0),
                'last' => (string)($seen['last'] ?? ''),
            ];
        }
        return $this->searchRecordsetBase($rows);
    }

    /**
     * the aliases from the settings just saved, then the filter (which registers the rules) and the
     * aliases (which fetches the lists) reloaded the way Firewall: Aliases reloads them, ThreatFox's
     * list fetched in the background (threatfox.py --apply: a download may take minutes, and Apply
     * does not wait for it), the web categories fetched and applied to Unbound in the background too
     * (categories.py --apply, 2026-11-19), then a first round of cutting
     */
    public function applyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $result = json_decode($backend->configdRun('blocklists apply'), true);
        if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
            return is_array($result) ? $result : ['status' => 'failed'];
        }
        $backend->configdRun('filter reload skip_alias');
        $backend->configdRun('template reload OPNsense/Filter');
        $backend->configdRun('filter refresh_aliases');
        $backend->configdRun('blocklists threatfox', true);
        $backend->configdRun('blocklists categories', true);
        $result['cut'] = json_decode($backend->configdRun('blocklists cut'), true);
        $result['ja4'] = json_decode($backend->configdRun('blocklists ja4'), true);
        return $result;
    }
}
