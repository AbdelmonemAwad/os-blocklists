<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\BlockLists\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'blocklists';
    protected static $internalModelClass = '\OPNsense\BlockLists\BlockLists';

    /**
     * The saved abuse.ch Auth-Key taken out of the configuration - the Settings tab's Remove the key
     * (2026-11-17). Its field is OPNsense's UpdateOnlyTextField, which keeps the key when the form sends
     * it empty, so this is the one way to remove it. Under the configuration's lock, as the model's own
     * saves are; config.xml is saved only when a key was there. The answer says whether one is saved
     * now - never the key.
     */
    public function forgetKeyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $this->throwReadOnly();
        $config = Config::getInstance();
        $config->lock();
        $root = $config->object();
        if (isset($root->OPNsense->BlockLists->general->threatfox_key)) {
            unset($root->OPNsense->BlockLists->general->threatfox_key);
            $config->save();
        } else {
            $config->unlock();
        }
        return ['status' => 'ok', 'key' => false];
    }
}
