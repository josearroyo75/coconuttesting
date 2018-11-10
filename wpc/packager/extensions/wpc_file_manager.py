"""
ECM Merged 8/18/2016
wpc_file_manager.py

Extends standard BSD file manager for WPC integration.
Loads the current group/device configuration through the broker.
"""

__copyright__ = """
Copyright (c) 2009-2012 CradlePoint, Inc. <www.cradlepoint.com>.  All rights reserved.

This file contains confidential information of CradlePoint, Inc. and your use of
this file is subject to the CradlePoint Software License Agreement distributed with
this file. Unauthorized reproduction or distribution of this file is subject to civil and
criminal penalties. """

import base64
from config_store import ConfigJsonEncoder, ConfigStore
from filemanager import FileNotFound
import json
import logging
import os
import random
import string
import urllib.request
import pickle

logger = logging.getLogger('svcmgr.fm')

WPC_HOST = os.environ.get('ROME_HOST', 'localhost')
WPC_PORT = os.environ.get('ROME_PORT', '8000')
WPC_SERVER = 'http://' + WPC_HOST + ':' + WPC_PORT


class WpcFileManager(object):
    """ Get and set configuration using broker """

    def __init__(self, editorUri, sessionId):
        # sessionId is obsolescent
        self.wpc_cfg_ver = 0
        self.editorUri = editorUri
        # Load the HTTP request headers from the environment.
        self.headers = json.loads(os.environ.get('HEADERS', '{}'))
        # Dynamic services is expecting sectors
        self.sectors = []

    def get_config(self):
        """ Read from the config api. """
        url = WPC_SERVER + self.editorUri + '?expand=firmware'
        try:
            req = urllib.request.Request(url)
            for k, v in self.headers.items():
                req.add_header(k, v)

            resp = urllib.request.urlopen(req)
            data = json.loads(str(resp.read(), 'utf-8').replace('&amp;', '&').replace('&lt;', '<')
                              .replace('&gt;', '>').replace('&quot;', '\\"').replace('&#39;', "'"))

            return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # This can happen if the user deletes the config editor while
                # the service manager is running and should not be logged as an
                # error.
                logger.warn("Can't get config: {} returned 404".format(url))
            else:
                logger.exception(exc)
            raise FileNotFound('config')
        except Exception as e:
            logger.exception('Unable to get config from %s: %s' % (url, e))
            raise FileNotFound('config')

    def get(self, name):
        # Shadow is used for passwords
        if name == 'shadow':
            raise FileNotFound()

        # config_diff & config_diff_removals used for migration
        # For now, return empty dictionary
        if name == 'config_diff' or name == 'config_diff_removals':
            return pickle.loads('{}')

        logger.debug('WPC File Manager: Read configuration')
        wpcConfig = self.get_config()
        try:
            cfg_diff = wpcConfig['data']['diff_from_default'][0]  # update portion
            removals = wpcConfig['data']['diff_from_default'][1]  # removal portion
            logger.debug('Config Diff: %s, Removals: %s' % (cfg_diff, removals))
            version = wpcConfig['data']['firmware']['version']
            logger.debug('Format Version: %s' % version)

            format_ver = (0, 0, 0)
            if version:
                format_ver = (version.split('.'))
                if len(format_ver) >= 3:
                    format_ver = (int(format_ver[0]), int(format_ver[1]), int(format_ver[2]))
                else:
                    format_ver = (int(format_ver[0]), int(format_ver[1]), 0)

            return cfg_diff, removals, format_ver
        except Exception as e:
            logger.exception('Error parsing config: %s: config=%s' % (e, wpcConfig))
            raise FileNotFound('config')

    def set(self, name, data, **xattrs):
        # Ignore password shadow file
        # Update editor with latest change
        if name == 'shadow':
            return

        logger.debug('WPC File Manager: Write configuration')
        cStore = ConfigStore()

        # Only capture the config portion of the diff (don't include state branch)
        # Config Diff: {'config': {...}}, Removals: [['config', 'lan', 1]]
        cfg_diff, removals = cStore.diffTree()
        cfg_diff = cfg_diff.get('config', {})
        removals = [x[1:] for x in removals if x[0] == 'config']

        url = WPC_SERVER + self.editorUri
        try:
            logger.debug('Config Diff: %s, Removals: %s' % (cfg_diff, removals))
            cfg_diff = ConfigJsonEncoder().encode(cfg_diff)
            removals = ConfigJsonEncoder().encode(removals)
            body = '{"diff_from_default": [' + cfg_diff + ', ' + removals + ']}'
            body = body.encode('utf-8')
            req = urllib.request.Request(url, body)

             # Django uses csrf protection
            for k, v in self.headers.items():
                req.add_header(k, v)
            req.get_method = lambda: 'PUT'
            try:
                resp = urllib.request.urlopen(req)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    # This can happen if the user deletes the config editor
                    # while the service manager is running and should not be
                    # logged as an error.
                    logger.warn("Can't set config: {} returned 404".format(url))
                else:
                    logger.exception(exc)
            else:
                data = json.loads(str(resp.read(), 'utf-8'))
                if not data['success']:
                    logger.error('Unable to update config to %s: %d: %s' % (url, data['status_code'], data['message']))
        except Exception as e:
            logger.exception('Unable to update config to %s', url)

    def has(self, *args, **kwargs):
        return False

    def space_validation(self, *args, **kwargs):
        pass
