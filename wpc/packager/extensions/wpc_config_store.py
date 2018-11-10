"""
ECM Merged 8/18/2016
wpc_config_store.py

Extends standard BSD config store for WPC integration.
Specialized for saving a diff of the configuration while retaining empty arrays when all
rows are deleted from a table. This insures that those rows are also cleared on the device.
"""

__copyright__ = """
Copyright (c) 2009-2012 CradlePoint, Inc. <www.cradlepoint.com>.  All rights reserved.

This file contains confidential information of CradlePoint, Inc. and your use of
this file is subject to the CradlePoint Software License Agreement distributed with
this file. Unauthorized reproduction or distribution of this file is subject to civil and
criminal penalties. """

from config_store import ConfigStore, WorkerThread, ConfigJsonEncoder
from config_collections import ConfigCollection, ConfigDict, ConfigList
from cp._config_store import config_walk
import config_migration
import os
import json
from filemanager import FileNotFound
import logging
from uuid import uuid3

logger = logging.getLogger('svcmgr.cs')


class WpcConfigStore(ConfigStore):
    """ Customizations:
         - Avoid config store change at start which bumps the config version
         - Augment diff algorithm to retain modified configuration arrays to properly clear device
     """

    def __init__(self, sysInit=None, fm=None, init=False):
        super().__init__(fm, init)
        if not init:
            return

        # Allow future references to ConfigStore() to get derived WPC class
        self._instances[ConfigStore] = self

        self.sysInit = sysInit

    def load(self):
        """ Load the config from the file manager. Called on start and whenever we detect that our copy is out-of-date. """

        # Initialize config store to defaults
        self.cfg = ConfigDict(status={}, control={}, config={}, state={})
        defaultCfg = self.getDefaultCfg()
        self.cfg['config'] = defaultCfg['config']
        self.cfg['state'] = defaultCfg['state']
        self.cfg.commit()

        try:
            cfg_diff, removals, version = self.filemanager.get(self.config_name)

            # Migrate configuration (note that we can't save in
            # here because we are starting; the caller must save)
            if version != self.sysInit.getFWVersion() and len(cfg_diff) > 0 and version != (0, 0, 0):
                logger.debug('Migrate configuration...')
                config_migration_schema = 'config_migration_schema.jsonmin'
                basedir = os.path.dirname(__file__)
                with open(os.path.join(basedir, config_migration_schema)) as f:
                    migration = config_migration.initFromSchema(json.load(f), cfg_diff, self.cfg['config'], version)
                try:
                    migration.convert(self.sysInit.getFWVersion())
                except Exception as e:
                    logger.debug('Failed to complete migration of old config to new format: {}, {}'.format(e, traceback.format_exc()))

                # Check if migration changed anything in the config
                if migration.config != cfg_diff:
                    self.migrated = True
                    cfg_diff = migration.config
                    logger.debug('Migrated Cfg: {}'.format(cfg_diff))

            # Overlay stored configuration diffs on top of default
            # configuration. Our delete, put and patch methods each result in a
            # PUT to the ECM editor. Combine updates and removals together via
            # patch() so that the ECM editor will see a consistent set of
            # changes.
            removals = [['config'] + path for path in removals]
            self.patch(removals=removals, updates={'config': cfg_diff})

            # Clear the saved_state from the patch() call above.
            self.cfg.commit(deep=True)

        except FileNotFound:
            logger.debug("Config not found - Using default config")
        except Exception as e:
            logger.exception("Unable to load config - Using default config")

    # Override
    def start(self):
        """ Ran by our controller (service_manager or broker for mgmt) to initialize the
          config after validators are plumbed in. """

        self.workerThread = WorkerThread(self)
        self.workerThread.start()
        self.load()
        self.on(self.requiredBasesCheck, 'validate', [])

    @classmethod
    def _genuuid(cls, path):
        """ Generate a uuid based on the path. """
        # For ECM, the namespace url needs to be different between group and
        # indie configs. It needs to be passed in to the service manager on
        # start, and it should be set as an attribute of this class.
        uuid = str(uuid3(cls.namespace, ".".join(path[:-1])))
        # override the first tuple index
        return "%08x" % int(path[-1]) + uuid[8:]
