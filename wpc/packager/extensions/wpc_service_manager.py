"""
ECM Merged 8/18/2016
wpc_service_manager.py

Extends standard BSD service manager for WPC integration.
"""

__copyright__ = """
Copyright (c) 2009-2012 CradlePoint, Inc. <www.cradlepoint.com>.  All rights reserved.

This file contains confidential information of CradlePoint, Inc. and your use of
this file is subject to the CradlePoint Software License Agreement distributed with
this file. Unauthorized reproduction or distribution of this file is subject to civil and
criminal penalties. """

import getopt
import logging
import os
import sys
import signal
from service_manager import SystemInit
import traceback
import uuid
from wpc_config_store import WpcConfigStore
from wpc_file_manager import WpcFileManager

SM_LOG_FILE = os.environ.get('SM_LOG_FILE', 'svcmgr.log')
handler = logging.FileHandler(SM_LOG_FILE)
handler.setFormatter(logging.Formatter(fmt='%(asctime)s [%(levelname)8s] [%(name)10s] [pid:%(process)-5d] [%(threadName)14s] %(message)s'))
logger = logging.getLogger('svcmgr')
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logger.propagate = False


class WpcSystemInit(SystemInit):
    def __init__(self, editorUri, sessionId):
        self.editorUri = editorUri
        self.sessionId = sessionId
        super().__init__()

    # Override
    # Initialize self.file_io
    # Not required for WPC server
    def initFileIO(self):
        pass

    # Override
    # Initialize self.fm using self.file_io
    # Use derived class
    def initFileManager(self):
        self.fm = WpcFileManager(self.editorUri, self.sessionId)

    # Override
    # Initialize self.cStore using self.fm
    # Use derived classes
    def initStores(self):
        namespace = uuid.uuid3(uuid.NAMESPACE_URL, self.editorUri)
        WpcConfigStore.namespace = namespace
        self.cStore = WpcConfigStore(self, self.fm, init=True)

    # Override
    # Not required for WPC server
    def migrateDefaultDiff(self):
        self.custom_defaults = False

    # Override
    # Start services with wpc flag enabled
    # Not be necessary after updates
    def startServices(self):
        """ Instantiate all the services.  We're off to the races now. """
        startup_list = sorted(sys.modules['services'].__classes__, key=lambda x: x.__startup__)
        self.services = []
        for Klass in startup_list:
            try:
                service = Klass(self.cStore,
                                delayedTask=self.delayedTask,
                                loopedTask=self.loopedTask,
                                schedTask=self.schedTask,
                                production=self.production,
                                filemanager=self.fm,
                                services=self.services,
                                system=self,
                                wpc=True
                                )
                self.services.append(service)

                if self.production:
                    service.onStart()

            except:
                traceback.print_exc()
                logger.critical('Service start exception', exc_info=True)


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'es', ['editor=', 'sessionid='])
        for key, val in opts:
            if key in ('-e', '--editor'):
                editorUri = val
            elif key in ('-s', '--sessionid'):
                sessionId = val
    except Exception as e:
        print('Unable to parse options: %s: %s' % (type(e), e))

    logger.info('Starting service_manager: %s' % editorUri)

    sysinit = WpcSystemInit(editorUri, sessionId)
    sysinit.start()

    # Tell config store to start persisting changes after startup
    sysinit.cStore.starting = False

    def handleShutdown(sig, frame):
        sys.exit(0)

    # catch shutdown signals
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handleShutdown)

    # block until shutdown sig received
    signal.pause()
