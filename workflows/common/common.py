#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import os
from configparser import ConfigParser

logger = logging.getLogger('workflows')

def getConf():
    logger.info('%s.getConf starts', __name__)

    currentPath = os.path.dirname(os.path.abspath(__file__))
    app_dir = os.path.join(currentPath, "..", "..")
    cfg = ConfigParser()
    confPath = os.path.join("/", "opt", "Synapse", "conf", "synapse.conf")
    try:
        cfg.read(confPath)
        return cfg
    except Exception as e:
        logger.error('%s', __name__, exc_info=True)


