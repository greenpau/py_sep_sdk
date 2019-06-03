#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
py_sep_sdk - Symantec Endpoint Protection Manager API Client Library

Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)
import os
import stat
import logging
import ConfigParser

class ClientConfiguration(object):
    '''
    This class implements the configuration for the API Client.
    '''

    def __init__(self):
        ''' Initializes the class. '''
        self.cfg_file = None
        self.settings = {}
        self.log = logging.getLogger('sepm-config')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.debug_enabled = False
        self.cfg_key_pairs = [
            'credentials:username',
            'credentials:password',
            'manager:host',
            'manager:port',
            'manager:protocol',
            'manager:basepath'
        ]
        return

    def load(self, cfg_file=None):
        ''' Load configuration from a configuration file in RC format. '''
        if not cfg_file:
            cfg_file = os.path.expanduser('~/.py_sep_sdk.rc')
        self.log.debug('configuration file: %s', cfg_file)
        if not os.path.exists(cfg_file):
            raise Exception('config', 'configuration file %s does not exist' % cfg_file)
        cfg_file_stat = os.stat(cfg_file)
        if cfg_file_stat.st_mode & stat.S_IROTH:
            raise Exception('config', 'configuration file %s is world readable' % cfg_file)
        if cfg_file_stat.st_mode & stat.S_IRGRP:
            raise Exception('config', 'configuration file %s is group readable' % cfg_file)
        self.cfg_file = cfg_file
        cfg_parser = ConfigParser.RawConfigParser()
        cfg_parser.read(cfg_file)
        for cfg_key_pair in self.cfg_key_pairs:
            cfg_section, cfg_key = cfg_key_pair.split(':')
            if cfg_section not in cfg_parser.sections():
                self.log.debug('configuration file ' + \
                        '%s has no %s section', cfg_file, cfg_section)
                continue
            if cfg_parser.has_option(cfg_section, cfg_key):
                self.settings[cfg_key] = cfg_parser.get(cfg_section, cfg_key)
        token_file_name = os.path.expanduser('~/.py_sep_sdk.token')
        self.settings['api_token_file'] = token_file_name
        self.log.debug('token file: %s', token_file_name)
        if os.path.exists(token_file_name):
            with open(token_file_name, 'r') as token_file:
                self.settings['api_token'] = token_file.readline().strip()
                self.log.debug('loaded %s token' % (self.settings['api_token']))
        return

    def validate(self):
        '''
        Validates that all configuration parameters necessary to establish
        a connection to SEP Manager are present.
        '''
        for cfg_key_pair in self.cfg_key_pairs:
            cfg_section, cfg_key = cfg_key_pair.split(':')
            if cfg_key not in self.settings:
                if cfg_key == 'protocol':
                    self.settings[cfg_key] = 'https'
                elif cfg_key == 'port':
                    self.settings[cfg_key] = '8446'
                elif cfg_key == 'basepath':
                    self.settings[cfg_key] = 'sepm/api/v1'
                else:
                    raise Exception('config', \
                            "no '%s' key in '%s' " % (cfg_key, cfg_section) + \
                            "section of the configuration")
            else:
                self.settings[cfg_key] = self.settings[cfg_key].strip("'").strip('"')
        return

    def get(self, item='url'):
        ''' Return configuration settings. '''
        if item == 'url':
            return '%s://%s:%s/%s' % (self.settings['protocol'], self.settings['host'], \
                    self.settings['port'], self.settings['basepath'])
        elif item == 'username':
            return '%s' % (self.settings['username'])
        return None
