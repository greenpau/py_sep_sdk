#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
py_sep_sdk - Symantec Endpoint Protection Manager API Client Library

Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)

import sys
import logging
import os
import unittest
import json
import py_sep_sdk
logging.basicConfig(stream=sys.stdout, format='%(asctime)s [%(levelname)-8s] %(message)s')
LOG = logging.getLogger(__file__)
LOG.setLevel(logging.DEBUG)
FILE_PATH = os.path.abspath(os.path.dirname(__file__))

class ReadinessTestCase(unittest.TestCase):
    ''' Tests the readiness of the package. '''

    @classmethod
    def setUpClass(cls):
        ''' This functions runs only once, prior to all the setups and tests. '''
        LOG.debug('Completed setting up the class!')
        return

    @classmethod
    def tearDownClass(cls):
        ''' This functions runs only once prior to tearing down the class. '''
        print('\n')
        LOG.debug('Completed tearing down the class!')
        return

    @classmethod
    def setUp(cls):
        ''' This functions runs for all of the tests in the class prior to running the test. '''
        LOG.debug('Completed setting up the test!')
        return

    @classmethod
    def tearDown(cls):
        ''' This function runs for all of the tests in the class prior to tearing down the test. '''
        LOG.debug('Completed tearing down the test!')

    def test_is_able_loading_sdk(self):
        ''' Is the loading of the SDK works? '''
        cli = py_sep_sdk.client.new_client()
        if not cli:
            self.fail('failed to initialize API client')
        cli.debug()
        cli.config.load()
        cli.config.validate()
        LOG.debug('Configuration URL: %s', cli.config.get('url'))
        LOG.debug('Configuration username: %s', cli.config.get('username'))
        data = cli.get_version()
        LOG.debug('Version: %s', data)
        data = cli.get_domains()
        file_name = os.path.join(FILE_PATH, 'tmp', 'domains.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Domains: %s', file_name)
        data = cli.get_groups()
        file_name = os.path.join(FILE_PATH, 'tmp', 'groups.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Groups: %s', file_name)
        data = cli.get_computers()
        file_name = os.path.join(FILE_PATH, 'tmp', 'computers.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Computers: %s', file_name)
        data = cli.get_licenses()
        file_name = os.path.join(FILE_PATH, 'tmp', 'licenses.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Licenses: %s', file_name)
        data = cli.get_policies()
        file_name = os.path.join(FILE_PATH, 'tmp', 'policies.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Policies: %s', file_name)
        data = cli.get_admin_users()
        file_name = os.path.join(FILE_PATH, 'tmp', 'admin_users.json')
        with open(file_name, 'w') as file_handle:
            json.dump(data, file_handle, sort_keys=True, indent=4, separators=(',', ': '))
        LOG.debug('Admin Users: %s', file_name)
        return

if __name__ == '__main__':
    unittest.main()
