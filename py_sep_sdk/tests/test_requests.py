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
logging.basicConfig(stream=sys.stdout, format='%(asctime)s [%(levelname)-8s] %(message)s')
LOG = logging.getLogger(__file__)
LOG.setLevel(logging.DEBUG)
FILE_PATH = os.path.abspath(os.path.dirname(__file__))

class PrereqTestCase(unittest.TestCase):
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

    def test_import_requests(self):
        ''' Is the loading of requests package works? '''
        import requests
        return

if __name__ == '__main__':
    unittest.main()
