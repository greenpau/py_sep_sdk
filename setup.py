#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
py_sep_sdk - Symantec Endpoint Protection Manager API Client Library

Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import print_function

import os
import unittest
import logging

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop

logging.basicConfig(level=logging.DEBUG)

PKG_DIR = os.path.abspath(os.path.dirname(__file__))
PKG_NAME = 'py_sep_sdk'
PKG_VERSION = '1.0.8'
PKG_AUTHOR_NAME = 'Paul Greenberg'
PKG_AUTHOR_HANDLE = 'greenpau'
PKG_AUTHOR_EMAIL = 'greenpau@outlook.com'
PKG_LICENSE = 'License :: OSI Approved :: Apache Software License'
PKG_DESCRIPTION = 'Symantec Endpoint Protection Manager API Client Library'
PKG_URL = 'https://github.com/%s/%s' % (PKG_AUTHOR_HANDLE, PKG_NAME)
PKG_DOWNLOAD_URL = 'https://github.com/%s/%s/archive/master.zip' % (PKG_AUTHOR_HANDLE, PKG_NAME)
PKG_LONG_DESCRIPTION = PKG_DESCRIPTION
with open(os.path.join(PKG_DIR, PKG_NAME, 'README.rst')) as f:
    PKG_LONG_DESCRIPTION = f.read()
PKG_PACKAGES = [PKG_NAME]
PKG_REQUIRES = [
    'setuptools',
    'wheel',
    'requests>=2.21.0',
    'ipaddress',
]
PKG_TEST_SUITE = 'setup._load_test_suite'
PKG_DATA = [
    'tests/test_requests.py',
    'README.rst',
    'LICENSE.txt',
    'VERSION',
]
PKG_SCRIPTS = [
    'scripts/symc-sep-client'
]
PKG_KEYWORDS = [
    'symantec',
    'sep',
    'api',
    'sdk',
    'endpoint protection',
    'symc',
]
PKG_PLATFORMS = 'any'
PKG_CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    PKG_LICENSE,
    'Programming Language :: Python',
    'Operating System :: POSIX :: Linux',
    'Topic :: Utilities',
    'Topic :: System :: Systems Administration',
]

def _load_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(os.path.join(PKG_DIR, PKG_NAME, 'tests'),
                                      pattern='test_requests.py')
    return test_suite

def pre_test_package():
    ''' This function runs pre-installation tasks. '''
    logging.debug('running tests ...')
    for test_suite in _load_test_suite():
        test_suite_runner = unittest.TextTestRunner()
        test_runner = test_suite_runner.run(test_suite)
        if not test_runner.failures:
            continue
        for test_failure in test_runner.failures:
            logging.error('%s', test_failure[1])
            return True
    return False

class InstallPackage(install):
    ''' This function runs installation tasks. '''
    def run(self):
        logging.debug('running install ...')
        err = pre_test_package()
        if err:
            return 1
        install.run(self)
        return 0

class UninstallPackage(develop):
    ''' This function runs uninstallation tasks. '''
    def run(self):
        logging.debug('running uninstall ...')
        develop.run(self)

CMD_CLASS = {
    'install': InstallPackage,
    'bdist_wheel': InstallPackage,
    'uninstall': UninstallPackage,
}

setup(
    name=PKG_NAME,
    version=PKG_VERSION,
    description=PKG_DESCRIPTION,
    long_description=PKG_LONG_DESCRIPTION,
    url=PKG_URL,
    download_url=PKG_DOWNLOAD_URL,
    author=PKG_AUTHOR_NAME,
    author_email=PKG_AUTHOR_EMAIL,
    license=PKG_LICENSE,
    platforms=PKG_PLATFORMS,
    classifiers=PKG_CLASSIFIERS,
    packages=PKG_PACKAGES,
    package_data={
        '': PKG_DATA,
    },
    scripts=PKG_SCRIPTS,
    keywords=PKG_KEYWORDS,
    install_requires=PKG_REQUIRES,
    test_suite=PKG_TEST_SUITE,
    cmdclass=CMD_CLASS
)
