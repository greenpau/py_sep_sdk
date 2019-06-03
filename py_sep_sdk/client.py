#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
py_sep_sdk - Symantec Endpoint Protection Manager API Client Library

Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)
import logging
import json
import requests
import urllib3
import py_sep_sdk.config as config
urllib3.disable_warnings()

class Client(object):
    '''
    This class implements an API client for Symantec Endpoint Protection Manager API.
    '''

    def __init__(self):
        ''' Initializes the class. '''
        self.log = logging.getLogger('sepm-client')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.host = None
        self.debug_enabled = False
        self.config = config.ClientConfiguration()
        self.session = requests.Session()
        self.headers = {
            "Accept-Charset": "utf-8",
            "Accept-Encoding": "gzip, deflate, compress",
            "Accept": "*/*",
        }
        self.is_authenticated = False
        return

    def debug(self):
        ''' Enables debugging of the class. '''
        self.log.setLevel(logging.DEBUG)
        self.debug_enabled = True
        self.config.log.setLevel(logging.DEBUG)
        self.config.debug_enabled = True
        return

    def delete_agent(self, agent_id=None, fmt='json'):
        if not agent_id:
            raise Exception('client', 'failed to delete an agent because id is empty')
        if agent_id == '':
            raise Exception('client', 'failed to delete an agent because id is empty')
        if len(agent_id) != 32:
            raise Exception('client', 'failed to delete an agent because id is unsupported, not len(32)')
        self.authenticate()
        url = '%s/computers/%s' % (self.config.get('url'), agent_id.lower())
        req = self.session.delete(url, headers=self.headers, verify=False)
        response = {
            'code': req.status_code,
        }
        if req.status_code == 400:
            response['message'] = 'The parameters are invalid.'
        elif req.status_code == 401:
            response['message'] = 'The user that is currently logged on has insufficient rights to execute the web method, or the user is unauthorized.'
        elif req.status_code == 410:
            response['message'] = 'Cannot find the specified object.'
        elif req.status_code == 500:
            response['message'] = 'The web service encountered an error while processing the web request.'
        elif req.status_code == 204:
            response['message'] = 'The resource was deleted. If the resource did not exist prior to the call, 204 is still returned.'
        else:
            response['message'] = req.text
        return response

    def set_host(self, host):
        ''' Sets API server host. '''
        self.host = host
        return

    def get_version(self):
        ''' Connect to API server and retrieves version information. '''
        url = '%s/version' % (self.config.get('url'))
        req = self.session.get(url, headers=self.headers, verify=False)
        if req.status_code != 200:
            raise Exception('client', 'url: %s, %s: %s' % (url, req.status_code, req.text))
        data = json.loads(req.text)
        manager = {}
        for key in ['version', 'API_SEQUENCE', 'API_VERSION']:
            if key not in data:
                raise Exception('client', "key '%s' is not part of the response" % (key))
            self.config.settings['manager_' + key.lower()] = str(data[key])
            manager[key.lower()] = str(data[key])
        return manager


    def get_user_session(self):
        ''' Connect to API server and retrieve currest user session information. '''
        if 'api_token' not in self.config.settings:
            self.log.debug('api_token is not in configuration settings')
            return False
        self.headers['Authorization'] = 'Bearer %s' % (self.config.settings['api_token'])
        self.log.debug('attempting accessing current user session with %s token' % (self.config.settings['api_token']))
        url = '%s/sessions/currentuser' % (self.config.get('url'))
        req = self.session.get(url, headers=self.headers, verify=False)
        if req.status_code != 200:
            self.log.debug('url: %s, %s: %s' % (url, req.status_code, req.text))
            return False
        data = json.loads(req.text)
        self.log.debug('%s' % (data))
        return True

    def _get_items(self, item=None):
        ''' Perform GET requests. '''
        self.authenticate()
        mandatory_response_keys = [
            'content',
            'firstPage',
            'lastPage',
            'totalPages'
        ]
        items = []
        page_counter = 0
        while True:
            page_counter += 1
            url = '%s/%s' % (self.config.get('url'), item)
            params = {}
            params['pageSize'] = 500
            params['pageIndex'] = page_counter
            self.log.debug('GET %s with params: %s', url, params)
            req = self.session.get(url, headers=self.headers, params=params, verify=False)
            if req.status_code != 200:
                raise Exception('client',
                                '%d: %s, message: %s' % (req.status_code, req.reason, req.text))
            data = json.loads(req.text)
            if item in ['domains', 'licenses', 'admin-users']:
                items.extend(data)
                break
            for key in mandatory_response_keys:
                if key not in data:
                    raise Exception('client', "key '%s' is not in response" % (key))
            items.extend(data['content'])
            if data['lastPage'] is True:
                break
            if page_counter > 100:
                break
        response = {}
        uuid = 'id'
        uuid_map = {
            'computers': 'agentId',
            'licenses': 'serialNumber'
        }
        if item in uuid_map:
            uuid = uuid_map[item]
        for entry in items:
            if uuid in entry:
                for f in ['computerName', 'loginDomain', 'logonUserName', 'domainOrWorkgroup']:
                    if f in entry:
                        if isinstance(entry[f], (str, unicode)):
                            entry[f] = str(entry[f].encode('utf-8')).lower()
                response[entry[uuid]] = entry

        response = self._remove_unicode(response)
        return response

    def get_domains(self):
        ''' Get a list of domains. '''
        return self._get_items('domains')

    def get_groups(self):
        ''' Get a list of groups. '''
        return self._get_items('groups')

    def get_computers(self):
        ''' Get a list of computers. '''
        return self._get_items('computers')

    def get_licenses(self):
        ''' Get a list of licenses. '''
        return self._get_items('licenses')

    def get_policies(self):
        ''' Get a list of policies. '''
        return self._get_items('policies/summary')

    def get_admin_users(self):
        ''' Get a list of admin users. '''
        return self._get_items('admin-users')

    def authenticate(self):
        ''' Handle authentication. '''
        if self.get_user_session():
            self.is_authenticated = True
        if not self.is_authenticated:
            url = '%s/identity/authenticate' % (self.config.get('url'))
            payload = {
                "username": self.config.settings['username'],
                "password": self.config.settings['password'],
                "domain": "",
            }
            req = self.session.post(url, json=payload, verify=False)
            if req.status_code != 200:
                raise Exception('client',
                                '%d: %s, message: %s' % (req.status_code, req.reason, req.text))
            data = json.loads(req.text)
            if 'token' not in data:
                raise Exception('client', 'authentication response has no token')
            self.config.settings['api_token'] = str(data['token'])
            for k in data:
                self.config.settings['api_' + str(k)] = data[k]
            self.headers['Authorization'] = 'Bearer %s' % (data['token'])
            self.log.debug('writing token %s to %s' % (self.config.settings['api_token'], self.config.settings['api_token_file']))
            with open(self.config.settings['api_token_file'], "w") as token_file:
                token_file.write(self.config.settings['api_token'])
            self.is_authenticated = True
        return

    def _remove_unicode(self, data):
        if isinstance(data, (dict)):
            new_data = {}
            for k in data:
                if isinstance(k, (unicode)):
                    new_data[str(k)] = self._remove_unicode(data[k])
                    continue
                new_data[k] = self._remove_unicode(data[k])
            return new_data
        if isinstance(data, (list)):
            new_data = []
            for entry in data:
                new_data.append(self._remove_unicode(entry))
            return new_data
        elif isinstance(data, (unicode)):
            s = ''
            try:
                s = str(data)
            except:
                s = data.replace(u"\u2018", "'").replace(u"\u2019", "'")
            return str(s)
        else:
            pass
        return data


def new_client():
    '''
    Return an instance of Client.
    '''
    return Client()
