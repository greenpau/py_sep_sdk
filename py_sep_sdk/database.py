#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
py_sep_sdk - Symantec Endpoint Protection Manager API Client Library

Copyright (C) 2019 Paul Greenberg @greenpau
See LICENSE for licensing details
'''

from __future__ import (absolute_import, division, print_function)

import sys
import argparse
import os
import pprint
import ipaddress
import json
import re
import logging
import datetime


class Database(object):

    def __init__(self, computers=None):
        ''' Initializes the class. '''
        self.operating_systems = []
        self.clean_data = False
        self._set_logging()
        self.output_fmt = 'json'
        self.duplicate_agents = None
        self.manager = 'sepm'
        return

    def add_computer_data(self, data):
        if not data:
            return
        if isinstance(data, (dict)):
            self.computers = data
        else:
            jdata = json.load(data)
            if isinstance(jdata, (list)):
                self.computers = {}
                for item in jdata:
                    if 'agentId' in item:
                        self.computers[item['agentId']] = item
            else:
                self.computers = jdata
        self.computers = self._remove_unicode(self.computers)
        self._mark_duplicate_agents()
        self._enrich_computer_data()
        #self._filter_computers()
        return

    def get_computers(self):
        items = []
        for i in sorted(self.computers):
            items.append(self.computers[i])
        return items

    def set_manager(self, s):
        self.manager = s.lower()

    def check_data(self):
        if self.clean_data:
            return
        self.log.debug('data checks begin')
        required_fields = [
            'operatingSystem',
            'computerName',
            'ipAddresses',
            'subnetMasks',
            'macAddresses',
            'gateways',
            'dnsServers',
            'lastUpdateTime',
        ]
        field_pairs = [
            ('ipAddresses', 'subnetMasks'),
            #('ipAddresses', 'macAddresses'),
            #('ipAddresses', 'gateways'),
        ]

        removal_list = []
        for _id in self.computers:
            _continue = False
            agent = self.computers[_id]
            for field in required_fields:
                if field not in agent:
                    self.log.warning("agent %s has no '%s' field" % (_id, field))
                    _continue = True
                    break
            for f in ['ipAddresses', 'subnetMasks', 'gateways', 'winServers', 'dnsServers', 'macAddresses']:
                remove_index = []
                for i, v in enumerate(agent[f]):
                    if v == '0' or v == '' or v == '0.0.0.0':
                        remove_index.append(i)
                remove_index.sort(reverse=True)
                for i in remove_index:
                    agent[f].pop(i)

            for field_pair in field_pairs:
                for i in [0, 1]:
                    if agent[field_pair[i]] is None:
                        self.log.warning("agent %s has %s field as None", _id, field_pair[i])
                        _continue = True
                if _continue:
                    continue
                if len(agent[field_pair[0]]) != len(agent[field_pair[1]]):
                    self.log.warning(
                        "agent %s has %s and %s field lendth mismatch: %s vs. %s",
                        _id,
                        field_pair[0], field_pair[1],
                        agent[field_pair[0]], agent[field_pair[1]],
                    )
                    _continue = True
            if _continue:
                if _id not in removal_list:
                    removal_list.append(_id)
                continue
            if agent['operatingSystem'] not in self.operating_systems:
                self.operating_systems.append(agent['operatingSystem'])

        for _id in removal_list:
            del self.computers[_id]

        self.log.debug('data checks end')
        self.clean_data = True
        return

    def get_agents(self, agent_type=None, agent_ids=None, agent_filters=[], agent_fields=[], fmt='json'):
        headers = ['UniqueID', 'Name']
        items = []
        _filter = None
        _dump_object = False
        for agent_filter in agent_filters:
            for k in ['name', 'ip', 'id', 'os', 'field', 'dump']:
                if not agent_filter.startswith(k + ':'):
                    continue
                if k == 'dump':
                    _dump_object = True
                    continue
                if not _filter:
                    _filter = {}
                if k == 'field':
                    if k not in _filter:
                        _filter[k] = {}
                    arr = agent_filter.split(':')
                    if arr[1] not in _filter[k]:
                        _filter[k][arr[1]] = []
                    _filter[k][arr[1]].append(arr[2]) 
                else:
                    if k not in _filter:
                        _filter[k] = []
                    _value = agent_filter.split(':')[1].lower()
                    _filter[k].append(_value)
        # Iterate over the list of computer objects
        for _id in self.computers:
            '''
            If the input of the function contains a list of agent IDs,
            then do not process agents not on that list.
            '''
            if agent_ids:
                if _id not in agent_ids:
                    continue
            agent = self.computers[_id]
            '''
            If the ID of the computer object is in the list of duplicate agent IDs,
            skip it.
            '''
            if 'isDuplicate' in agent:
                if agent['isDuplicate'] == 1:
                    if agent_ids is None:
                        continue
            '''
            If the input of the function contains agent type,
            then do not process the agents that do not match that type.
            '''
            if agent_type:
                if agent_type in ['windows-server', 'windows']:
                    if not re.search('Windows', agent['operatingSystem']):
                        continue
                if agent_type in ['windows-server']:
                    if not re.search('Server', agent['operatingSystem']):
                        continue
            _name = agent['computerName']
            _uniqueId = agent['uniqueId']
            _operatingSystem = agent['operatingSystem']
            _continue = False
            '''
            Perform additional filtering.
            '''
            if _filter:
                if 'name' in _filter:
                    if _name.lower() not in _filter['name']:
                        continue
                if 'id' in _filter:
                    if _id.lower() not in _filter['id']:
                        continue
                if 'os' in _filter:
                    for k in _filter['os']:
                        if re.match(k, _operatingSystem, re.IGNORECASE):
                            _continue = False
                            break
                        _continue = True
                if 'field' in _filter:
                    for k in _filter['field']:
                        if k not in agent:
                            _continue = True
                            break
                        _value = str(agent[k])
                        if isinstance(agent[k], (unicode)):
                            _value = agent[k]
                        if _value in _filter['field'][k]:
                            self.log.debug('%s vs. %s' % (_value, _filter['field'][k]))
                            break
                        _continue = True
                        break
            if _continue:
                continue
            if _dump_object: 
                items.append(agent)
                continue
            
            '''
            The following applies to any non-dump filters.
            '''
            '''
            ip_addresses = []
            ip_networks = []
            for i, ip_address in enumerate(agent['ipAddresses']):
                if re.match('FE80', ip_address):
                    continue
                elif re.match('169.254', ip_address):
                    continue
                ip_subnet_mask = agent['subnetMasks'][i]
                ip_address_with_mask = "%s/%s" % (ip_address, ip_subnet_mask)
                ip_network = None
                try:
                    ip_network = ipaddress.IPv4Network(ip_address_with_mask, False)
                except Exception as e:
                    self.log.error("agent %s has unsupported IP address: %s, %s", _id, ip_address_with_mask, e)
                    continue
                ip_address = str('%s' % (ip_address))
                ip_network = str('%s' % (ip_network))
                if ip_address not in ip_addresses:
                    ip_addresses.append(ip_address)
                if ip_network not in ip_networks:
                    ip_networks.append(ip_network)
            '''
            ts = datetime.datetime.fromtimestamp(int(agent['lastUpdateTime']) / 1000).strftime('%Y-%m-%d %H:%M:%S')
            item = {
                #'id': str(_id.encode("utf-8")),
                'UniqueID': _uniqueId,
                'Name': str(_name),
                'IP Address': ','.join(agent['ipNetAddresses']),
                'IP Network': ','.join(agent['ipNetworks']),
                'Last Updated Time': ts,
            }
            if agent_fields:
                for agent_field in agent_fields:
                    #self.log.debug(agent_field['name'])
                    if agent_field['name'] not in agent:
                        continue
                    if agent[agent_field['name']] in agent_field['values']:
                        item[agent_field['header']] = agent_field['values'][agent[agent_field['name']]]
                    else:
                        item[agent_field['header']] = str(agent[agent_field['name']])
            for k in item:
                if k not in headers:
                    headers.append(k)
            items.append(item)
        if self.output_fmt in ['json', 'yaml']:
            return {'agents': items}
        if self.output_fmt in ['csv']:
            lines = []
            lines.append(';'.join(headers))
            for item in items:
                line = []
                for header in headers:
                    if header in item:
                        line.append(item[header])
                    else:
                        line.append('')
                lines.append(';'.join(line))
            return '\n'.join(lines) + '\n'
        return None

    def get_operating_systems(self):
        self.check_data()
        data = {}
        for _id in self.computers:
            agent = self.computers[_id]
            _os = str(agent['operatingSystem'])
            if _os not in data:
                data[_os] = {
                    'count': 0,
                }
            data[_os]['count'] += 1
        if self.output_fmt == 'csv':
            lines = []
            for _os in sorted(data):
                line = [_os, str(data[_os]['count'])]
                lines.append(';'.join(line))
            return '\n'.join(lines) + '\n'
        return data

    def get_duplicate_agent_ids(self):
        self._mark_duplicate_agents()
        return self.duplicate_agents

    def _mark_duplicate_agents(self):
        if self.duplicate_agents:
            return
        self.check_data()
        data = {}
        agents = {}
        for _id in self.computers:
            _id = _id
            agent = self.computers[_id]
            _name = agent['computerName']
            if _name not in agents:
                agents[_name] = {}
            if _id not in agents[_name]:
                agents[_name][_id] = agent['lastUpdateTime']
        for _name in agents:
            if len(agents[_name]) < 2:
                continue
            if _name not in data:
                data[_name] = {}
            _most_recently_updated = None
            _most_recently_updated_ts = 0
            for _id in agents[_name]:
                _last_update_ts = int(agents[_name][_id]) / 1000
                if not _most_recently_updated:
                    _most_recently_updated_ts = _last_update_ts
                    _most_recently_updated = _id
                    continue
                if _last_update_ts > _most_recently_updated_ts:
                    data[_name][_most_recently_updated] = _most_recently_updated_ts
                    _most_recently_updated_ts = _last_update_ts
                    _most_recently_updated = _id
                else:
                    data[_name][_id] = _last_update_ts
        _ids = []
        for _name in data:
            for _id in data[_name]:
                _ids.append(_id)
        for _id in self.computers:
            if _id in _ids:
                self.computers[_id]['isDuplicate'] = 1
            else:
                self.computers[_id]['isDuplicate'] = 0
        self.duplicate_agents = _ids
        return

    def get_duplicate_agents(self):
        _ids = self.get_duplicate_agent_ids()
        return self.get_agents(agent_ids=_ids)

    def get_infected_agents(self, agent_filters=[]):
        self.check_data()
        _ids = []
        for _id in self.computers:
            _id = str(_id)
            agent = self.computers[_id]
            if agent['infected'] == 1:
                _ids.append(_id)
        if not _ids:
            return 'None\n'
        if agent_filters:
            return self.get_agents(agent_ids=_ids, agent_filters=agent_filters)
        return self.get_agents(agent_ids=_ids)

    def get_prometheus_metrics(self):
        metrics = [
            {
                'name': 'symc_sepm_agent_auto_protection_status',
                'type': 'gauge',
                'field': 'apOnOff',
                'header': 'Auto-Protection',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_av_engine_status',
                'type': 'gauge',
                'field': 'avEngineOnOff',
                'header': 'AV Engine',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_tamper_status',
                'type': 'gauge',
                'field': 'tamperOnOff',
                'header': 'Tamper Protection',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_elam_status',
                'type': 'gauge',
                'field': 'elamOnOff',
                'header': 'Early launch anti-malware (ELAM)',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_firewall_status',
                'type': 'gauge',
                'field': 'firewallOnOff',
                'header': 'Firewall',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_ptp_status',
                'type': 'gauge',
                'field': 'ptpOnOff',
                'header': 'Proactive Threat Protection (PTP)',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_pep_status',
                'type': 'gauge',
                'field': 'pepOnOff',
                'header': 'Memory Exploit Mitigation Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_cids_browser_firefox_status',
                'type': 'gauge',
                'field': 'cidsBrowserFfOnOff',
                'header': 'Firefox Browser Protection Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_cids_browser_ie_status',
                'type': 'gauge',
                'field': 'cidsBrowserIeOnOff',
                'header': 'IE Browser Protection Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_download_advisor_status',
                'type': 'gauge',
                'field': 'daOnOff',
                'header': 'Download Advisor Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_network_cids_status',
                'type': 'gauge',
                'field': 'cidsDrvOnOff',
                'header': 'Network Intrusion Prevention Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3]
            },
            {
                'name': 'symc_sepm_agent_sonar_status',
                'type': 'gauge',
                'field': 'bashStatus',
                'header': 'SONAR Status',
                'values': {
                    0: 'Disabled',
                    1: 'On',
                    2: 'Not installed',
                    3: 'Disabled by policy',
                    4: 'Malfunctioning',
                    5: 'Disabled as unlicensed',
                    127: 'Status not reported',
                },
                'skip_values': [1, 3],
                'skip_counts': [1, 3],
            },
            {
                'name': 'symc_sepm_agent_reboot_required_status',
                'type': 'gauge',
                'field': 'rebootRequired',
                'header': 'Reboot Required Status',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
                'skip_counts': [0],
            },
            {
                'name': 'symc_sepm_agent_is_vdi_client',
                'type': 'gauge',
                'field': 'isNpvdiClient',
                'header': 'Client is a non-persistent virtual desktop infrastructure (VDI) client',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
            },
            {
                'name': 'symc_sepm_agent_install_client',
                'type': 'gauge',
                'field': 'installType',
                'header': 'Client installation type',
                'values': {
                    0: 'Type 0',
                    1: 'Type 1',
                },
                'skip_values': [0],
                'skip_counts': [0],
            },
            {
                'name': 'symc_sepm_agent_is_infected',
                'type': 'gauge',
                'field': 'infected',
                'header': 'Client is infected',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
                'add_kv_pairs': [
                    {'lastConnectedIpAddr': 'ip_address'},
                    {'logonUserName': 'logon_user_name'},
                    {'operatingSystem': 'operating_system'},
                    {'groupName': 'group_name'},
                ]
            },
            {
                'name': 'symc_sepm_agent_infection_severity',
                'type': 'gauge',
                'field': 'worstInfectionIdx',
                'header': 'Severity of the worst detection that was made',
                'values': {
                    0: 'Viral',
                    1: 'Non-viral malicious',
                    2: 'Malicious',
                    3: 'Antivirus - Heuristic',
                    5: 'Hack tool',
                    6: 'Spyware',
                    7: 'Trackware',
                    8: 'Dialer',
                    9: 'Remote access',
                    10: 'Adware',
                    11: 'Jokeware',
                    12: 'Client compliancy',
                    13: 'Generic load point',
                    14: 'Proactive Threat Scan - Heuristic',
                    15: 'Cookie',
                    9999: 'No detections'
                },
                'skip_values': [9999],
                'skip_totals': True,
            },
            {
                'name': 'symc_sepm_agent_is_deleted',
                'type': 'gauge',
                'field': 'deleted',
                'header': 'Client is deleted',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
                'skip_counts': [0],
            },
            {
                'name': 'symc_sepm_agent_is_online',
                'type': 'gauge',
                'field': 'onlineStatus',
                'header': 'Client is Online',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [1],
                'skip_counts': [1],
            },
            {
                'name': 'symc_sepm_agent_is_cids_silent_mode',
                'type': 'gauge',
                'field': 'cidsSilentMode',
                'header': 'Client IDS driver is installed as an internal component for another protection technology',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
                'skip_counts': [0],
            },
            {
                'name': 'symc_sepm_agent_edr_status',
                'type': 'gauge',
                'field': 'edrStatus',
                'header': 'Endpoint Detection and Response (EDR) Status',
                'values': {
                    0: 'EDR is disabled',
                    1: 'EDR is enabled but not connected to any ATP server',
                    2: 'EDR is enabled and connecting to ATP successfully',
                    3: 'EDR is enabled but cannot authenticate with the ATP server',
                },
                'skip_values': [2],
                'skip_counts': [2],
            },
            {
                'name': 'symc_sepm_agent_type',
                'type': 'gauge',
                'field': 'agentType',
                'header': 'Agent Type',
                'values': {
                    0: 'Unknown',
                    105: 'Symantec Endpoint Protection',
                    151: 'Symantec Network Access Control',
                },
                'skip_values': [105],
                'skip_counts': [105],
            },
            {
                'name': 'symc_sepm_agent_version',
                'type': 'gauge',
                'field': 'agentVersion',
                'header': 'Agent Version',
                'always_on': True,
                'add_kv_pairs': [{'agentVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_deployment_running_version',
                'type': 'gauge',
                'field': 'deploymentRunningVersion',
                'header': 'Agent Deployment Running Version',
                'always_on': True,
                'add_kv_pairs': [{'deploymentRunningVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_deployment_target_version',
                'type': 'gauge',
                'field': 'deploymentTargetVersion',
                'header': 'Agent Deployment Target Version',
                'always_on': True,
                'add_kv_pairs': [{'deploymentTargetVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_operating_system_version',
                'type': 'gauge',
                'field': 'operatingSystem',
                'header': 'Operating System',
                'always_on': True,
                'add_kv_pairs': [{'operatingSystem': 'operating_system'}]
            },
            {
                'name': 'symc_sepm_agent_cids_engine_version',
                'type': 'gauge',
                'field': 'cidsEngineVersion',
                'header': 'IDS Engine Version',
                'always_on': True,
                'add_kv_pairs': [{'cidsEngineVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_cids_defset_version',
                'type': 'gauge',
                'field': 'cidsDefsetVersion',
                'header': 'IDS definition version number',
                'always_on': True,
                'add_kv_pairs': [{'cidsDefsetVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_profile_version',
                'type': 'gauge',
                'field': 'profileVersion',
                'header': 'current profile version of the agent',
                'always_on': True,
                'add_kv_pairs': [{'profileVersion': 'version'}]
            },
            {
                'name': 'symc_sepm_agent_last_deployment_time',
                'type': 'gauge',
                'field': 'lastDeploymentTime',
                'header': 'The time of the last deployment action (GMT)',
                'skip_totals': True,
                'skip_values': [0],
            },
            {
                'name': 'symc_sepm_agent_last_scan_time',
                'type': 'gauge',
                'field': 'lastScanTime',
                'header': 'The last scan time for this agent (GMT)',
                'skip_totals': True,
            },
            {
                'name': 'symc_sepm_agent_last_virus_time',
                'type': 'gauge',
                'field': 'lastVirusTime',
                'header': 'The last time a virus was detected on the client (GMT)',
                'skip_totals': True,
            },
            {
                'name': 'symc_sepm_agent_last_heuristic_threat_time',
                'type': 'gauge',
                'field': 'lastHeuristicThreatTime',
                'header': 'The last time that SONAR detected a risk (GMT)',
                'skip_totals': True,
            },
            {
                'name': 'symc_sepm_agent_is_duplicate',
                'type': 'gauge',
                'field': 'isDuplicate',
                'header': 'Whether the client is a duplicate',
                'values': {
                    0: 'No',
                    1: 'Yes',
                },
                'skip_values': [0],
                'skip_counts': [0],
                'allow_duplicates': True,
            },
            {
                'name': 'symc_sepm_agent_dhcp_server_config',
                'type': 'gauge',
                'field': 'dhcpServer',
                'header': 'DHCP Server configured on the agent',
                'always_on': True,
                'add_kv_pairs': [{'dhcpServer': 'dhcp_server'}]
            },
            {
                'name': 'symc_sepm_agent_dns_server_config',
                'type': 'gauge',
                'field': 'dnsServers',
                'header': 'DNS Server configured on the agent',
                'always_on': True,
                'is_list': True,
                'add_kv_pairs': [{'dnsServers': 'dns_server'}]
            },
            {
                'name': 'symc_sepm_agent_wins_server_config',
                'type': 'gauge',
                'field': 'winServers',
                'header': 'WINS Server configured on the agent',
                'always_on': True,
                'is_list': True,
                'add_kv_pairs': [{'winServers': 'win_server'}]
            },
            {
                'name': 'symc_sepm_agent_default_gateway_config',
                'type': 'gauge',
                'field': 'gateways',
                'header': 'default IP gateway configured on the agent',
                'always_on': True,
                'is_list': True,
                'add_kv_pairs': [{'gateways': 'ip_gateway'}]
            },
            {
                'name': 'symc_sepm_agent_ip_network_config',
                'type': 'gauge',
                'field': 'ipNetworks',
                'header': 'IP network configured on the agent',
                'always_on': True,
                'is_list': True,
                'add_kv_pairs': [{'ipNetworks': 'ip_network'}]
            },
            {
                'name': 'symc_sepm_agent_ip_address_config',
                'type': 'gauge',
                'field': 'ipNetAddresses',
                'header': 'IP address configured on the agent',
                'always_on': True,
                'is_list': True,
                'skip_totals': True,
                'add_kv_pairs': [{'ipNetAddresses': 'ip_address'}]
            },
            {
                'name': 'symc_sepm_agent_group_name_config',
                'type': 'gauge',
                'field': 'groupName',
                'header': 'The group name the agent belongs to',
                'always_on': True,
                'add_kv_pairs': [{'groupName': 'group_name'}]
            },
        ]
        errors = 0
        output = []
        _duplicate_agent_ids = []
        try:
            _duplicate_agent_ids = self.get_duplicate_agent_ids()
            lines = []
            lines.append('# HELP symc_sepm_duplicate_agents_total The number of duplicate agents in Symantec SEPM')
            lines.append('# TYPE symc_sepm_duplicate_agents_total gauge')
            _kv_pairs = []
            _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
            _kv = '{%s}' % ','.join(_kv_pairs)
            lines.append('symc_sepm_duplicate_agents_total%s %d' % (_kv, len(_duplicate_agent_ids)))
            output.extend(lines)
            lines = []
            lines.append('# HELP symc_sepm_agents_total The number of agents (no duplicates) in Symantec SEPM')
            lines.append('# TYPE symc_sepm_agents_total gauge')
            _kv_pairs = []
            _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
            _kv = '{%s}' % ','.join(_kv_pairs)
            lines.append('symc_sepm_agents_total%s %d' % (_kv, (len(self.computers) - len(_duplicate_agent_ids))))
            output.extend(lines)
        except:
            raise
            errors += 1
        for m in metrics:
            if 'skip' in m:
                continue
            _metric = m['name']
            #if _metric != 'symc_sepm_agent_version':
            #    continue
            _metric_type = m['type']
            _is_list_metric = False
            if 'is_list' in m:
                _is_list_metric = True
            _is_always_on = False
            if 'always_on' in m:
                _is_always_on = True
            _is_add_kv_pairs = False
            if 'add_kv_pairs' in m:
                _is_add_kv_pairs = True
            if 'counts' not in m:
                m['counts'] = {}
            lines = []
            try:
                _description = 'Symantec SEP %s' % (m['header'])
                if 'values' in m:
                    _values = []
                    for v in m['values']:
                        t = '%d - %s' % (v, m['values'][v])
                        _values.append(t)
                    if _values:
                        _description += ': ' + ', '.join(_values)
                count = 0
                for _id in self.computers:
                    if _id in _duplicate_agent_ids and 'allow_duplicates' not in m:
                        continue
                    agent =self.computers[_id]
                    _hostname = agent['computerName'].lower()
                    _uniqueId = agent['uniqueId']


                    if _is_list_metric and _is_always_on and _is_add_kv_pairs:
                        _key = None
                        _values = []
                        for kv_pair in m['add_kv_pairs']:
                            for k in kv_pair:
                                _key = kv_pair[k]
                                if k not in self.computers[_id]:
                                    _values.append('Unknown')
                                    break
                                if not isinstance(self.computers[_id][k], (list)):
                                    _values.append('Unknown-%s-%s' % (k, type(self.computers[_id][k])))
                                    break
                                _values = self.computers[_id][k]
                                break
                        if _key and len(_values) > 0:
                            for _value in _values:
                                if _value == '0.0.0.0':
                                    continue
                                _kv_pairs = []
                                _kv_pairs.insert(0, '%s="%s"' % (_key, _value))
                                _kv_pairs.insert(0, 'hostname="%s"' % (_hostname))
                                _kv_pairs.insert(0, 'uuid="%s"' % (_uniqueId))
                                _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
                                _kv = '{%s}' % ','.join(_kv_pairs)
                                lines.append('%s%s %d' % (_metric, _kv, 1))
                                _value = '{%s="%s"}' % (_key, _value)
                                if _value not in m['counts']:
                                    m['counts'][_value] = 1
                                else:
                                    m['counts'][_value] += 1
                    else:
                        _kv_pairs = []
                        if 'add_kv_pairs' in m:
                            for kv_pair in m['add_kv_pairs']:
                                for k in kv_pair:
                                    _key = kv_pair[k]
                                    if k not in self.computers[_id]:
                                        _value = 'Unknown'
                                    else:
                                        _value = self.computers[_id][k]
                                    if _value is None:
                                        _value = 'Unknown'
                                    if _value == '':
                                        _value = 'Unknown'
                                    if k not in self.computers[_id]:
                                        _value = 'Unknown'
                                    _kv_pairs.append('%s="%s"' % (_key, _value))
                        if 'add_kv_pairs' in m and 'always_on' in m:
                            _value = '{%s}' % ','.join(_kv_pairs)
                            if _value not in m['counts']:
                                m['counts'][_value] = 1
                            else:
                                m['counts'][_value] += 1
                        _kv_pairs.insert(0, 'hostname="%s"' % (_hostname))
                        _kv_pairs.insert(0, 'uuid="%s"' % (_uniqueId))
                        _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
                        _kv = '{%s}' % ','.join(_kv_pairs)
                        _value = None
                        if 'always_on' in m:
                            _value = 1
                            lines.append('%s%s %d' % (_metric, _kv, _value))
                        else:
                            if m['field'] in self.computers[_id]:
                                if self.computers[_id][m['field']] == '':
                                    _value = 0
                                else:
                                    _value = int(self.computers[_id][m['field']])
                                _add_metric = True
                                if 'skip_values' in m:
                                    if _value in m['skip_values']:
                                        _add_metric = False
                                if _add_metric:
                                    try:
                                        lines.append('%s%s %d' % (_metric, _kv, _value))
                                    except:
                                        pprint.pprint(m)
                                        pprint.pprint(self.computers[_id])
                                        raise 
                            if _value not in m['counts']:
                                m['counts'][_value] = 1
                            else:
                                m['counts'][_value] += 1
                    #count += 1
                    #if count > 5:
                    #    break
                '''
                Output metrics, if any.
                '''
                if len(lines) > 0:
                    output.append('# HELP %s %s' % (_metric, _description))
                    output.append('# TYPE %s %s' % (_metric, _metric_type))
                    output.extend(lines)
                '''
                Skip totals if necessary.
                '''
                if 'skip_totals' in m:
                    continue
                '''
                Generate summaries.
                '''
                _metric = m['name'] + '_total'
                _description = 'Symantec SEP %s totals per status' % (m['header'])
                lines = []
                for c in m['counts']:
                    if 'skip_counts' in m:
                        if c in m['skip_counts']:
                            continue
                    _value = m['counts'][c]
                    _kv_pairs = []
                    _kv = ''
                    if 'add_kv_pairs' in m and 'always_on' in m:
                        _kv = c
                    else:
                        if c is not None:
                            status_name = 'Unknown'
                            if c in m['values']:
                                status_name = m['values'][c]
                            else:
                                status_name = 'Unknown-%d' % (c)
                            _kv_pairs.append('status="%s"' % (status_name))
                        _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
                        _kv = '{%s}' % ','.join(_kv_pairs)

                    lines.append('%s%s %d' % (_metric, _kv, _value))
                if lines:
                    output.append('# HELP %s %s' % (_metric, _description))
                    output.append('# TYPE %s %s' % (_metric, _metric_type))
                    output.extend(lines)
            except:
                raise
                errors += 1

        output.append('# HELP symc_sepm_status_values The values of metrics status values.')
        output.append('# TYPE symc_sepm_status_values gauge')
        for m in metrics:
            if 'skip' in m:
                continue
            if 'values' not in m:
                continue
            for v in m['values']:
                _kv_pairs = []
                _kv_pairs.insert(0, 'metric_status="%s"' % (m['values'][v]))
                _kv_pairs.insert(0, 'metric_value="%s"' % (v))
                _kv_pairs.insert(0, 'metric_name="%s"' % (m['name']))
                _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
                _kv = '{%s}' % ','.join(_kv_pairs)
                output.append('symc_sepm_status_values%s 1' % (_kv))
 
        output.append('# HELP symc_sepm_collector_errors Symantec SEP Collection Errors')
        output.append('# TYPE symc_sepm_collector_errors gauge')
        _kv_pairs = []
        _kv_pairs.insert(0, 'manager="%s"' % (self.manager))
        _kv = '{%s}' % ','.join(_kv_pairs)
        output.append('symc_sepm_collector_errors%s %d' % (_kv, errors))
        return '\n'.join(output) + '\n'
            

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
                s = ''.join([i if ord(i) < 128 else ' ' for i in data])
            return str(s)
        else:
            pass
        return data

    def _enrich_computer_data(self):
        for _id in self.computers:
            if 'group' in self.computers[_id]:
                if 'name' in self.computers[_id]['group']:
                    groupName = self.computers[_id]['group']['name']
                    groupNameArray = groupName.split('\\')
                    if 'My Company' == groupNameArray[0]:
                        groupNameArray.pop(0)
                    if len(groupNameArray) == 0:
                        groupName = 'My Company'
                    else:
                        groupName = ' - '.join(groupNameArray)
                    self.computers[_id]['groupName'] = groupName
            agent = self.computers[_id]
            if 'ipAddresses' in agent:
                for i, ip_address in enumerate(agent['ipAddresses']):
                    try:
                        if len(ip_address) > 16:
                            continue
                        if ip_address == '':
                            continue
                        if re.match('FE80', ip_address):
                            continue
                        elif re.match('169.254', ip_address):
                            continue
                        ip_subnet_mask = agent['subnetMasks'][i]
                        ip_address_with_mask = str("%s/%s" % (ip_address, ip_subnet_mask))
                        ip_network = None
                        try:
                            ip_network = ipaddress.IPv4Network(unicode(ip_address_with_mask), False)
                        except Exception as e:
                            self.log.error("agent %s has unsupported IP address: %s, %s", _id, ip_address_with_mask, e)
                            continue
                        ip_address = str('%s/%d' % (ip_address, ip_network.prefixlen))
                        ip_network = str('%s' % (ip_network))
                        if 'ipNetworks' not in self.computers[_id]:
                            self.computers[_id]['ipNetworks'] = []
                        if ip_network not in self.computers[_id]['ipNetworks']:
                            self.computers[_id]['ipNetworks'].append(ip_network)
                        if 'ipNetAddresses' not in self.computers[_id]:
                            self.computers[_id]['ipNetAddresses'] = []
                        if ip_address not in self.computers[_id]['ipNetAddresses']:
                            self.computers[_id]['ipNetAddresses'].append(ip_address)
                    except:
                        continue
        return

    @staticmethod
    def is_ascii(s):
        try:
            return all(ord(c) < 128 for c in s)
        except TypeError:
            return False 

    def _set_logging(self):
        self.debug_enabled = False
        self.log = logging.getLogger('computers')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)

    def debug(self):
        ''' Enables debugging of the class. '''
        if self.debug_enabled:
            return
        self.log.setLevel(logging.DEBUG)
        self.debug_enabled = True
        return

def new():
    '''
    Return an instance of Database.
    '''
    return Database()
