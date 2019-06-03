py\_sep\_sdk
============

Unofficial Symantec Endpoint Protection Manager API Client Library.

References: - `Symantec Endpoint Protection Manager REST API
Reference <https://apidocs.symantec.com/home/saep>`__

Installation
------------

First, add ``~/.py_sep_sdk.rc`` user credentials file:

::

    [credentials]
    username = "admin"
    password = "P@ssword"
    domain = "EXAMPLE.COM"

    [manager]
    host = "sepm"
    port = "8446"
    protocol = "https"

Then, create installation package:

.. code:: bash

    make package

Next, install the package:

.. code:: bash

    $ sudo pip install dist/py_sep_sdk-1.0.8.tar.gz --no-binary py_sep_sdk
    DEPRECATION: Python 2.7 will reach the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 won't be maintained after that date. A future version of pip will drop support for Python 2.7.
    Processing ./dist/py_sep_sdk-1.0.8.tar.gz
    Requirement already satisfied: setuptools in /usr/lib/python2.7/site-packages (from py-sep-sdk==1.0.8) (40.6.3)
    Requirement already satisfied: wheel in /usr/lib/python2.7/site-packages (from py-sep-sdk==1.0.8) (0.32.3)
    Requirement already satisfied: requests>=2.21.0 in /usr/lib/python2.7/site-packages (from py-sep-sdk==1.0.8) (2.21.0)
    Requirement already satisfied: ipaddress in /usr/lib/python2.7/site-packages (from py-sep-sdk==1.0.8) (1.0.22)
    Requirement already satisfied: urllib3<1.25,>=1.21.1 in /usr/lib/python2.7/site-packages (from requests>=2.21.0->py-sep-sdk==1.0.8) (1.24.1)
    Requirement already satisfied: chardet<3.1.0,>=3.0.2 in /usr/lib/python2.7/site-packages (from requests>=2.21.0->py-sep-sdk==1.0.8) (3.0.4)
    Requirement already satisfied: idna<2.9,>=2.5 in /usr/lib/python2.7/site-packages (from requests>=2.21.0->py-sep-sdk==1.0.8) (2.8)
    Requirement already satisfied: certifi>=2017.4.17 in /usr/lib/python2.7/site-packages (from requests>=2.21.0->py-sep-sdk==1.0.8) (2018.11.29)
    Skipping bdist_wheel for py-sep-sdk, due to binaries being disabled for it.
    Installing collected packages: py-sep-sdk
      Running setup.py install for py-sep-sdk ... done
    Successfully installed py-sep-sdk-1.0.8

If necessary, uninstall the package:

.. code:: bash

    $ pip uninstall py-sep-sdk
    Uninstalling py-sep-sdk-1.0.1:
      Would remove:
        /usr/bin/symc-sep-client
        /usr/lib/python2.7/site-packages/py_sep_sdk-1.0.1-py2.7.egg-info
        /usr/lib/python2.7/site-packages/py_sep_sdk/*
    Proceed (y/n)? y
      Successfully uninstalled py-sep-sdk-1.0.1

Getting Started
---------------

The package comes with ``symc-sep-client`` command line utility. It is a
great example if you want to learn how this API client works.

General Usage
~~~~~~~~~~~~~

::

    symc-sep-client - Symantec EPM API Client

    optional arguments:
      -h, --help            show this help message and exit

      -i FILE               Read from input file (or stdin); only works with non-
                            liver queries
      -o output             Write to output file (or stdout)
      --manager manager     SEP Manager IP address or name
      --filter KEY:VALUE    Object filters, e.g. ip:1.1.1.1, name:nysrv1
      --format {json,csv,yaml}
                            Output format
      --cron                Set for cronjobs
      --debug               Enable debugging

    Available Actions:
      --get-version         performs live query for API version
      --get-domains         performs live query for domains
      --get-groups          performs live query for groups
      --get-computers       performs live query for computers
      --get-licenses        performs live query for licenses
      --get-policies        performs live query for policies
      --get-admin-users     performs live query for admin users
      --delete-agent AGENT_ID
                            deletes an agent from SEPM by its ID
      --get-prometheus-metrics
                            output Prometheus metrics
      --dump-agents         dumps agents
      --dump-operating-systems
                            dumps operating system types for the agents
      --dump-windows-server-agents
                            dumps agents with Windows Server OS
      --dump-duplicate-agents
                            dumps duplicate agents
      --dump-agent-info     dumps agent information
      --check-data          checks the quality of input data

    documentation: https://github.com/greenpau/py_sep_sdk

Computer Objects
~~~~~~~~~~~~~~~~

The following command fetches all computer records from SEP Manager host
``sepmanager1`` and stores them in ``/tmp/computers.json``:

.. code:: bash

    symc-sep-client --manager sepmanager1 --get-computers -o /tmp/computers.json

Next, having that data, a user may query for a specific server, e.g.
``server1``:

.. code:: bash

    symc-sep-client -i /tmp/computers.json --dump-agent-info --filter "name:server1" --debug

Duplicate Computer Objects
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following sequence of commands helps getting rid of duplicate
computer objects in SEP Manager. Please pay attention and replace
``sepmanager1`` with the name of an appropriate SEP Manager.

.. code:: bash

    symc-sep-client --manager sepmanager1 --get-computers -o /tmp/computers.json
    symc-sep-client -i /tmp/computers.json --dump-duplicate-agents --debug --format csv > /tmp/computers.dups.list
    cat /tmp/computers.dups.list | cut -d";" -f1 | sort | uniq | sed 's/^/symc-sep-client --manager sepmanager1 --delete-agent /;s/$/; sleep 1;/' | grep -v "UniqueID" > /tmp/doit.sh
    chmod +x /tmp/doit.sh
    /tmp/doit.sh

Prometheus Metrics
~~~~~~~~~~~~~~~~~~

Configure the following ``cron`` job to collect and export SEP Manager
metrics to Prometheus. The ``cron`` argument is necessary when running
the command via ``cron``:

::

    # crontab -l
    SHELL=/bin/bash

    */5 * * * * symc-sep-client --get-prometheus-metrics -o /var/lib/node_exporter/sepm.prom --cron

The exported metrics are:

-  ``symc_sepm_agent_auto_protection_status``
-  ``symc_sepm_agent_auto_protection_status_total``
-  ``symc_sepm_agent_av_engine_status``
-  ``symc_sepm_agent_av_engine_status_total``
-  ``symc_sepm_agent_cids_browser_firefox_status``
-  ``symc_sepm_agent_cids_browser_firefox_status_total``
-  ``symc_sepm_agent_cids_browser_ie_status``
-  ``symc_sepm_agent_cids_browser_ie_status_total``
-  ``symc_sepm_agent_cids_defset_version``
-  ``symc_sepm_agent_cids_defset_version_total``
-  ``symc_sepm_agent_cids_engine_version``
-  ``symc_sepm_agent_cids_engine_version_total``
-  ``symc_sepm_agent_default_gateway_config``
-  ``symc_sepm_agent_default_gateway_config_total``
-  ``symc_sepm_agent_deployment_running_version``
-  ``symc_sepm_agent_deployment_running_version_total``
-  ``symc_sepm_agent_deployment_target_version``
-  ``symc_sepm_agent_deployment_target_version_total``
-  ``symc_sepm_agent_dhcp_server_config``
-  ``symc_sepm_agent_dhcp_server_config_total``
-  ``symc_sepm_agent_dns_server_config``
-  ``symc_sepm_agent_dns_server_config_total``
-  ``symc_sepm_agent_download_advisor_status``
-  ``symc_sepm_agent_download_advisor_status_total``
-  ``symc_sepm_agent_edr_status``
-  ``symc_sepm_agent_edr_status_total``
-  ``symc_sepm_agent_elam_status``
-  ``symc_sepm_agent_elam_status_total``
-  ``symc_sepm_agent_firewall_status``
-  ``symc_sepm_agent_firewall_status_total``
-  ``symc_sepm_agent_group_name_config``
-  ``symc_sepm_agent_group_name_config_total``
-  ``symc_sepm_agent_infection_severity``
-  ``symc_sepm_agent_install_client``
-  ``symc_sepm_agent_install_client_total``
-  ``symc_sepm_agent_ip_address_config``
-  ``symc_sepm_agent_ip_network_config``
-  ``symc_sepm_agent_ip_network_config_total``
-  ``symc_sepm_agent_is_cids_silent_mode``
-  ``symc_sepm_agent_is_cids_silent_mode_total``
-  ``symc_sepm_agent_is_duplicate``
-  ``symc_sepm_agent_is_duplicate_total``
-  ``symc_sepm_agent_is_infected_total``
-  ``symc_sepm_agent_is_online``
-  ``symc_sepm_agent_is_online_total``
-  ``symc_sepm_agent_is_vdi_client_total``
-  ``symc_sepm_agent_last_deployment_time``
-  ``symc_sepm_agent_last_heuristic_threat_time``
-  ``symc_sepm_agent_last_scan_time``
-  ``symc_sepm_agent_last_virus_time``
-  ``symc_sepm_agent_network_cids_status``
-  ``symc_sepm_agent_network_cids_status_total``
-  ``symc_sepm_agent_operating_system_version``
-  ``symc_sepm_agent_operating_system_version_total``
-  ``symc_sepm_agent_pep_status``
-  ``symc_sepm_agent_pep_status_total``
-  ``symc_sepm_agent_profile_version``
-  ``symc_sepm_agent_profile_version_total``
-  ``symc_sepm_agent_ptp_status``
-  ``symc_sepm_agent_ptp_status_total``
-  ``symc_sepm_agent_reboot_required_status``
-  ``symc_sepm_agent_reboot_required_status_total``
-  ``symc_sepm_agent_sonar_status``
-  ``symc_sepm_agent_sonar_status_total``
-  ``symc_sepm_agents_total``
-  ``symc_sepm_agent_tamper_status``
-  ``symc_sepm_agent_tamper_status_total``
-  ``symc_sepm_agent_type``
-  ``symc_sepm_agent_type_total``
-  ``symc_sepm_agent_version``
-  ``symc_sepm_agent_version_total``
-  ``symc_sepm_agent_wins_server_config``
-  ``symc_sepm_agent_wins_server_config_total``
-  ``symc_sepm_collector_errors``
-  ``symc_sepm_duplicate_agents_total``
-  ``symc_sepm_status_values``

