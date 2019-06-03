#!/bin/bash

# File: /usr/local/bin/get_sepm_metrics.sh

symc-sep-client --get-prometheus-metrics -o /var/lib/node_exporter/sepm.prom
