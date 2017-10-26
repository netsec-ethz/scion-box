#!/usr/bin/env bash
# This file is located in $SCIONPATH and called periodically by cron or systemd

export PYTHONPATH=python/:sub/web/:.

python3 python/topology/update_gen.py
