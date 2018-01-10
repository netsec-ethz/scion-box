#!/usr/bin/env bash
# This file is located in $SCIONPATH and called periodically by cron or systemd

export PYTHONPATH=../scion/python/:sub/util/:.

python3 ./update_gen.py
