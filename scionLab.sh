#!/usr/bin/env bash
# This file is located in $SCIONBOX and called periodically by cron or systemd

export PYTHONPATH=$SC:$SC/python:sub/util/:.

python3 ./update_gen.py $*
