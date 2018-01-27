#!/usr/bin/env bash
# This file is located in the scion-Box path and called to start the Heartbeat.

export PYTHONPATH=$PYTHONPATH:../scion/python/:../scion-web/:../scion/:

while :
do
  python3 heartbeat.py
  sleep 60
done

