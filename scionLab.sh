#!/usr/bin/env bash

# This file is located in $SCIONBOX and called periodically by cron or systemd

set -e
SC="$HOME/go/src/github.com/scionproto/scion"
BASE=$(dirname $0)

IA=$(cat $SC/gen/ia)
ACC_ID=$(cat $SC/gen/account_id)
ACC_PW=$(cat $SC/gen/account_secret)
IP_ADDR=$(hostname -I | awk '{print $1}')
URL="https://scion-ad6.inf.ethz.ch"

export PYTHONPATH=$SC:$SC/python:$BASE/sub/util/:$BASE
python3 $BASE/update_gen.py --url "$URL" --updateAS "$IA" --accountId "$ACC_ID" --secret "$ACC_PW" --address "$IP_ADDR" $*
