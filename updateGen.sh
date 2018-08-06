#!/usr/bin/env bash

# This file is located in $SCIONBOX and called periodically by cron or systemd

set -e
SC="$HOME/go/src/github.com/scionproto/scion"
BASE=$(dirname $0)
if [ -f "$SC/gen/ia" ]; then
    IAS=$(cat $SC/gen/ia)
fi
if [ -f "$SC/gen/account_id" ]; then
    ACC_ID=$(cat $SC/gen/account_id)
fi
if [ -f "$SC/gen/account_secret" ]; then
    ACC_PW=$(cat $SC/gen/account_secret)
fi
IP_ADDR=$(hostname -I | awk '{print $1}')
URL="https://www.scionlab.org"

export PYTHONPATH=$SC:$SC/python:$BASE/sub/util/:$BASE
while read -r IA; do
    echo "Updating AP for IA: $IA ..."
    python3 $BASE/update_gen.py --url "$URL" --updateAS "$IA" --accountId "$ACC_ID" --secret "$ACC_PW" --address "$IP_ADDR" $*
done <<< "$IAS"
echo "Done updating AP."
