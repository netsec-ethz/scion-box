#!/usr/bin/env bash
# This file is located in the scion-Box path and called when the Box needs a gen folder.

export PYTHONPATH=$PYTHONPATH:../scion/python/:../scion-web/:../scion/:

# Run the init script
python3 init.py
ret=$?
if [ $ret -ne 0 ]; then
     beep -l 350 -f 392 -D 100
else
    echo "Init Finished sucessfully!"
    # Start BW/RTT Servers
    echo "Starting RTT Server"
    python3 rtt_test.py &
    echo "Starting BW Server"
    cd igi-ptr-2.1
    ./ptr-server &
    cd ..
    #Now the Heartbeat script is started
    ./heartBeat.sh
fi

