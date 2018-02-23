#!/bin/bash
# checks if this attachment point is ready. Sets it if not.
set -e

PORT=1194
NETWORK="10.0.8.0"
SUBNET="255.255.255.0"

usage="$(basename $0) -n 'Name' [-p 1194] [-s 255.255.255.0]
Four files need to be present in the working directory: ca.crt, dh4096.pem, Name.crt and Name.key

where:
    -n Name     Name of this AS, also used for two of the files.
    -p Port     Port where the OpenVPN server will listen. Defaults to 1194.
    -i Net      Network for the OpenVPN server. Defaults to 10.0.8.0
    -s Subnet   Subnet to configure the OpenVPN server. Defaults to 255.255.255.0"
while getopts ":n:p:i:s:" opt; do
case $opt in
    h)
        echo "$usage"
        exit 0
        ;;
    n)
        asname="$OPTARG"
        ;;
    p)
        PORT="$OPTARG"
        ;;
    i)
        NETWORK="$OPTARG"
        ;;
    s)
        SUBNET="$OPTARG"
        ;;
    \?)
        echo "Invalid option: -$OPTARG" >&2
        echo "$usage" >&2
        exit 1
        ;;
    :)
        echo "Option -$OPTARG requires an argument." >&2
        echo "$usage" >&2
        exit 1
        ;;
esac
done

if [ -z "$asname" ]; then
    echo "$usage"
    exit 1
fi

# ca.crt, asname.crt, asname.key, dh4096.pem

if [ ! -f "ca.crt" ] || [ ! -f "dh4096.pem" ] || [ ! -f "$asname.crt" ] || [ ! -f "$asname.key" ]; then
    echo "Missing one or more credential files: ca.crt, dh4096.pem, $asname.crt or $asname.key"
    exit 1
fi

OPENVPNSERVERCONF=$(cat <<ENDOFCONF
port $PORT
proto udp
dev tun

# certificates and keys
ca   ca.crt
cert $asname.crt
key  $asname.key  # This file should be kept secret
dh   dh4096.pem

topology subnet
server $NETWORK $SUBNET
ifconfig-pool-persist ipp.txt
client-config-dir /home/$USER/openvpn_ccd
keepalive 10 120
;tls-auth ta.key 0 # This file is secret
comp-lzo
;max-clients 100
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
mute 20
ENDOFCONF
)

# STEPS

# (from https://help.ubuntu.com/lts/serverguide/openvpn.html)
# install openvpn
if ! dpkg-query -s openvpn &> /dev/null ; then
    sudo apt-get install openvpn -y
fi
# copy server conf to /etc/openvpn/server.conf
TMPFILE=$(mktemp)
echo "$OPENVPNSERVERCONF" > "$TMPFILE"
sudo mv "$TMPFILE" "/etc/openvpn/server.conf"

# copy the 4 files from coordinator
sudo cp "ca.crt" "dh4096.pem" "$asname.crt" "$asname.key" "/etc/openvpn/"
sudo chmod 600 "/etc/openvpn/$asname.key"

# client configurations to get static IPs
mkdir -p "$HOME/openvpn_ccd"

# uncomment /etc/sysctl.conf ipv4.ip_foward and restart sysctl
sudo sed -i -- 's/^#.*net.ipv4.ip_forward=1\(.*\)$/net.ipv4.ip_forward=1\1/g' "/etc/sysctl.conf"


# start service systemctl start openvpn@server
sudo systemctl stop "openvpn@server" || true
sudo systemctl start "openvpn@server"
sudo systemctl enable "openvpn@server"

# TODO copy and run update gen
echo "Done."
