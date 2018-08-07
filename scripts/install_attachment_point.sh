#!/bin/bash
# checks if this attachment point is ready. Sets it if not.
set -e


PORT=1194
NETWORK="10.0.8.0"
SUBNET="255.255.255.0"
no_vpn=0
inside_docker=0

thisdir="$(dirname $0)"
cd "$thisdir"

usage="$(basename $0) -i IA -a account_id -b account_secret [-p 1194] [-s 255.255.255.0]
where:
    -i IA           IA of this AS, also used to derive the name of the two VPN server files. E.g. 1-17, and will look for AS1-17.{crt,key}
    -p Port         Port where the OpenVPN server will listen. Defaults to 1194.
    -n Net          Network for the OpenVPN server. Defaults to 10.0.8.0
    -s Subnet       Subnet to configure the OpenVPN server. Defaults to 255.255.255.0
    -a account_id   Account ID
    -b ac._secret   Account secret
    -t              Don't install any VPN files, only update scripts and services.
    -d              Run inside a docker container."
while getopts ":hi:p:n:s:a:b:td" opt; do
case $opt in
    h)
        echo "$usage"
        exit 0
        ;;
    i)
        ia="$OPTARG"
        asname="AS$ia"
        ;;
    p)
        PORT="$OPTARG"
        ;;
    n)
        NETWORK="$OPTARG"
        ;;
    s)
        SUBNET="$OPTARG"
        ;;
    a)
        ACC_ID="$OPTARG"
        ;;
    b)
        ACC_PWD="$OPTARG"
        ;;
    t)
        no_vpn=1
        ;;
    d)
        inside_docker=1
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
if [ $inside_docker -eq 1 ]; then
    no_vpn=1
fi

pip3 install --user -r "../requirements.txt"

if [ "$no_vpn" -eq 0 ] && { [ -z "$asname" ] || [ -z "$ACC_ID" ] || [ -z "$ACC_PWD" ]; } then
    echo "$usage"
    exit 1
fi

declare -a vpn_files=("ca.crt"
                      "dh4096.pem"
                      "$asname.crt"
                      "$asname.key")
declare -a updater_files=("../update_gen.py"
                          "../updateGen.sh"
                          "../sub/util/local_config_util.py")
declare -a service_files=("files/updateAS.service"
                          "files/updateAS.timer")
declare -a files=("${updater_files[@]}")

if [ $inside_docker -eq 0 ]; then
    files+=("${service_files[@]}")
fi
if [ "$no_vpn" -eq 0 ]; then
    files+=("${vpn_files[@]}"
            "server.conf")
fi

missingFiles=()
for f in "${files[@]}"; do
    if [ ! -f "$f" ]; then
        missingFiles+=("$f")
    fi
done

if [ ! -z "$missingFiles" ]; then
    echo "For this script to work we need the following files in the working directory:"
    echo "${files[@]}"
    echo "But there are missing files:"
    echo "${missingFiles[@]}"
    echo "Get the .key and .crt files from the Coordinator. Run ./build-key-server $asname"
    exit 1
fi

# STEPS
TMPFILE=$(mktemp)
if [ "$no_vpn" -eq 0 ]; then
    # (from https://help.ubuntu.com/lts/serverguide/openvpn.html)
    # install openvpn
    if ! dpkg-query -s openvpn &> /dev/null ; then
        sudo apt-get install openvpn -y
    fi

    # copy server conf to /etc/openvpn/server.conf
    cp "server.conf" "$TMPFILE"
    sed -i -- "s/_PORT_/$PORT/g" "$TMPFILE"

    sed -i -- "s/_ASNAME_/$asname/g" "$TMPFILE"
    sed -i -- "s/_NETWORK_/$NETWORK/g" "$TMPFILE"
    sed -i -- "s/_SUBNET_/$SUBNET/g" "$TMPFILE"
    sed -i -- "s/_USER_/$USER/g" "$TMPFILE"
    sudo mv "$TMPFILE" "/etc/openvpn/server.conf"

    # copy the 4 files from coordinator
    sudo cp "${vpn_files[@]}" "/etc/openvpn/"
    sudo chmod 600 "/etc/openvpn/$asname.key"

    # client configurations to get static IPs
    mkdir -p "$HOME/openvpn_ccd"

    # uncomment /etc/sysctl.conf ipv4.ip_foward and restart sysctl
    sudo sed -i -- 's/^#.*net.ipv4.ip_forward=1\(.*\)$/net.ipv4.ip_forward=1\1/g' "/etc/sysctl.conf"

    # start service systemctl start openvpn@server
    sudo systemctl stop "openvpn@server" || true
    sudo systemctl start "openvpn@server"
    sudo systemctl enable "openvpn@server"

    # create the three ia, account_secret account_id files under gen :
    pushd "$SC/gen" >/dev/null
    printf "$ia" > "ia"
    printf "$ACC_ID" > account_id
    printf "$ACC_PWD" > account_secret
    popd >/dev/null
fi

# copy and run update gen
cp "${updater_files[@]}" "$HOME/.local/bin/"
if [ $inside_docker -eq 0 ]; then
    sudo systemctl stop "updateAS.timer" || true
    sudo systemctl stop "updateAS.service" || true
    for f in "${service_files[@]}"; do
        cp "$f" "$TMPFILE"
        sed -i -- "s/_USER_/$USER/g" "$TMPFILE"
        sudo cp "$TMPFILE" "/etc/systemd/system/$(basename $f)"
    done
    sudo systemctl daemon-reload
    sudo systemctl start "updateAS.service" || true
    sudo systemctl enable "updateAS.service"
    sudo systemctl start "updateAS.timer"
    sudo systemctl enable "updateAS.timer"
fi

echo "Done."
