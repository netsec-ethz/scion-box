# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`rtt_simple.py` ---  script to compute the RTT
==============================================================================
"""
# Stdlib
import socket
import datetime

# SCION-Box
from defines import(
    RTT_SERVER_PORT,
    MEASUREMENTS,
)

"""
The following configurations need to be customized to the Box
"""

def rtt_client(ip_address):
    """
    Send packets to the rtt server and wait for a response
    :param: List of potential neighbor IP addresses
    :return: minimum of computed rtts
    """
    # Find MAC and IP address
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        m_list =[]
        server_address = (ip_address, RTT_SERVER_PORT)
        print ('connecting to %s port %s' % server_address)
        sock.settimeout(10)
        sock.connect(server_address)
        for i in range(0,MEASUREMENTS-1):
            sendtime = datetime.datetime.now()
            nonce = str(sendtime)
            sock.sendall(nonce.encode())
            sock.recv(1024)
            recvtime = datetime.datetime.now()
            rtt = (recvtime - sendtime).microseconds / 1000
            m_list.append(rtt)

        sock.close()
    except socket.error as e:
        print ("[ERROR]", e)
        return -1

    return min(m_list)


def rtt_server():
    """
    Sends back packet so the client can compute the RTT
    """
    serversocket = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('', RTT_SERVER_PORT))
    serversocket.listen(1)
    while True:
        (clientsocket, address) = serversocket.accept()
        print ('new connection from %s %s' % address)
        for i in range(0, MEASUREMENTS-1):
            clientsocket.recv(1024)
            clientsocket.send("ACK".encode())
        clientsocket.close()


def main():
    rtt_server()

if __name__ == '__main__':
    main()
