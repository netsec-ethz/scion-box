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
:mod:`link_test.py` --- Script that runs BW/RTT tests to potential neigbhors
==============================================================================

This file is located where igi_client is located
"""
# Stdlib
from subprocess import call
import logging
import threading

# SCION-Box
from rtt_test import rtt_client
from defines import(
    PTR_SERVER_PORT,
    PTR_PATH_CLIENT,
    OUTPUT_PATH_CLIENT,
    REPETITIONS,
)


m_list = []


def test_links(Potential_Neighbors):
    """
    Runs connection tests to each potential neighbor.
    :param: List of potential neighbor IP addresses
            [{AS_ID: "1",ISD_ID: "1", IP: "135.251.53.1"},
			{AS_ID: "6",ISD_ID: "1", IP: "13.2.53.1"}]
    :return: List like above but with BW: and RTT:
    """
    logging.info("Running connection test for neighbors:%s", str(Potential_Neighbors))
    threads = []
    for i,nb in enumerate(Potential_Neighbors):
        t = threading.Thread(target=connection_test, args=(nb,))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    logging.info("[INFO] Measurements: %s", str(m_list))
    return m_list


def connection_test(nb):
    """
    Runs RTT & BW tests for one neighbor
    :param nb: dictionary of the pot. Neighbor
    """
    IP = nb["IP"]
    bw = bw_test(IP)
    nb["BW"] = bw
    rtt = rtt_test(IP)
    nb["RTT"] = rtt
    m_list.append(nb)


def _get_output_file(ip_address):
    """
    Opens the BW test output File
    :param ip_address: address to which BW was measured
    :return: The opened File
    """
    fn = OUTPUT_PATH_CLIENT + str(ip_address) + ".txt"
    try:
        file = open(fn, 'r')
    except IOError:
        file = open(fn, 'w')
    file.close()
    return fn


def bw_test(ip_address):
    """
    Calls a modified version of igi-udp, If there is an error we retry 5 times
    if no succes the returned value is -1.
    :param ip_address: string of the IP address to which we test the connection
    :return: int bw: the bottelneck bw estimated by igi-udp.
    """
    igi_udp_path = PTR_PATH_CLIENT
    for i in range(0,REPETITIONS-1):
        call([igi_udp_path, "-p " + str(PTR_SERVER_PORT), "-f" + _get_output_file(ip_address), ip_address])
        f = open(_get_output_file(ip_address))
        for line in f:
            if "CONNECTION FAILED" in line:
                break
            if "Packet Transmit Rate:" in line:
                bw = _get_bw(line)
                return bw/8
    return -1


def _get_bw(line):
    """
    Extracts the BW from the string of the Form
    Bottleneck Bandwidth: bw
    :param line: string in which the bw is saved
    :return: int bw
    """
    index = line.index(":")
    bw = ""
    for c in line[index+1:]:
        if c != " " and c!= "\n":
            if c == "M":
                break
            bw = bw + c
    return float(bw)


def rtt_test(ip_address):
    """
    Uses Pings to determine the RTT of the connection
    :param ip_address:
    :return: int rtt
    """
    for i in range(0,REPETITIONS-1):
        r = rtt_client(ip_address)
        if r != -1:
            break
    return r

