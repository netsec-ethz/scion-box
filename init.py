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
:mod:`init_simple.py` --- Initialization script to get the gen folder from the SCION-coord
==============================================================================

This file is located in $PROJECT_ROOT/Scion-box
"""
# Stdlib
import requests
import netifaces as ni
import logging
import logging.config
import json


# SCION-Box
from link_test import test_links
import utils
from heartbeat import heartbeat
from defines import(
    SCION_COORD_URL,
    INIT_URL,
    CONNECT_URL,
    BOX_LOGFILE,
    FORMAT,
    INTERFACE
)


logging.basicConfig(filename=BOX_LOGFILE,level=logging.DEBUG, format=FORMAT)

def init_box():
    """
    Calls the init_box API from the SCION-coord.
    Receive the gen folder and start SCION
    """
    # Find MAC and IP address
    ip_address = ni.ifaddresses(INTERFACE)[ni.AF_INET][0]['addr']
    mac_address = ni.ifaddresses(INTERFACE)[ni.AF_LINK][0]['addr']
    conn_results = utils.test_connections()
    logging.info("Connection test results: %s \n", str(conn_results))
    start_port, free_ports = utils.connection_results_2_free_ports(conn_results)
    resp, err = call_init(mac_address, ip_address, start_port, free_ports)
    if err:
        logging.error("Failed to connect to SCION-COORD server: \n %s \n",err)
        exit(1)
    elif resp.status_code == 200:
        if resp.headers['content-type'] == 'application/json; charset=utf-8':
            # We have received the list of potential neighbors
            dict = json.loads(resp.content.decode('utf8').replace("'", '"'))
            utils.save_credentials(dict)
            logging.info("Received list of potential neighbors and credentials from SCION-COORD: %s ", str(dict))
            if not dict["PotentialNeighbors"]:
               logging.info("no potential Neighbors !")
               exit(1)
            connection_results = test_links(dict["PotentialNeighbors"])
            dict["PotentialNeighbors"] = connection_results
            connect_box(dict)
        elif resp.headers['content-type'] == 'application/gzip':
            logging.info("Received gen folder ")
            utils.parse_response(resp)
            logging.info("Starting SCION !")
            utils.start_scion()
        else:
            # Received something else
            # TODO UPDATE ?
            pass
    else:
        logging.error("[ERROR] Wrong status code %s", resp.status_code)
        exit(1)


def connect_box(dictionary):
    """
    Calls the connect_box API, extracts gen folder
    and starts SCION
    :param dictionary: Dictionary with the connection results + credentials
    """
    resp, err = call_connect(dictionary)
    if err:
        logging.error("Failed to connect to SCION-COORD server: %s" % err)
        exit(1)
    elif resp.headers['content-type'] == 'application/gzip':
        logging.info("Received gen folder ")
        utils.parse_response(resp)
        logging.info("Starting SCION !")
        utils.start_scion()
        exit(0)
    else:
        logging.error("Did not receive gen folder %s", resp.headers['content-type'])
        exit(1)


def call_init(mac_address, ip_address, start_port, free_ports):
    """
    Calls the init_box API
    :param String: mac_address of the SCIONBox
    :param String: ip_address of the eth0 interface
    :param List of dictionaries with connection test results
    :returns Response from the server
    """
    url = INIT_URL
    init_dict = {'IPAddress': ip_address, 'MacAddress': mac_address, 'OpenPorts': free_ports, 'StartPort': start_port}
    logging.info("Calling coordinator at url: %s, with dict: %s", url, str(init_dict))
    try:
        resp = requests.post(url, json=init_dict, timeout=10)
    except requests.exceptions.RequestException as e:
        return None, e
    return resp, None


def call_connect(dictionary):
    """
    Calls the connect_box API
    :param dictionary: List with dictionariers containing the measurement results
    :returns Response from the server
    """
    connect_query = {'Neighbors' : dictionary["PotentialNeighbors"], 'IP' : dictionary["IP"], 'UserMail': dictionary["UserMail"]}
    POST_REQ = CONNECT_URL + dictionary["ID"] + "/" + dictionary["SECRET"]
    url = POST_REQ
    logging.info("Calling coordinator at url: %s, with dict: %s", POST_REQ, str(connect_query))
    try:
        resp = requests.post(url, json=connect_query, timeout=10)
    except requests.exceptions.RequestException as e:
        return None, e
    return resp, None


def main():
    init_box()

if __name__ == '__main__':
    main()

