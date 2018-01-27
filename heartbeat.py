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
:mod:`heartbeat` --- Heartbeat function to keep in touch with the SCION-coord
==============================================================================

This file is located in $SCIONPATH/python/topology/
"""
# Stdlib
import json
import requests
import netifaces as ni
import logging
import time

# SCION
from lib.packet.scion_addr import ISD_AS

# SCION-Box
import utils
from defines import(
    SCION_COORD_URL,
    CREATE,
    UPDATE,
    REMOVE,
    BOX_LOGFILE,
    FORMAT,
    INTERFACE,
    PARENT,
    CHILD,
    CORE
)


logging.basicConfig(filename=BOX_LOGFILE,level=logging.DEBUG, format=FORMAT)


def heartbeat():
    """
    The main function that updates the topology configurations
    """
    is_modified = False
    ia_list = utils._get_my_asid()
    resp, err = request_server(ia_list)
    if err:
        logging.error("Failed to connect to SCION-COORD server: \n%s" % err)
        exit(1)
    elif resp.headers['content-type'] == 'application/json; charset=utf-8':
        resp_dict = json.loads(resp.content.decode('utf8').replace("'", '"'))
        ia_list = resp_dict["IAList"]
        new_br_list = []
        for ia in ia_list:
            connection_dict = ia["Connections"]
            _isd = ia["ISD"]
            _as = ia["AS"]
            ia = ISD_AS.from_values(_isd, _as)
            as_obj, original_topo = utils.load_topology(ia)
            topo = original_topo
            logging.info("Received answer from Heartbeat function : \n%s" % resp_dict)
            # check for new neighbors
            for connection in connection_dict:
                if connection["Status"] == CREATE:
                    is_modified = True
                    topo = utils._add_br(connection, topo)
                    new_br_list.append(utils._get_br_id(connection,topo)[0])
                elif connection["Status"] == UPDATE:
                    is_modified = True
                    topo = utils._update_br(connection, topo)
                elif connection["Status"] == REMOVE:
                    is_modified = True
                    topo = utils._remove_br(connection, topo)

        if not is_modified:
            # no change
            logging.info("Nothing changed not Restarting SCION")
        else:
            utils.generate_local_gen(ia, as_obj, topo)
            logging.info("[INFO] Restarting SCION")
            utils.restart_scion()
    # In case we receive the gen folder from the coordinator
    elif resp.headers['content-type'] == 'application/gzip':
        logging.info("[INFO] Received gen folder ")
        utils.parse_response(resp)
        logging.info("[INFO] Starting SCION !")
        utils.restart_scion()
    else:
        # Received something else
        # TODO UPDATE BOX ?
        pass


def request_server(ia_list):
    """
    Communicate with SCION coordination server over HTTPS.
    Call the Heartbeat API
    Send Post Request to the SCION coord,
    receive the list of current neighbor
    :returns dict current_neighbors:
    """
    credentials = utils.get_credentials()
    POST_REQ = SCION_COORD_URL + "api/as/heartbeat/" + credentials["ID"] + "/" + credentials["SECRET"]
    # TODO send some status info to the SCION coord
    IAList = []
    for ia in ia_list:
        list = utils.assemble_current_br_list(ia)
        IA = {'ISD': ia._isd, 'AS': ia._as, 'Connections': list}
        IAList.append(IA)
    ip_address = ni.ifaddresses(INTERFACE)[ni.AF_INET][0]['addr']
    # Send the list of current connections aswell as, userMail, IA of the scionLabAS and the ip address.
    HeartBeatQuery = {'IAList': IAList, 'UserMail' : credentials["UserMail"], 'IP': ip_address, 'Time': time.time()}
    logging.info("Calling HB API at: %s, with json: %s", POST_REQ, HeartBeatQuery)
    try:
        resp = requests.post(POST_REQ, json=HeartBeatQuery, timeout=10)
    except requests.exceptions.RequestException as e:
        return None, e
    if resp.status_code == 200:
        return resp, None
    else:
        logging.error("[ERROR] Wrong Status Code ! %s", resp.status_code)
        exit(1)


def main():
    heartbeat()


if __name__ == '__main__':
    main()

