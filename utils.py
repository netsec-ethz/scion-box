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
:mod:`utils.py` --- Library of calls used by both init and heartbeat
==============================================================================
Contains Definitions used throughout the scripts
This file is located in $SCIONPATH/
"""
# Stdlib
import os
import shutil
import subprocess
import tarfile
import json
import netifaces as ni
from shutil import rmtree
import logging
from itertools import groupby, count
import yaml

# SCION
from lib.packet.scion_addr import ISD_AS

# SCION-WEB
from ad_manager.util.local_config_util import (
    ASCredential,
    write_endhost_config,
    get_elem_dir,
    prep_supervisord_conf,
    write_as_conf_and_path_policy,
    write_certs_trc_keys,
    write_dispatcher_config,
    write_supervisord_config,
    write_topology_file,
    write_zlog_file,
    TYPES_TO_EXECUTABLES,
    TYPES_TO_KEYS,
)

#SCION-BOX
from defines import(
    INITIAL_CERT_VERSION,
    INITIAL_TRC_VERSION,
    SCION_PATH,
    GEN_PATH,
    CONN_TESTER_CLIENT,
    CONN_TESTER_INPUT_PATH,
    CONN_TESTER_OUTPUT_PATH,
    FORMAT,
    BOX_LOGFILE,
    PARENT,
    CHILD,
    CORE,
    CONN_TESTER_PORTS,
    CONN_TESTER_START_PORT,
    CONN_TESTER_HOST,
    INTERFACE
)


logging.basicConfig(filename=BOX_LOGFILE,level=logging.DEBUG, format=FORMAT)


def test_connections():
    """
    Calls the connection-tester client with the specified json config
    :return: Dictionary of the Connection results
    """
    config_dict = {}
    config_dict["tests"] = []
    # set up connection tester config file
    for i in range(0, CONN_TESTER_PORTS):
        new_test = {"name": "udp_in",
                    "params":{ "host":CONN_TESTER_HOST,
                               "timeout":1,
                               "my_port":str(CONN_TESTER_START_PORT+i)
                            }
                    }
        config_dict["tests"].append(new_test)
    with open(CONN_TESTER_INPUT_PATH, 'w') as outfile:
        json.dump(config_dict, outfile)
    connection_list = []
    subprocess.call([CONN_TESTER_CLIENT, "--config", CONN_TESTER_INPUT_PATH, "--output_result",
          "--output_path=" + CONN_TESTER_OUTPUT_PATH])
    with open(CONN_TESTER_OUTPUT_PATH) as data_file:
        data = json.load(data_file)
    tests = data['tests']
    for test in tests:
        name = test['name']
        result = test['results']
        if name == "http_test":
            print ("Connection result http: ", result)
        elif name == "udp_in":
            port = test['params']['my_port']
            connection = {'name': name, 'port': int(port), 'result': result[0]["success"]}
            connection_list.append(connection)
    return connection_list


def connection_results_2_free_ports(results):
    """
    Calculates the number of open UDP ports starting from 50000
    :param connection_list: list of connection results
    :return: int: number of free Ports
    """
    port_list = []
    for result in results:
        if result['result']:
            port_list.append(result['port'])
    if len(port_list) == 0:
        # No free Ports
        return 50000, 0
    port_list.sort()
    # Find the longest consecutive subsequence
    port_list = port_list + [-1]  # add guard element
    start_index = 0
    seq_length = 0
    # map of longest subsequence length starting at key index
    index = 0
    subsequences = [[]]
    previous = port_list[0]
    index += 1
    while index < len(port_list):
        if port_list[index] == previous + 1:
            subsequences[-1].append(port_list[index])
        else:
            subsequences.append([port_list[index]])
        previous = port_list[index]
        index += 1
    longest_sequence = max(subsequences, key=len)
    start = longest_sequence[0]
    seq_length = len(longest_sequence)
    return start, seq_length


def save_credentials(response):
    """
    Saves the Credentials to Credentials.conf in the Gen folder path
    :param response: json received from the SCION-COORD
    """
    with open('box_credentials.conf', 'w') as outfile:
        json.dump(response, outfile)


def get_credentials():
    """
    Loads the Credentials file
    :return Dictionary of the credentials
    """
    with open('box_credentials.conf') as cred_file:
        credentials = json.load(cred_file)
    return credentials


def parse_response(resp):
    """
    Extracts the received file and copies the gen folder to the SCIONPATH
    """
    userMail = get_credentials()["UserMail"]
    try:
        shutil.rmtree(userMail)
    except OSError:
        pass
    tar = resp.content
    with open(userMail +".tar.gz", "wb") as file1:
        file1.write(tar)
    tar = tarfile.open(userMail +".tar.gz")
    tar.extractall()
    tar.close()
    try:
        shutil.rmtree(GEN_PATH)
    except OSError as e:
        logging.error("Error removing gen folder %s", e)
    shutil.copytree(userMail + "/gen", GEN_PATH)
    shutil.copy(userMail + "/box_credentials.conf", "box_credentials.conf")


def generate_local_gen(my_asid, as_obj, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under gen
    :param str my_asid: ISD-AS as a string
    :param obj as_obj: An object that stores crypto information for AS
    :param dict tp: the topology parameter file as a dict of dicts
    """
    ia = my_asid
    write_dispatcher_config(GEN_PATH)
    as_path = get_elem_dir(GEN_PATH, ia, "")
    rmtree(as_path, True)
    for service_type, type_key in TYPES_TO_KEYS.items():
        executable_name = TYPES_TO_EXECUTABLES[service_type]
        instances = tp[type_key].keys()
        for instance_name in instances:
            config = prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                           service_type, instance_name, ia)
            instance_path = get_elem_dir(GEN_PATH, ia, instance_name)
            write_certs_trc_keys(ia, as_obj, instance_path)
            write_as_conf_and_path_policy(ia, as_obj, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    write_endhost_config(tp, ia, as_obj, GEN_PATH)
    generate_sciond_config(tp, ia, GEN_PATH, as_obj)
    # We don't need to create zk configration for existing ASes
    # generate_zk_config(tp, ia, GEN_PATH, simple_conf_mode=False)

def generate_sciond_config(tp, ia, local_gen_path, as_obj):
    executable_name = "sciond"
    instance_name = "sd%s" % str(ia)
    service_type = "sciond"
    processes = []
    for svc_type in ["BorderRouters", "BeaconService", "CertificateService",
                     "HiddenPathService", "PathService"]:
        if svc_type not in tp:
            continue
        for elem_id, elem in tp[svc_type].items():
            processes.append(elem_id)
    processes.append(instance_name)
    config = prep_supervisord_conf(None, executable_name, service_type, instance_name, ia)
    config['group:'  "as%s" % str(ia)] = {'programs': ",".join(processes)}
    sciond_conf_path = get_elem_dir(local_gen_path, ia, "")
    write_supervisord_config(config, sciond_conf_path)


def _get_my_asid():
    """
    Load ISDAS information running on the local machine
    :returns: a list of ISD_AS objects
    """
    isdas_list = []
    for directory in os.listdir(GEN_PATH):
        if 'ISD' in directory:
            for folder in os.listdir(os.path.join(GEN_PATH, directory)):
                if 'AS' in folder:
                    isdas = ISD_AS.from_values(int(directory[3:]), int(folder[2:]))
                    isdas_list.append(isdas)
    return isdas_list


def _get_process_path(path):
    """
    Searching one of the existing process directories from the topology directory
    and returns it as a process path.
    :param str gen_path: path for sub directory of target as (e.g., 'gen/ISD1/AS11')
    :returns: a process path (e.g., 'gen/ISD1/AS11/br1-11-1')
    """
    for root, dirs, files in os.walk(path):
        if 'topology.json' in files:
            return root
    logging.error("Cannot find topology file")
    exit(1)


def _get_masterkey(conf_file):
    """
    Parse the configruation file and extract the Master key
    :param filestream conf_file: configuration file as a filestream
    :returns: Master key as a string
    """
    try:
        as_conf = yaml.load(conf_file)
        key = as_conf['MasterASKey']
        return key
    except:
        print("[ERROR] Unable to load the AS master key")
    exit(1)

def _get_current_br(br_dict):
    if len(br_dict['Interfaces'].keys()) is 1:
        for if_id, intf_dict in br_dict['Interfaces'].items():
            return if_id
    return None


def load_topology(ia):
    """
    Reload the current topology configuration.
    :returns: as topology as json
    """
    isd_number = str(ia._isd)
    as_number = str(ia._as)
    isd_directory = "ISD" + isd_number
    as_directory = "AS" + as_number
    process_path = _get_process_path(GEN_PATH + "/" + isd_directory + "/" + as_directory)
    try:
        with open(process_path + "/" + 'topology.json') as topo_file:
            topo_dict = json.load(topo_file)
        with open(process_path + "/" + 'keys/as-sig.key') as sig_file:
            sig_priv_key = sig_file.read()
        with open(process_path + "/" +  'keys/as-decrypt.key') as enc_file:
            enc_priv_key = enc_file.read()
        with open(process_path + "/" + 'certs/ISD%s-AS%s-V%s.crt' %
                               (isd_number, str(ia._as), INITIAL_CERT_VERSION)) as cert_file:
            certificate = cert_file.read()
        with open(process_path + "/" + 'certs/ISD%s-V%s.trc' %
                               (isd_number, INITIAL_TRC_VERSION)) as trc_file:
            trc = trc_file.read()
        with open(process_path + "/" + 'as.yml') as conf_file:
            master_as_key = _get_masterkey(conf_file)
    except OSError as e:
        logging.error("to open '%s': \n%s" % (e.filename, e.strerror))
        exit(1)
    as_obj = ASCredential(sig_priv_key, enc_priv_key, certificate, trc, master_as_key)
    return as_obj, topo_dict


def _remove_br(new_neighbor, topo):
    """
    Removes a border router.
    :param new_neighbor: dictionary of removed neighbor
    :param topo: current topology
    :return: updated topology
    """
    br, br_id = _get_br_id(new_neighbor, topo)
    del topo['BorderRouters'][br]
    return topo


def _update_br(new_neighbor, topo):
    """
    Updates a border router.
    :param new_neighbor: dictionary of the modified neighbor
    :param topo: current topology
    :return: updated topology
    """
    br, br_id = _get_br_id(new_neighbor, topo)
    if br_id != 0:
        topo['BorderRouters'][br]['Interfaces'][br_id]['Remote']['Addr'] = new_neighbor['NeighborIP']
        topo['BorderRouters'][br]['Interfaces'][br_id]['Remote']['L4Port'] = new_neighbor['RemotePort']
    else:
        return _add_br(new_neighbor, topo)
    return topo


def _get_br_id(neighbor, topo):
    """
    Returns the br-id of the br connected to the ia
    :param neighbors: dictionary of a neighbor
    :param topo: current topology
    :return: br-id string, id of the br int
    """
    brs = topo["BorderRouters"]
    neighbor_ia = "%s-%s" % (str(neighbor["NeighborISD"]), str(neighbor["NeighborAS"]))
    for br in brs:
        for item in brs[br]["Interfaces"]:
            if brs[br]["Interfaces"][item]["ISD_AS"] == neighbor_ia:
                return br, item
    return "", 0


def _add_br(new_neighbor, topo):
    """
    Adds a new border router to the topology
    :param new_neighbor: dictionary of new neighbor
    :param topo: current topology
    :return: updated topology
    """
    br_id, br_port, if_id, external_port, neighbor_addr, ext_addr, linktype, internal_port, int_addr, ia = _get_new_br_obj(
        new_neighbor, topo)
    topo['BorderRouters'][br_id] = {
        'InternalAddrs': [
            {
                'Public': [
                    {
                        'Addr': int_addr,
                        'L4Port': br_port
                    }
                ]
            }
        ],
        'Interfaces': {
            if_id: {
                "Overlay": "UDP/IPv4",
                "Bandwidth": 1000,
                "Remote": {
                    "L4Port": external_port,
                    "Addr": neighbor_addr
                },
                "MTU": 1472,
                "LinkType": linktype,
                "Public": {
                    "L4Port": internal_port,
                    "Addr": ext_addr
                },
                "Bind": {
                    "L4Port": internal_port,
                    "Addr": int_addr
                },
                "InternalAddrIdx": 0,
                "ISD_AS": ia
            }
        }
    }
    return topo


def _get_new_br_obj(new_neighbor, topo):
    """
    Initiating border router objects to create new border router entity
    :param ISD_AS my_asid: current AS number
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: current AS topology
    :returns: new border router id, border router port, interface id,
              internal address, interface address, mtu and bandwidth
    """
    br_id = []
    if_id = []
    br_n = ""
    br_port = []

    for br_name, br in topo['BorderRouters'].items():
        br_id.append(int(br_name.split('-')[2]))
        br_n = br_name.split('-')[0] + "-" + br_name.split('-')[1]
        br_port.append(br['InternalAddrs'][0]['Public'][0]['L4Port'])
        for ifid, intf in br['Interfaces'].items():
            if_id.append(int(ifid))

    new_br_id = '%s-%s' % (br_n,new_neighbor["BRID"])
    new_if_id = new_neighbor["BRID"]

    external_port = new_neighbor["RemotePort"]
    neighbor_addr = new_neighbor["NeighborIP"]
    ext_addr = get_credentials()["IP"]
    if new_neighbor["Linktype"] == CHILD:
        linktype = "CHILD"
    elif new_neighbor["Linktype"] == PARENT:
        linktype = "PARENT"
    else:
        linktype = "CORE"
    internal_port = new_neighbor["LocalPort"]
    int_addr = ni.ifaddresses(INTERFACE)[ni.AF_INET][0]['addr']
    ia = ISD_AS.from_values(new_neighbor["NeighborISD"], new_neighbor["NeighborAS"])
    ia = ia.__str__()

    new_br_port = _get_lowest_empty_id(br_port)

    return new_br_id, new_br_port, new_if_id, external_port, neighbor_addr, ext_addr, linktype, internal_port, int_addr, ia


def _get_lowest_empty_id(id_list):
    for i in range(min(id_list), max(id_list)):
        if i not in id_list:
            return i
    return max(id_list) + 1


def assemble_current_br_list(ia):
    """
    Assemble a list of the current border Routers
    :param ia: ISD-AS running on this machine
    :return: list of current border Routers
    """
    _, topo = load_topology(ia)
    br_list = []
    brs = topo["BorderRouters"]
    for br_id in brs:
        iid = list(brs[br_id]["Interfaces"])[0]
        br = brs[br_id]["Interfaces"][iid]
        dict = {'NeighborIA': br["ISD_AS"], 'NeighborIP': br["Remote"]["Addr"], "RemotePort": br["Remote"]["L4Port"]}
        br_list.append(dict)
    return br_list


def start_scion():
    """
    Starts scion using ./scion.sh run
    """
    scion_command = os.path.join(SCION_PATH, "scion.sh")
    p = subprocess.Popen([scion_command, "run"], cwd=SCION_PATH)
    p.wait()

def restart_scion():
    """
    Restarts scion
    """
    scion_command = os.path.join(SCION_PATH, "scion.sh")
    supervisord_command = os.path.expanduser("~/.local/bin/supervisorctl")

    p = subprocess.Popen([scion_command, "stop"], cwd=SCION_PATH)
    p.wait()

    supervisor_path = os.path.join(SCION_PATH, "supervisor/supervisord.conf")
    p = subprocess.Popen([supervisord_command, "-c", supervisor_path, "shutdown"], cwd=SCION_PATH)
    p.wait()

    p = subprocess.Popen([scion_command, "run"], cwd=SCION_PATH)
    p.wait()
