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
:mod:`update_gen` --- Local config update tool for a SCIONLab Attachment Point
==============================================================================

This file is located in $SCIONPATH/python/topology/
"""
# Stdlib
import copy
import json
import os
import requests
from shutil import rmtree
from subprocess import call
import yaml


# SCION
from lib.defines import (
    GEN_PATH,
    PROJECT_ROOT,
)
from lib.packet.scion_addr import ISD_AS
from topology.generator import (
    INITIAL_CERT_VERSION,
    INITIAL_TRC_VERSION,
    TopoID,
)

# SCION-WEB
from ad_manager.util.local_config_util import (
    ASCredential,
    generate_prom_config,
    gererate_sciond_config,
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

"""
The following configurations need to be customized to the AP
"""
#: Default SCION-coord server account ID
ACC_ID = ""
#: Default SCION-coord server account PW
ACC_PW = ""
#: Client configuration directory for openvpn
OPENVPN_CCD = os.path.expanduser("~/openvpn_ccd")
#: Different IP addresses
INTL_ADDR = ""
INTF_ADDR = ""
VPN_ADDR = "10.0.8.1"
VPN_NETMASK = "255.255.255.0"
#: Port of the AP
EXTERNAL_PORT = 50000
#: URL of SCION Coordination Service
SCION_COORD_URL = "https://coord.scionproto.net/"

#: Default key set for new SCIONLabVM join requests
REMOVE = 'Remove'
UPDATE = 'Update'
CREATE = 'Create'
#: Default key set for acknowlegment messages
REMOVED = 'Removed'
UPDATED = 'Updated'
CREATED = 'Created'
#: Default SCION Prometheus port offset
PROM_PORT_OFFSET = 100

# Template for new_as_dict
# new_as_dict = {
#     '1-13': {
#         'Create': [
#             {
#                 'ASID': '1-4001',
#                 'IsVPN': true,
#                 'VMIP': '10.8.0.42',
#                 'RemoteIAPort': 50050,
#                 'UserEmail': 'jonghoonkwon@gmail.com',
#                 'RemoteBR': 'br1-13-2'
#             },
#         ],
#         'Update': [],
#         'Remove': []
#     }
# }


def update_local_gen():
    """
    The main function that updates the topology configurations
    """
    is_modified = False
    updated_vmip = {}
    original_topo = []
    isdas_list = _get_my_asid()
    new_as_dict, err = request_server(isdas_list)
    if err:
        print("[ERROR] Failed to connect to SCION-COORD server: \n%s" % err)
        exit(1)

    for my_asid, new_reqs in new_as_dict.items():
        if my_asid not in isdas_list:
            continue
        as_obj, tp = load_topology(my_asid)
        original_topo.append((my_asid, as_obj, tp))
        new_tp = copy.deepcopy(tp)
        updated_vmip[my_asid] = {}
        updated_vmip[my_asid][CREATED] = []
        updated_vmip[my_asid][UPDATED] = []
        updated_vmip[my_asid][REMOVED] = []
        for req_type, vmip_list in (
            (REMOVE, updated_vmip[my_asid][REMOVED]),
            (UPDATE, updated_vmip[my_asid][UPDATED]),
            (CREATE, updated_vmip[my_asid][CREATED]),
        ):
            if new_reqs[req_type]:
                new_tp = update_topology(my_asid, new_reqs, req_type, vmip_list, new_tp)
                is_modified = True
    if is_modified:
        generate_local_gen(my_asid, as_obj, new_tp)
        print("[INFO] Configuration changed. Acknowlege to the SCION-COORD server")
        _, err = request_server(isdas_list, ack_json=updated_vmip)
        if err:
            print("[ERROR] Failed to connect to SCION-COORD server: \n%s" % err)
            for my_asid, as_obj, old_tp in original_topo:
                print("[INFO] Retrieving the original topology congiguration: %s" % my_asid)
                generate_local_gen(my_asid, as_obj, old_tp)
            exit(1)
        print("[INFO] Restarting SCION")
        _restart_scion()
    else:
        print("[INFO] Nothing changed. Not restarting SCION")


def _get_my_asid():
    """
    Load ISDAS information running on the local machine
    :returns: a list of ISD-AS (e.g., ['1-11', '1-12'])
    """
    path = os.path.normpath('.')
    isdas_list = []
    for root, dirs, files in os.walk(GEN_PATH):
        depth = root[len(path) + len(os.path.sep):].count(os.path.sep)
        if depth == 2 and 'gen/ISD' in root and 'AS' in root:
            token = root.split('/')
            isdas = '%s-%s' % (token[1][3:], token[2][2:])
            isdas_list.append(isdas)
    if not isdas_list:
        print("[DEBUG] No ASes running on the machine.")
    else:
        print("[DEBUG] ASes running on the machine: \n%s" % isdas_list)
    return isdas_list


def request_server(isdas_list, ack_json=None):
    """
    Communicate with SCION coordination server over HTTPS.
    Send get and post requests in order to get newly joined SCIONLabVM's
    information and report the update status respectively.
    :param list isdas_list: given ISD and AS numbers
    :param dict ack_json: updated SCIONLabVM's IP addresses
    :returns dict resp_dic:
    """
    GET_REQ = SCION_COORD_URL + "api/as/getSCIONLabVMASes"
    POST_REQ = SCION_COORD_URL + "api/as/confirmSCIONLabVMASes"
    QUERY = "scionLabAS="
    if ack_json:
        url = POST_REQ + "/" + ACC_ID + "/" + ACC_PW
        try:
            resp = requests.post(url, json=ack_json)
        except requests.exceptions.ConnectionError as e:
            return None, e
        return None, None
    else:
        url = GET_REQ + "/" + ACC_ID + "/" + ACC_PW + "?" + QUERY
        for my_asid in isdas_list:
            url = url + my_asid
            break  # AT this moment, we only support one AS for a machine
        try:
            resp = requests.get(url)
        except requests.exceptions.ConnectionError as e:
            return None, e
        content = resp.content.decode('utf-8')
        resp_dict = json.loads(content)
        print("[DEBUG] Recieved New SCIONLabVM ASes: \n%s" % resp_dict)
        return resp_dict, None


def load_topology(asid):
    """
    Reload the current topology configuration.
    :param str gen_path: target asid (e.g., '1-11')
    :returns: keys, trc, cert and topology dictionary for the given AS
    """
    ia = ISD_AS(asid)
    as_path = 'ISD%s/AS%s' % (ia[0], ia[1])
    process_path = _get_process_path(os.path.join(GEN_PATH, as_path))
    try:
        with open(os.path.join(PROJECT_ROOT, process_path, 'topology.json')) as topo_file:
            topo_dict = json.load(topo_file)
        with open(os.path.join(process_path, 'keys/as-sig.key')) as sig_file:
            sig_priv_key = sig_file.read()
        with open(os.path.join(process_path, 'keys/as-decrypt.key')) as enc_file:
            enc_priv_key = enc_file.read()
        with open(os.path.join(process_path, 'certs/ISD%s-AS%s-V%s.crt' %
                               (ia[0], ia[1], INITIAL_CERT_VERSION))) as cert_file:
            certificate = cert_file.read()
        with open(os.path.join(process_path, 'certs/ISD%s-V%s.trc' %
                               (ia[0], INITIAL_TRC_VERSION))) as trc_file:
            trc = trc_file.read()
        with open(os.path.join(process_path, 'as.yml')) as conf_file:
            master_as_key = _get_masterkey(conf_file)
    except OSError as e:
        print("[ERROR] Unable to open '%s': \n%s" % (e.filename, e.strerror))
        exit(1)
    as_obj = ASCredential(sig_priv_key, enc_priv_key, certificate, trc, master_as_key)
    return as_obj, topo_dict


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
    print("[ERROR] Unable to load topology.json")
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


def update_topology(my_asid, reqs, req_type, res_list, tp):
    """
    Update the topology by adding, updating and removing BRs as requested.
    :param ISD_AS my_asid: current AS number
    :param dict requests: requested entities to be changed from current topology
    :param str req_type: type of requested changes
    :param list res_list: list that stores results of successfully update
    :returns: the updated topology as dict
    """
    for req in reqs[req_type]:
        user = req['UserEmail']
        as_id = req['ASID']
        vm_ip = req['VMIP']
        is_vpn = req['IsVPN']
        l4port = req['RemoteIAPort']

        if req_type == REMOVE:
            current_br = req['RemoteBR']
            if_id = _get_current_ifid(as_id, vm_ip, l4port, tp['BorderRouters'][current_br])
            if if_id:
                tp = _remove_topology(current_br, is_vpn, tp)
                if is_vpn:
                    _remove_vpn_ip(user)
                res = {'ASID': as_id, 'VMIP': vm_ip, 'RemoteIAPort': l4port, 'RemoteBR': None}
                res_list.append(res)
        elif req_type == UPDATE:
            current_br = req['RemoteBR']
            if_id = _get_current_br(tp['BorderRouters'][current_br])
            if if_id:
                tp = _update_topology(current_br, if_id, as_id, vm_ip, l4port, is_vpn, tp)
                if is_vpn:
                    _configure_vpn_ip(user, vm_ip)
                res = {'ASID': as_id, 'VMIP': vm_ip, 'RemoteIAPort': l4port,
                       'RemoteBR': current_br}
                res_list.append(res)
        else:
            new_br, tp = _create_topology(my_asid, as_id, vm_ip, l4port, is_vpn, tp)
            if is_vpn:
                _configure_vpn_ip(user, vm_ip)
            res = {'ASID': as_id, 'VMIP': vm_ip, 'RemoteIAPort': l4port, 'RemoteBR': new_br}
            res_list.append(res)

    return tp


def _ccd_user(user):
    """
    Location where the vpn ip address is saved for given user
    :param user: user email address
    :return: location
    """
    return os.path.join(OPENVPN_CCD, user)


def _configure_vpn_ip(user, vpn_ip):
    """
    Adds/updates the vpn ip address in the client-configuration directory
    :param user: email of the user
    :param vpn_ip: ip address to assign to this user
    :return: void
    """
    with open(_ccd_user(user), 'w') as vpn_config:
        vpn_config.write("ifconfig-push " + vpn_ip + " " + VPN_NETMASK)
    return


def _remove_vpn_ip(user):
    """
    Removes the vpn ip address in the client-configuration directory
    :param user: email of the user
    :return: void
    """
    try:
      os.remove(_ccd_user(user))
    except OSError:
        pass
    return


def _get_current_ifid(as_id, vm_ip, l4port, br_dict):
    """
    Parsing border router topology and returns if_id corresponding to the given information
    :param str as_id: remote AS ID
    :param str vm_ip: the IP address of the remote AS
    :param int l4port: the port number of the host AS
    :param dict br_dict: the border router topology
    :returns: the interface id as int
    """
    for if_id, intf_dict in br_dict['Interfaces'].items():
        if br_dict['Interfaces'][if_id]['ISD_AS'] != as_id:
            continue
        elif br_dict['Interfaces'][if_id]['Remote']['Addr'] != vm_ip:
            continue
        elif br_dict['Interfaces'][if_id]['Public']['L4Port'] != l4port:
            continue
        else:
            return if_id
    return None


def _get_current_br(br_dict):
    if len(br_dict['Interfaces'].keys()) is 1:
        for if_id, intf_dict in br_dict['Interfaces'].items():
            return if_id
    return None


def _remove_topology(br, is_vpn, tp):
    """
    Remove a border router information from the topology
    :param str br: border router ID
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: target AS topology
    :returns: updated topology as dict
    """
    del tp['BorderRouters'][br]
    return tp


def _update_topology(br, if_id, as_id, vm_ip, l4port, is_vpn, tp):
    """
    Update a border router information from the topology
    :param str br: border router ID
    :param int if_id: interface id
    :param str as_id: remote AS ID
    :param str vm_ip: the IP address of the remote AS
    :param int l4port: the port number of the host AS
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: target AS topology
    :returns: updated topology as dict
    """
    tp['BorderRouters'][br]['Interfaces'][if_id]['ISD_AS'] = as_id
    tp['BorderRouters'][br]['Interfaces'][if_id]['Remote']['Addr'] = vm_ip
    tp['BorderRouters'][br]['Interfaces'][if_id]['Public']['Addr'] = VPN_ADDR if is_vpn else INTF_ADDR
    tp['BorderRouters'][br]['Interfaces'][if_id]['Public']['L4Port'] = l4port
    return tp


def _create_topology(my_asid, as_id, vm_ip, l4port, is_vpn, tp):
    """
    Create and add a border router information to the topology
    :param str as_id: remote AS ID
    :param str vm_ip: the IP address of the remote AS
    :param int l4port: the port number of the host AS
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: target AS topology
    :returns: new border router id and updated topology
    """
    br_id, br_port, if_id, intl_addr, intf_addr, mtu, bandwidth = _get_new_br_obj(
        my_asid, is_vpn, tp)

    tp['BorderRouters'][br_id] = {
        'InternalAddrs': [
            {
                'Public': [
                    {
                        'Addr': intl_addr,
                        'L4Port': br_port
                    }
                ]
            }
        ],
        'Interfaces': {
            if_id: {
                "Overlay": "UDP/IPv4",
                "Bandwidth": bandwidth,
                "Remote": {
                    "L4Port": EXTERNAL_PORT,
                    "Addr": vm_ip
                },
                "MTU": mtu,
                "LinkType": "CHILD",
                "Public": {
                    "L4Port": l4port,
                    "Addr": intf_addr
                },
                "InternalAddrIdx": 0,
                "ISD_AS": as_id
            }
        }
    }
    return br_id, tp


def _get_new_br_obj(my_asid, is_vpn, tp):
    """
    Initiating border router objects to create new border router entity
    :param ISD_AS my_asid: current AS number
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: current AS topology
    :returns: new border router id, border router port, interface id,
              internal address, interface address, mtu and bandwidth
    """
    br_id = []
    br_port = []
    if_id = []

    for br_name, br in tp['BorderRouters'].items():
        br_id.append(int(br_name.split('-')[2]))
        br_port.append(br['InternalAddrs'][0]['Public'][0]['L4Port'])
        for ifid, intf in br['Interfaces'].items():
            if_id.append(int(ifid))

    new_br_id = 'br%s-%s' % (my_asid, _get_lowest_empty_id(br_id))
    new_br_port = _get_lowest_empty_id(br_port)
    new_if_id = str(_get_lowest_empty_id(if_id))

    base_br = 'br%s-%s' % (my_asid, max(br_id))
    base_ifid = list(tp['BorderRouters'][base_br]['Interfaces'].keys())[0]
    intl_addr = INTL_ADDR
    intf_addr = VPN_ADDR if is_vpn else INTF_ADDR
    mtu = tp['BorderRouters'][base_br]['Interfaces'][base_ifid]['MTU']
    bandwidth = tp['BorderRouters'][base_br]['Interfaces'][base_ifid]['Bandwidth']

    return new_br_id, new_br_port, new_if_id, intl_addr, intf_addr, mtu, bandwidth


def _get_lowest_empty_id(id_list):
    for i in range(min(id_list), max(id_list)):
        if i not in id_list:
            return i
    return max(id_list) + 1


def generate_local_gen(my_asid, as_obj, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under gen
    :param str my_asid: ISD-AS as a string
    :param obj as_obj: An object that stores crypto information for AS
    :param dict tp: the topology parameter file as a dict of dicts
    """
    ia = TopoID(my_asid)
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
    # We don't need to create zk configration for existing ASes
    # generate_zk_config(tp, ia, GEN_PATH, simple_conf_mode=False)
    gererate_sciond_config(ia, as_obj, tp)
    generate_prom_config(ia, tp)


def _restart_scion():
    scion_command = os.path.join(PROJECT_ROOT, "scion.sh")
    supervisord_command = os.path.expanduser("~/.local/bin/supervisorctl")

    call([scion_command, "stop"])
    call([supervisord_command, "-c", "supervisor/supervisord.conf", "shutdown"])
    call([scion_command, "run"])


def main():
    update_local_gen()

if __name__ == '__main__':
    main()

