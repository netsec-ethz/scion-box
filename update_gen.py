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
import argparse
from lib.packet.scion_addr import ISD_AS


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

# SCION-Utilities
from local_config_util import (
    ASCredential,
    generate_prom_config,
    generate_sciond_config,
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
#: Client configuration directory for openvpn
OPENVPN_CCD = os.path.expanduser("~/openvpn_ccd")
#: Different IP addresses
VPN_ADDR = "10.0.8.1"
VPN_NETMASK = "255.255.255.0"

#: Default MTU and bandwidth
MTU = 1472
BANDWIDTH = 1000
#: First internal port assigned to border routers
BR_INTERNAL_START_PORT = 31050

#: Default key set for new SCIONLabAS join requests
REMOVE = 'Remove'
UPDATE = 'Update'
CREATE = 'Create'
#: Default key set for acknowlegment messages
REMOVED = 'Removed'
UPDATED = 'Updated'
CREATED = 'Created'
effects = {
    REMOVE: REMOVED,
    UPDATE: UPDATED,
    CREATE: CREATED,
}
#: API calls at the coordinator
GET_REQ = "api/as/getUpdatesForAP"
GETFULL_REQ = "api/as/getConnectionsForAP"
POST_REQ = "api/as/confirmUpdatesFromAP"
ONLY_AS_TO_UPDATE = None


def dict_equal(dict1, dict2):
    keys1 = dict1.keys()
    keys2 = dict2.keys()
    if keys1 ^ keys2:
        return False
    # same keys; what about the values?
    for k, v1 in dict1.items():
        v2 = dict2[k]
        if isinstance(v1, dict) and isinstance(v2, dict) and not dict_equal(v1, v2):
            return False
        elif v1 != v2:
            return False
    return True


# Template for new_as_dict
# new_as_dict = {
#     '1-13': {
#         'Create': [
#             {
#                 'ASID': '1-4001',
#                 'IsVPN': True,
#                 'VPNUserID': 'user@example.com_4001',
#                 'IP': '10.8.0.42',
#                 'UserPort': 50000,
#                 'APPort': 50050,
#                 'APBRID': 2
#             },
#         ],
#         'Update': [],
#         'Remove': []
#     }
# }
def fullsync_local_gen():
    """
    Replaces the topology with the one indicated by the Coordinator
    """
    topo_has_changed = False
    something_to_acknowledge = {}
    isdas_list = _get_my_asid()
    fullsynced = request_server_fullsync(isdas_list)
    for my_asid, status in fullsynced.items():
        if my_asid not in isdas_list:
            continue
        connections = status['connections']

        as_obj, tp = load_topology(my_asid)
        new_tp = copy.deepcopy(tp)
        brs = new_tp['BorderRouters']
        # remove all child border routers to user ASes in this AP
        for brname in list(brs.keys()): # list() because we del()
            br = brs[brname]
            for ifnum in list(br['Interfaces'].keys()):
                iface = br['Interfaces'][ifnum]
                ia = ISD_AS(iface['ISD_AS'])
                asid = ia[1]
                # if the link is to a child and that child is a user AS
                if asid >= 0xffaa00010000 and iface['LinkTo'] == 'CHILD':
                    del br['Interfaces'][ifnum]
            if not br['Interfaces']: # no interfaces left -> remove BR
                del brs[brname]
        # add the links from the Coordinator
        for conn in connections:
            user = conn['VPNUserID']
            as_id = conn['ASID']
            as_ip = conn['IP']
            is_vpn = conn['IsVPN']
            ap_port = conn['APPort']
            as_port = conn['UserPort']
            br_id = conn['APBRID']
            br_name = _br_name_from_br_id(br_id, my_asid)
            if_id = str(br_id) # Always use the BR ID as IF ID
            new_tp = _create_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, new_tp)
            if is_vpn:
                _configure_vpn_ip(user, as_ip)
        something_to_acknowledge[my_asid] = status
        topo_has_changed = topo_has_changed or not dict_equal(tp['BorderRouters'], brs)

    if topo_has_changed:
        generate_local_gen(my_asid, as_obj, new_tp)
    if something_to_acknowledge:
        print("[INFO] Configuration received and processed. Acknowledge to the SCION-COORD server")
        try:
            ack_message = something_to_acknowledge
            replay_server_fullsync(isdas_list, ack_message)
        except Exception as ex:
            print("[ERROR] Failed to ACK the fullsync to the Coordinator: \n{}".format(ex))

    if topo_has_changed:
        print("[INFO] Configuration has changed. Restarting SCION")
        _restart_scion()
    else:
        print("[INFO] Nothing changed. Not restarting SCION")


def update_local_gen():
    """
    The main function that updates the topology configurations
    """

    topo_has_changed = False
    something_to_acknowledge = False
    updated_ases = {}
    original_topo = []
    isdas_list = _get_my_asid()
    new_as_dict = request_server(isdas_list)

    for my_asid, new_reqs in new_as_dict.items():
        if my_asid not in isdas_list:
            continue
        updated_ases[my_asid] = {}
        updated_ases[my_asid][CREATED] = []
        updated_ases[my_asid][UPDATED] = []
        updated_ases[my_asid][REMOVED] = []

        as_obj, tp = load_topology(my_asid)
        original_topo.append((my_asid, as_obj, tp))
        new_tp = copy.deepcopy(tp)

        for req_type in (REMOVE, UPDATE, CREATE):
            if new_reqs[req_type]:
                modifiedASes, topo_changed_now = update_topology(my_asid, new_reqs, req_type, new_tp)
                updated_ases[my_asid][effects[req_type]].extend(modifiedASes)
                topo_has_changed = topo_has_changed or topo_changed_now
                something_to_acknowledge = True
    if something_to_acknowledge:
        generate_local_gen(my_asid, as_obj, new_tp)
        print("[INFO] Configuration changed. Acknowledge to the SCION-COORD server")
        try:
            request_server(isdas_list, ack_json=updated_ases)
        except Exception as ex:
            print("[ERROR] Failed to connect to SCION-COORD server: \n%s" % ex)
            for my_asid, as_obj, old_tp in original_topo:
                print("[INFO] Retrieving the original topology configuration: %s" % my_asid)
                generate_local_gen(my_asid, as_obj, old_tp)
            exit(1)
    if topo_has_changed:
        print("[INFO] Restarting SCION")
        _restart_scion()
    else:
        print("[INFO] Nothing changed. Not restarting SCION")


def _get_my_asid():
    """
    Load ISD-AS information running on the local machine
    :returns: a list of ISD-AS (e.g., ['1-11', '1-12'])
    """
    path = os.path.normpath('.')
    isdas_list = []
    for root, _, _ in os.walk(os.path.join(PROJECT_ROOT, GEN_PATH)):
        base_depth = PROJECT_ROOT.count(os.path.sep)
        depth = root[len(path) + len(os.path.sep):].count(os.path.sep)
        if depth == base_depth + 2 and 'gen/ISD' in root and 'AS' in root:
            token = root.split('/')
            isdas = '%s-%s' % (token[-2][3:], token[-1][2:])
            isdas_list.append(isdas)
    if not isdas_list:
        print("[DEBUG] No ASes running on the machine.")
    else:
        print("[DEBUG] ASes running on the machine: \n\t%s" % isdas_list)
    return isdas_list

def send_request_and_get_json(url):
    """
    :returns dict json_response
    """
    resp = requests.get(url)
    content = resp.content.decode('utf-8')
    if resp.status_code == 204:
        return {}
    elif resp.status_code != 200:
        raise Exception("Status code ({}) not 200. Content is: {}".format(resp.status_code, content))
    try:
        resp_dict = json.loads(content)
    except Exception as ex:
        raise Exception("Error while parsing JSON: {} : {}\nContent was: {}".format(type(ex),str(ex), content))
    return resp_dict

def request_server(isdas_list, ack_json=None):
    """
    Communicate with SCION coordination server over HTTPS.
    Send get and post requests in order to get newly joined SCIONLabAS's
    information and report the update status respectively.
    :param list isdas_list: given ISD and AS numbers
    :param dict ack_json: updated SCIONLabAS's IP addresses
    :returns dict resp_dic:
    """
    query = "scionLabAP="
    if ack_json:
        url = SCION_COORD_URL + "/" + POST_REQ + "/" + ACC_ID + "/" + ACC_PW
        while url:
            resp = requests.post(url, json=ack_json, allow_redirects=False)
            url = resp.next.url if resp.is_redirect and resp.next else None
        return None
    else:
        url = SCION_COORD_URL + "/" + GET_REQ + "/" + ACC_ID + "/" + ACC_PW + "?" + query
        # AT this moment, we only support one AS for a machine
        my_asid = ONLY_AS_TO_UPDATE if ONLY_AS_TO_UPDATE else isdas_list[0]
        url += my_asid
        return send_request_and_get_json(url)

def request_server_fullsync(isdas_list):
    url = SCION_COORD_URL + "/" + GETFULL_REQ + "/" + ACC_ID + "/" + ACC_PW + "?scionLabAP="
    # AT this moment, we only support one AS for a machine
    my_asid = ONLY_AS_TO_UPDATE if ONLY_AS_TO_UPDATE else isdas_list[0]
    url += my_asid
    return send_request_and_get_json(url)

def replay_server_fullsync(isdas_list, ack_message):
    pass

def load_topology(asid):
    """
    Reload the current topology configuration.
    :param str gen_path: target asid (e.g., '1-11')
    :returns: keys, trc, cert and topology dictionary for the given AS
    """
    ia = ISD_AS(asid)
    as_str = ia.as_file_fmt() if 'as_file_fmt' in dir(ia) else ia[1]
    as_path = 'ISD%s/AS%s' % (ia[0], as_str)
    process_path = _get_process_path(os.path.join(PROJECT_ROOT, GEN_PATH, as_path))
    try:
        with open(os.path.join(process_path, 'topology.json')) as topo_file:
            topo_dict = json.load(topo_file)
        with open(os.path.join(process_path, 'keys/as-sig.seed')) as sig_file:
            sig_priv_key = sig_file.read()
        with open(os.path.join(process_path, 'keys/as-sig.key')) as sig_file:
            sig_priv_key_raw = sig_file.read()
        with open(os.path.join(process_path, 'keys/as-decrypt.key')) as enc_file:
            enc_priv_key = enc_file.read()
        with open(os.path.join(process_path, 'certs/ISD%s-AS%s-V%s.crt' %
                               (ia[0], as_str, INITIAL_CERT_VERSION))) as cert_file:
            certificate = cert_file.read()
        with open(os.path.join(process_path, 'certs/ISD%s-V%s.trc' %
                               (ia[0], INITIAL_TRC_VERSION))) as trc_file:
            trc = trc_file.read()
        with open(os.path.join(process_path, 'as.yml')) as conf_file:
            master_as_key = _get_masterkey(conf_file)
    except OSError as e:
        print("[ERROR] Unable to open '%s': \n%s" % (e.filename, e.strerror))
        exit(1)
    key_dict = {
        'enc_key': enc_priv_key,
        'sig_key': sig_priv_key,
        'sig_key_raw': sig_priv_key_raw,
        'master_as_key': master_as_key,
    }
    as_obj = ASCredential(certificate, trc, key_dict)
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


def update_topology(my_asid, reqs, req_type, tp):
    """
    Update the topology by adding, updating and removing BRs as requested.
    :param ISD_AS my_asid: current AS number
    :param dict reqs: requested entities to be changed from current topology
    :param str req_type: type of requested changes
    :param dict tp: in/out existing topology / updated topology
    :returns: modified user ASes and boolean indicating if topology is now different
    """
    modifiedASes = []
    topo_has_changed = False
    for req in reqs[req_type]:
        success = False
        user = req['VPNUserID']
        as_id = req['ASID']
        as_ip = req['IP']
        is_vpn = req['IsVPN']
        ap_port = req['APPort']
        as_port = req['UserPort']
        br_id = req['APBRID']
        br_name = _br_name_from_br_id(br_id, my_asid)
        if_id = str(br_id) # Always use the BR ID as IF ID

        if req_type == REMOVE:
            current_br = _get_br_from_as(as_id, tp['BorderRouters'])
            if current_br and current_br == br_name:
                tp = _remove_topology(br_name, tp)
                if is_vpn:
                    _remove_vpn_ip(user)
                success = True
        elif req_type == UPDATE:
            current_br = _get_br_from_as(as_id, tp['BorderRouters'])
            if current_br is not None:
                if current_br == br_name:
                    tp = _update_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, tp)
                else:
                    tp = _remove_topology(current_br, tp)
                    tp = _create_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, tp)
                if is_vpn:
                    _configure_vpn_ip(user, as_ip)
                success = True
        else:
            tp = _create_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, tp)
            if is_vpn:
                _configure_vpn_ip(user, as_ip)
            success = True
        modifiedASes.append({"IA": as_id, "success": success})
        topo_has_changed = topo_has_changed or success

    return modifiedASes, topo_has_changed


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


def _get_br_from_as(as_id, brs_dict):
    """
    Parses border router topology and returns the ID of the current border router
    corresponding to the given ISD-AS string
    :param str as_id: ISD-AS string
    :param dict brs_dict: dictionary of all border routers
    :returns: the border router name corresponding to this AS if it exists
    """
    for br, br_dict in brs_dict.items():
        for if_id, _ in br_dict['Interfaces'].items():
            if br_dict['Interfaces'][if_id]['ISD_AS'] != as_id:
                continue
            else:
                return br
    return None


def _remove_topology(br, tp):
    """
    Remove a border router information from the topology
    :param str br: border router name
    :param dict tp: target AS topology
    :returns: updated topology as dict and success as bool
    """
    del tp['BorderRouters'][br]
    return tp


def _update_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, tp):
    """
    Update a border router information from the topology
    :param str br_name: name of the border router
    :param str if_id: interface ID
    :param str as_id: remote AS ID
    :param str as_ip: the IP address of the remote AS
    :param int as_port: the port number of the remote AS
    :param int ap_port: the port number of the attachment point
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: target AS topology
    :returns: updated topology as dict
    """
    tp['BorderRouters'][br_name]['Interfaces'][if_id]['ISD_AS'] = as_id
    tp['BorderRouters'][br_name]['Interfaces'][if_id]['Remote']['Addr'] = as_ip
    tp['BorderRouters'][br_name]['Interfaces'][if_id]['Remote']['L4Port'] = as_port
    tp['BorderRouters'][br_name]['Interfaces'][if_id]['Public']['Addr'] = _intf_addr(is_vpn)
    tp['BorderRouters'][br_name]['Interfaces'][if_id]['Public']['L4Port'] = ap_port
    return tp


def _create_topology(br_name, if_id, as_id, as_ip, as_port, ap_port, is_vpn, tp):
    """
    Create and insert border router information in the topology
    :param str br_name: name of the border router
    :param str if_id: interface ID
    :param str as_id: remote AS ID
    :param str as_ip: the IP address of the remote AS
    :param int as_port: the port number of the remote AS
    :param int ap_port: the port number of the attachment point
    :param bool is_vpn: is this a vpn-based setup
    :param dict tp: target AS topology
    :returns: updated topology as dict
    """
    intl_addr = INTL_ADDR
    intf_addr = _intf_addr(is_vpn)
    mtu = MTU
    bandwidth = BANDWIDTH

    tp['BorderRouters'][br_name] = {
        'InternalAddrs': [
            {
                'Public': [
                    {
                        'Addr': intl_addr,
                        'L4Port': BR_INTERNAL_START_PORT - 1 + int(if_id)
                    }
                ]
            }
        ],
        'Interfaces': {
        # Always use interface 1
            if_id: {
                "Overlay": "UDP/IPv4",
                "Bandwidth": bandwidth,
                "Remote": {
                    "L4Port": as_port,
                    "Addr": as_ip
                },
                "MTU": mtu,
                "LinkTo": "CHILD",
                "Public": {
                    "L4Port": ap_port,
                    "Addr": intf_addr
                },
                "InternalAddrIdx": 0,
                "ISD_AS": as_id
            }
        }
    }
    return tp


def _br_id_from_br_name(br_name):
    """
    Parse a border router name and obtain its ID
    :param str br_name: name of the border router
    :returns: ID of the border router
    """
    return int(br_name.split('-')[2])


def _br_name_from_br_id(br_id, isdas):
    """
    Construct a border router name from its ID
    :param int br_name: ID of the border router
    :param str isdas: ISD-AS string of the attachment point
    :returns: name of the border router
    """
    return 'br{}-{}'.format(isdas, br_id)


def _intf_addr(is_vpn):
    return VPN_ADDR if is_vpn else INTF_ADDR


def generate_local_gen(my_asid, as_obj, tp):
    """
    Creates the usual gen folder structure for an ISD/AS under gen
    :param str my_asid: ISD-AS as a string
    :param obj as_obj: An object that stores crypto information for AS
    :param dict tp: the topology parameter file as a dict of dicts
    """
    ia = TopoID(my_asid)
    gen_path = os.path.join(PROJECT_ROOT, GEN_PATH)
    write_dispatcher_config(gen_path)
    as_path = get_elem_dir(gen_path, ia, "")
    rmtree(as_path, True)
    for service_type, type_key in TYPES_TO_KEYS.items():
        executable_name = TYPES_TO_EXECUTABLES[service_type]
        if type_key not in tp:
            continue
        instances = tp[type_key].keys()
        for instance_name in instances:
            config = prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                           service_type, instance_name, ia)
            instance_path = get_elem_dir(gen_path, ia, instance_name)
            write_certs_trc_keys(ia, as_obj, instance_path)
            write_as_conf_and_path_policy(ia, as_obj, instance_path)
            write_supervisord_config(config, instance_path)
            write_topology_file(tp, type_key, instance_path)
            write_zlog_file(service_type, instance_name, instance_path)
    # We don't need to create zk configration for existing ASes
    # generate_zk_config(tp, ia, GEN_PATH, simple_conf_mode=False)
    generate_sciond_config(ia, as_obj, tp, gen_path)
    generate_prom_config(ia, tp, gen_path)


def _restart_scion():
    scion_command = "./scion.sh"
    supervisor_command = "./supervisor/supervisor.sh"

    os.chdir(PROJECT_ROOT)
    call([scion_command, "stop"])
    call([supervisor_command, "shutdown"])
    call([supervisor_command, "reload"])
    call([scion_command, "run"])

def parse_command_line_args():
    global SCION_COORD_URL, INTF_ADDR, INTL_ADDR, ACC_ID, ACC_PW, ONLY_AS_TO_UPDATE
    parser = argparse.ArgumentParser(description="Update the SCION gen directory")
    parser.add_argument("--url", required=True, type=str,
                        help="URL of the Coordination service")
    parser.add_argument("--address", required=True, type=str,
                        help="The interface address")
    parser.add_argument("--internal", nargs="?", type=str,
                        help="The internal address")
    parser.add_argument("--accountId", required=True, type=str,
                        help="The SCION Coordinator account ID that has permission to access this AS")
    parser.add_argument("--secret", required=True, type=str,
                        help="The secret for the SCION Coordinator account that has permission to access this AS")
    parser.add_argument("--updateAS", nargs="?", type=str, metavar="IA, e.g. 1-12",
                        help="The AS to update. If not specified, the first one from the existing ones will be updated")
    parser.add_argument("--fullsync", action="store_true",
                        help="Generate IPv6 addresses")

    # The required arguments will be present, or parse_args will exit the application
    args = parser.parse_args()
    # URL of SCION Coordination Service
    SCION_COORD_URL = args.url
    # IP address used by remote border routers for connections (default: public IP address)
    INTF_ADDR = args.address
    # Internal address the border routers should bind to (default: same as INTF_ADDR)
    INTL_ADDR = args.internal if args.internal else INTF_ADDR # copy it from INTF_ADDR if not specified
    # Default SCION-coord server account ID
    ACC_ID = args.accountId
    # Default SCION-coord server account PW
    ACC_PW = args.secret
    # If set, that is the AS to be updated, instead of the first one from the list of running ASes
    ONLY_AS_TO_UPDATE = args.updateAS
    return args

def main():
    args = parse_command_line_args()
    if not os.path.exists(OPENVPN_CCD):
        os.makedirs(OPENVPN_CCD)
    if args.fullsync:
        fullsync_local_gen()
    else:
        update_local_gen()


if __name__ == '__main__':
    main()
