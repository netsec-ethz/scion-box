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
"""
# Stdlib
import copy
import collections
import json
import os
import requests
from shutil import rmtree
from subprocess import call
import yaml
import argparse
import time
from lib.packet.scion_addr import ISD_AS


# SCION
from lib.defines import (
    GEN_PATH,
    PROJECT_ROOT,
)
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
ONLY_AS_TO_UPDATE = None


def asid_is_infrastructure(asid):
    return asid > 0xffaa00000000 and asid < 0xffaa00010000




def fullsync_local_gen(config, coordinator, asid, timestamp):
    """
    Replaces the topology with the one indicated by the Coordinator
    :param config: The LocalConfig object used to read and write the configuration
    :param coordinator: the CoordinatorServer object used to communicate with the coordinator
    :param asid: the AS-ID of the access point for which the configuration will be updated
    :param timestamp: timestamp, seconds since Epoch
    :returns: Has the topology changed?
    """
    topo_has_changed = False
    ack_to_coordinator_message = {}
    fullsynced = coordinator.request_fullsync(asid, timestamp)
    print("[DEBUG] fullsync received: {}".format(fullsynced))

    isdas_list = [asid] # XXX: only one AS supported by query, this could work with multiple ASes

    for my_asid, status in fullsynced.items():
        if my_asid not in isdas_list:
            continue
        connections = status['connections'] or []

        as_obj, tp = config.load_topology(my_asid)
        new_tp = copy.deepcopy(tp)

        _remove_child_interfaces(new_tp)
        br = _combine_border_routers(new_tp, 'br{}'.format(my_asid))

        # add the interfaces for the links specified by the Coordinator to the BR
        skipped = []
        for i, conn in enumerate(connections):
            as_id = conn['ASID']
            as_ip = conn['UserIP']
            as_port = conn['UserPort']
            ap_port = conn['APPort']
            if_id = conn['APBRID'] # Use the BR ID as IF ID
            is_vpn = conn['IsVPN']
            user = conn['VPNUserID']
            # refuse to update if infrastructure BRID or already existent:
            if if_id <= 10 or str(if_id) in br.get('Interfaces', []):
                skipped.append(i)
                continue

            ap_ip = VPN_ADDR if is_vpn else config.interface_ip
            _insert_interface(br, if_id, as_id, as_ip, as_port, ap_ip, ap_port, config.internal_ip)

            if is_vpn:
                config.configure_vpn_ip(user, as_ip) # XXX: config files are not cleaned up
        skipped = set(skipped)
        if skipped:
            print("********************************* ERROR *************************")
            print("Refuse to update the topology with certain BRs. Too dangerous. Skipped connections are: {}".format([connections[i] for i in skipped]))
        connections[:] = [connections[i] for i in range(len(connections)) if i not in skipped]
        ack_to_coordinator_message[my_asid] = status

        topo_changed_now = tp['BorderRouters'] != new_tp['BorderRouters']
        if topo_changed_now:
            config.write_topology(my_asid, as_obj, new_tp)

        topo_has_changed = topo_has_changed or topo_changed_now


    print("[INFO] Configuration received and processed. Acknowledge to the SCION-COORD server? {} , with this content: {}".format(bool(ack_to_coordinator_message), ack_to_coordinator_message))
    if ack_to_coordinator_message:
        try:
            response = coordinator.reply_fullsync(ack_to_coordinator_message, timestamp)
        except Exception as ex:
            print("[ERROR] Failed to ACK the fullsync to the Coordinator: \n{}".format(ex))
        if response and response != ack_to_coordinator_message:
            print("***************************************************************")
            print("***************************** ERROR ***************************")
            print("***************************************************************")
            print("Looks like the Coordinator differs in what the truth is. Please check here and Coordinator.")
        print("[DEBUG] Response from Coordinator to our status: {}".format(response))

    return topo_has_changed


def _remove_child_interfaces(topo):
    """
    Remove all Interfaces to CHILD user-ASes and the corresponding Border Routers from the topology config
    :param topo:    The topology dict from which Interfaces and BRs will be removed
    """
    brs = topo['BorderRouters']
    for brname in list(brs.keys()): # list() because we del()
        br = brs[brname]

        # count references to internal addrs:
        internalAddrIdxCounter = collections.Counter(iface['InternalAddrIdx'] for iface in br['Interfaces'].values())
        for ifnum in list(br['Interfaces'].keys()):
            iface = br['Interfaces'][ifnum]
            ia = ISD_AS(iface['ISD_AS'])
            internalAddrIdx = iface['InternalAddrIdx']
            # if the link is to a child and that child is a user AS
            if not asid_is_infrastructure(ia[1]) and iface['LinkTo'] == 'CHILD':
                internalAddrIdxCounter[internalAddrIdx] -= 1
                del br['Interfaces'][ifnum]

        if not br['Interfaces']: # no interfaces left -> remove BR
            del brs[brname]
        else:
            # remove unreferenced internal addrs:
            idxsToRemove = (idx for idx, count in internalAddrIdxCounter.items() if count is 0)
            for i in sorted(idxsToRemove, reverse=True):
                del br['InternalAddrs'][i]
            # patch remaining internal adddress indexes:
            idxRemap = {}
            idxOffset = 0
            for idx, count in internalAddrIdxCounter.items():
                if count == 0:
                    idxOffset += 1
                else:
                    idxRemap[idx] = idx-idxOffset
            for iface in br['Interfaces'].values():
                iface['InternalAddrIdx'] = idxRemap[iface['InternalAddrIdx']]

def _combine_border_routers(topo, brname):
    """
    If configuration entries for more than one BorderRouter process exists,
    combine them into a config for a single BorderRouter process with multiple interfaces.
    This is an "upgrade" step that will likely only have an effect for the first time
    this version of the update_gen script is executed.
    :param topo:    The topology dict to edit
    :param brname:  The name to be used for the single new BorderRouter entry
    :returns:       The entry for the single BorderRouter in topo
    """
    brs = topo['BorderRouters']
    if len(brs) == 1:
        br = brs[brname] = brs.pop(next(iter(brs))) # rename
    else:
        br = brs.setdefault(brname, {})
        # merge interfaces of all other BRs into `br`
        internalAddrs = br.setdefault('InternalAddrs', [])
        interfaces = br.setdefault('Interfaces', {})
        for currBrName in sorted(set(brs.keys()) - {brname}):
            currBr = brs[currBrName]
            internalAddrIdx = len(internalAddrs)
            internalAddrs.append(currBr['InternalAddrs'][0]) # assume only one interface per input BR
            ifid, iface = next(iter(currBr['Interfaces'].items()))
            iface['InternalAddrIdx'] = internalAddrIdx
            interfaces[ifid] = iface
            del brs[currBrName]
    return br



def deltasync_local_gen(config, coordinator, asid):
    """
    The update the topology configuration by requesting a list of changes from the coordinator.
    :param config: The LocalConfig object used to read and write the configuration
    :param coordinator: the CoordinatorServer object used to communicate with the coordinator
    :param asid: the AS-ID of the access point for which the configuration will be updated
    :returns: Has the topology changed?
    """

    topo_has_changed = False
    updated_ases = {}
    original_topo = []
    new_as_dict = coordinator.request_deltasync(asid)

    isdas_list = [asid] # XXX: only one AS supported by query, this could work with multiple ASes

    for my_asid, new_reqs in new_as_dict.items():
        if my_asid not in isdas_list:
            continue
        updated_ases[my_asid] = {}
        updated_ases[my_asid][CREATED] = []
        updated_ases[my_asid][UPDATED] = []
        updated_ases[my_asid][REMOVED] = []

        as_obj, tp = config.load_topology(my_asid)
        original_topo.append((my_asid, as_obj, tp))
        new_tp = copy.deepcopy(tp)

        for req_type in new_reqs.keys():
            if new_reqs[req_type]:
                modifiedASes, topo_changed_now = update_topology(config, my_asid, new_reqs, req_type, new_tp)
                updated_ases[my_asid][effects[req_type]].extend(modifiedASes)
                if topo_changed_now:
                    config.write_topology(my_asid, as_obj, new_tp)
                    topo_has_changed = True

    if topo_has_changed:
        print("[INFO] Configuration changed. Acknowledge to the SCION-COORD server")
        try:
            coordinator.reply_deltasync(updated_ases)
        except Exception as ex:
            print("[ERROR] Failed to connect to SCION-COORD server: \n%s" % ex)
            for my_asid, as_obj, old_tp in original_topo:
                print("[INFO] Retrieving the original topology configuration: %s" % my_asid)
                config.write_topology(my_asid, as_obj, old_tp)
            exit(1)
    return topo_has_changed

class CoordinatorServer:
    """
    Communicate with SCIONLab coordination server over HTTPS.
    Encapsulates requests and the corresponding ack-replys.
    """

    GET_REQ = "api/as/getUpdatesForAP"
    GETFULL_REQ = "api/as/getConnectionsForAP"
    POST_REQ = "api/as/confirmUpdatesFromAP"
    POSTFULL_REQ = "api/as/setConnectionsForAP"

    def __init__(self, url, accountId, accountPwd):
        """
        :param url: string, the base adress for the coordinator
        :param accountId: string
        :param accountPwd: string
        """
        self.url = url
        self.accountId = accountId
        self.accountPwd = accountPwd

    def request_fullsync(self, asid, timestamp):
        """
        Ask the Coordinator for the full list of connections for the access point with the given AS-id.
        :param asid: string, AS-id of the access point for which information is requested.
        :param int timestamp: seconds since Epoch
        :returns: dict response from Coordinator
                  {
                    '17-ffaa_0_110': {
                        'connections': [
                            {
                                'ASID': '1-ffaa:0:111',
                                'UserIP': '192.168.1.8',
                                'UserPort': 50000,
                                'APPort': 50021,
                                'APBRID': 80,
                                'IsVPN': False,
                                'VPNUserID': '',
                            },
                            {
                                'ASID': '1-ffaa:0:112',
                                'UserIP': '192.168.1.9',
                                'UserPort': 50000,
                                'APPort': 50021,
                                'APBRID': 72,
                                'IsVPN': False,
                                'VPNUserID': '',
                            },
                        ]
                    }
                }
        """
        url = "{url}/{req}/{accountId}/{accountPwd}?scionLabAP={asid}&utcTimeDelta={timestamp}".format( \
                    url=self.url,
                    req=self.GETFULL_REQ,
                    accountId=self.accountId,
                    accountPwd=self.accountPwd,
                    asid=asid,
                    timestamp=timestamp)
        return self._send_request_and_get_json(url)

    def reply_fullsync(self, ack_message, timestamp):
        """
        Confirm to the Coordinator the current accepted list of connections.
        :param dict ack_message: message to send to the Coordinator. Same format
                                 as result of request_fullsync.
        :param int timestamp: seconds since Epoch
        :returns: response from Coordinator; same format as above.
        """
        url = "{url}/{req}/{accountId}/{accountPwd}?utcTimeDelta={timestamp}".format( \
                    url=self.url,
                    req=self.POSTFULL_REQ,
                    accountId=self.accountId,
                    accountPwd=self.accountPwd,
                    timestamp=timestamp)
        while url:
            resp = requests.post(url, json=ack_message, allow_redirects=False)
            url = resp.next.url if resp.is_redirect and resp.next else None
        content = resp.content.decode("utf-8")
        try:
            resp_dict = json.loads(content)
        except Exception as ex:
            raise Exception("Error while parsing JSON: {} : {}\nContent was: {}".format(type(ex), str(ex), content))
        return resp_dict

    def request_deltasync(self, asid):
        """
        Send get requests in order to get newly joined SCIONLab ASes.
        :param asid: string, AS-id of the access point for which information is requested.
        :returns: dict describing the update actions to perform
                     {
                        '17-ffaa_0_1103': {
                             'Create': [
                                 {
                                     'ASID': '17:ffaa:1:4001',
                                     'IsVPN': True,
                                     'VPNUserID': 'user@example.com_4001',
                                     'UserIP': '10.8.0.42',
                                     'UserPort': 50000,
                                     'APPort': 50050,
                                     'APBRID': 2
                                 },
                             ],
                             'Update': [],
                             'Remove': []
                         }
                     }
        """
        url = "{url}/{req}/{accountId}/{accountPwd}?scionLabAP={asid}".format( \
                    url=self.url,
                    req=self.GET_REQ,
                    accountId=self.accountId,
                    accountPwd=self.accountPwd,
                    asid=asid)
        return self._send_request_and_get_json(url)

    def reply_deltasync(self, ack):
        """
        Send post request to report the update status to the coordinator.
        :param ack: dict describing the update actions actually performed:
                     {
                        '17-ffaa:0:1103': {
                             'Created': [
                                 {
                                     'IA': '17:ffaa:1:4001',
                                     'success': True,
                                 },
                             ],
                             'Updated': [],
                             'Removed': []
                         }
                     }
        """
        url = "{url}/{req}/{accountId}/{accountPwd}".format( \
                    url=self.url,
                    req=self.POST_REQ,
                    accountId=self.accountId,
                    accountPwd=self.accountPwd)
        while url:
            resp = requests.post(url, json=ack, allow_redirects=False)
            url = resp.next.url if resp.is_redirect and resp.next else None

    def _send_request_and_get_json(self, url):
        """
        :returns dict json_response
        """
        print("[DEBUG] requesting Coordinator with: {}".format(url))
        try:
            resp = requests.get(url)
        except requests.exceptions.ConnectionError as ex:
            print(str(ex))
            exit(1)
        content = resp.content.decode('utf-8')
        if resp.status_code == 204:
            return {}
        elif resp.status_code != 200:
            raise Exception("Status code ({}) not 200. Content is: {}".format(resp.status_code, content))
        try:
            resp_dict = json.loads(content)
        except Exception as ex:
            raise Exception("Error while parsing JSON: {} : {}\nContent was: {}".format(type(ex), str(ex), content))
        return resp_dict


class LocalConfig:
    """
    Read and write local configuration.
    """

    def __init__(self, interface_ip, internal_ip, gen_path, openvpn_ccd_path):
        """
        :param interface_ip: the IP address of the attachment point
        :param internal_ip: the (AS-)internal IP address of the BR
        :param gen_path: Path to gen directory ($SC/gen)
        :param openvpn_ccd_path: Client configuration directory for openvpn (~/openvpn_ccd/)
        """
        self.interface_ip = interface_ip
        self.internal_ip = internal_ip
        self.gen_path = gen_path
        self.openvpn_ccd_path = openvpn_ccd_path

    def load_topology(self, asid):
        """
        Reload the current topology configuration.
        :param str gen_path: target asid (e.g., '1-11')
        :returns: credentials (keys, trc, cert) and topology dictionary for the given AS
        """
        ia = ISD_AS(asid)
        as_str = ia.as_file_fmt() if 'as_file_fmt' in dir(ia) else ia[1]
        as_path = 'ISD%s/AS%s' % (ia[0], as_str)
        process_path = self._get_process_path(os.path.join(self.gen_path, as_path))
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
                master_as_key = self._get_masterkey(conf_file)
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

    def write_topology(self, asid, as_obj, tp):
        """
        Creates the usual gen folder structure for an ISD/AS under gen
        :param str asid: ISD-AS as a string
        :param obj as_obj: An object that stores crypto information for AS
        :param dict tp: the topology parameter file as a dict of dicts
        """
        ia = TopoID(asid)

        write_dispatcher_config(self.gen_path)
        as_path = get_elem_dir(self.gen_path, ia, "")
        rmtree(as_path, True)
        for service_type, type_key in TYPES_TO_KEYS.items():
            executable_name = TYPES_TO_EXECUTABLES[service_type]
            if type_key not in tp:
                continue
            instances = tp[type_key].keys()
            for instance_name in instances:
                config = prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                               service_type, instance_name, ia, "127.0.0.1")
                instance_path = get_elem_dir(self.gen_path, ia, instance_name)
                write_supervisord_config(config, instance_path)
                write_certs_trc_keys(ia, as_obj, instance_path)
                write_as_conf_and_path_policy(ia, as_obj, instance_path)
                write_topology_file(tp, type_key, instance_path)
                write_zlog_file(service_type, instance_name, instance_path)
        # We don't need to create zk configration for existing ASes
        # generate_zk_config(tp, ia, GEN_PATH, simple_conf_mode=False)
        generate_sciond_config(ia, as_obj, tp, self.gen_path)
        generate_prom_config(ia, tp, self.gen_path)


    def configure_vpn_ip(self, user, vpn_ip):
        """
        Adds/updates the vpn ip address in the client-configuration directory
        :param user: email of the user
        :param vpn_ip: ip address to assign to this user
        :return: void
        """
        if not os.path.exists(self.openvpn_ccd_path):
            os.makedirs(self.openvpn_ccd_path)
        with open(self._ccd_user(user), 'w') as vpn_config:
            vpn_config.write("ifconfig-push " + vpn_ip + " " + VPN_NETMASK)

    def remove_vpn_ip(self, user):
        """
        Removes the vpn ip address in the client-configuration directory
        :param user: email of the user
        :return: void
        """
        try:
            os.remove(self._ccd_user(user))
        except OSError:
            pass

    def get_asids(self):
        """
        Load ISD-AS information running on the local machine
        :returns: a list of ISD-AS (e.g., ['1-11', '1-12'])
        """
        path = os.path.normpath('.')
        isdas_list = []
        for root, _, _ in os.walk(self.gen_path):
            base_depth = self.gen_path.count(os.path.sep)
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

    def _ccd_user(self, user):
        """
        Location where the vpn ip address is saved for given user
        :param user: user email address
        :return: location
        """
        return os.path.join(self.openvpn_ccd_path, user)


    def _get_process_path(self, path):
        """
        Searching one of the existing process directories from the topology directory
        and returns it as a process path.
        :param str path: path for sub directory of target as (e.g., 'gen/ISD1/AS11')
        :returns: a process path (e.g., 'gen/ISD1/AS11/br1-11-1')
        """
        for root, _, files in os.walk(path):
            if 'topology.json' in files:
                return root
        print("[ERROR] Unable to load topology.json")
        exit(1)

    def _get_masterkey(self, conf_file):
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


def update_topology(config, my_asid, reqs, req_type, tp):
    """
    Update the topology by adding, updating and removing BRs as requested.
    :param config: The LocalConfig used to modify the VPN configuration
    :param ISD_AS my_asid: current AS number
    :param dict reqs: requested entities to be changed from current topology
    :param str req_type: type of requested changes
    :param dict tp: in/out existing topology / updated topology
    :returns: modified user ASes and boolean indicating if topology is now different
    """

    brs = tp['BorderRouters']
    modifiedASes = []
    topo_has_changed = False
    for req in reqs[req_type]:
        success = False
        user = req['VPNUserID']
        as_id = req['ASID']
        as_ip = req['UserIP']
        is_vpn = req['IsVPN']
        ap_port = req['APPort']
        as_port = req['UserPort']
        if_id = req['APBRID']
        ap_ip = VPN_ADDR if is_vpn else config.interface_ip

        if req_type == REMOVE:
            current_br, current_if_id = _get_br_ifid_from_as(as_id, tp)
            if current_br:
                _remove_interface(current_br, current_if_id, tp)
                if is_vpn:
                    config.remove_vpn_ip(user)
                success = True
        elif req_type == UPDATE:
            current_br, current_if_id = _get_br_ifid_from_as(as_id, tp)
            if current_br:
                if current_if_id == if_id:
                    _update_interface(brs[current_br], if_id, as_id, as_ip, as_port, ap_ip, ap_port)
                else:
                    _remove_interface(current_br, current_if_id, tp)
                    _insert_interface(brs[current_br], if_id, as_id, as_ip, as_port, ap_ip, ap_port, config.internal_ip)
                if is_vpn:
                    config.configure_vpn_ip(user, as_ip)
                success = True
        else:
            br = brs.setdefault('br{}'.format(my_asid), {})
            _insert_interface(br, if_id, as_id, as_ip, as_port, ap_ip, ap_port, config.internal_ip)
            if is_vpn:
                config.configure_vpn_ip(user, as_ip)
            success = True
        modifiedASes.append({"IA": as_id, "success": success})
        topo_has_changed = topo_has_changed or success

    return modifiedASes, topo_has_changed


def _get_br_ifid_from_as(as_id, tp):
    """
    Parses border router topology and returns the ID of the current border router
    corresponding to the given ISD-AS string
    :param str as_id: ISD-AS string
    :param dict tp: target AS topology
    :returns: the border router name and Interface-ID corresponding to this AS if it exists
    """
    brs = tp['BorderRouters']
    for br, br_dict in brs.items():
        for if_id, _ in br_dict['Interfaces'].items():
            if br_dict['Interfaces'][if_id]['ISD_AS'] != as_id:
                continue
            else:
                return br, int(if_id)
    return None, None


def _remove_interface(brname, if_id, tp):
    """
    Remove an interface from the topology
    :param str br: border router name
    :param int if_id: interface id
    :param dict tp: target AS topology
    """
    brs = tp['BorderRouters']
    br = brs[brname]
    if len(br['Interfaces']) == 1:
        del brs[brname]
    else:
        internalAddrIdx = br['Interfaces'][str(if_id)]['InternalAddrIdx']
        del br['Interfaces'][str(if_id)]

        # if that was the last reference to this internal addr, remove it and patch the indices
        if not internalAddrIdx in (iface['InternalAddrIdx'] for iface in br['Interfaces'].values()):
            del br['InternalAddrs'][internalAddrIdx]
            for iface in br['Interfaces'].values():
                if iface['InternalAddrIdx'] > internalAddrIdx:
                    iface['InternalAddrIdx'] -= 1


def _update_interface(br, if_id, as_id, as_ip, as_port, ap_ip, ap_port):
    """
    Update a BorderRouter Interface entry
    :param str br: border router name
    :param int if_id: interface id
    :param str as_id: remote AS ID
    :param str as_ip: the IP address of the remote AS
    :param int as_port: the port number of the remote AS
    :param str ap_ip: the IP address of the attachment point
    :param int ap_port: the port number of the attachment point
    :param dict tp: target AS topology
    """
    iface = br['Interfaces'][str(if_id)]
    iface['ISD_AS'] = as_id
    iface['Remote']['Addr'] = as_ip
    iface['Remote']['L4Port'] = as_port
    iface['Public']['Addr'] = ap_ip
    iface['Public']['L4Port'] = ap_port

def _insert_interface(br, if_id, as_id, as_ip, as_port, ap_ip, ap_port, internal_ip):
    """
    Create and insert interface in the BorderRouter entry in the topology
    :param ap_addrs: IP/Port of Access Point
    :param dict br: BorderRouters entry in target topology
    :param int if_id: interface ID
    :param str as_id: remote AS ID
    :param str as_ip: the IP address of the remote AS
    :param int as_port: the port number of the remote AS
    :param str ap_ip: the IP address of the attachment point
    :param int ap_port: the port number of the attachment point
    :param str internal_ip: the (AS-)internal IP address of the BR
    :returns: updated topology as dict
    """

    mtu = MTU
    bandwidth = BANDWIDTH

    internalAddrs = br.setdefault('InternalAddrs', [])
    interfaces = br.setdefault('Interfaces', {})

    internalAddrIdx = len(internalAddrs)
    internalAddrs.append({
        'Public': [
            {
                'Addr': internal_ip,
                'L4Port': BR_INTERNAL_START_PORT - 1 + if_id
            }
        ]
    })

    interfaces[str(if_id)] = {
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
            "Addr": ap_ip
        },
        "InternalAddrIdx": internalAddrIdx,
        "ISD_AS": as_id
    }




def _restart_scion():
    scion_command = "./scion.sh"
    supervisor_command = "./supervisor/supervisor.sh"

    os.chdir(PROJECT_ROOT)
    call([scion_command, "stop"])
    call([supervisor_command, "shutdown"])
    call([supervisor_command, "reload"])
    call([scion_command, "run"])

def parse_command_line_args():
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
    return args

def main():
    args = parse_command_line_args()
    print("[DEBUG] update_gen --------------------------------------- START -------------------------------------")

    config = LocalConfig(args.address,
                         args.internal or args.address,
                         os.path.join(PROJECT_ROOT, GEN_PATH),
                         os.path.expanduser("~/openvpn_ccd"))
    coordinator = CoordinatorServer(args.url, args.accountId, args.secret)

    asid = args.updateAS or config.get_asids()[0]

    if args.fullsync:
        timestamp = int(time.time())
        topo_has_changed = fullsync_local_gen(config, coordinator, asid, timestamp)
    else:
        topo_has_changed = deltasync_local_gen(config, coordinator, asid)

    if topo_has_changed:
        print("[INFO] Restarting SCION")
        _restart_scion()
    else:
        print("[INFO] Nothing changed. Not restarting SCION")

    print("[DEBUG] update_gen --------------------------------------- END ---------------------------------------")


if __name__ == '__main__':
    main()
