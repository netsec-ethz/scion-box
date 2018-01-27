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
This file is located in $SCIONBOXPATH/
"""

#StdLib
import os

#: URL of SCION Coordination Service
SCION_COORD_URL = "https://coord.scionproto.net/"
INIT_URL = SCION_COORD_URL + "api/as/initBox"
CONNECT_URL = SCION_COORD_URL + "api/as/connectBox/"
HB_URL = SCION_COORD_URL + "api/as/heartbeat/"
#: Cerfificate Version
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0
#: Path to the Project Root netsec-ethz/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: Path to the scion folder
SCION_PATH = os.path.join(PROJECT_ROOT, "scion")
#: Path to the scion box folder
SCION_BOX_PATH = os.path.join(PROJECT_ROOT, "scion-box")
#: Path to the gen folder
GEN_PATH = os.path.join(SCION_PATH, "gen")
#: Constants used by the scion-coord
#: States of Connections and ScionLabAses
INACTIVE = 0
ACTIVE = 1
CREATE = 2
UPDATE = 3
REMOVE = 4
REMOVED = 5
#: Linktypes
PARENT = 0
CHILD = 1
CORE = 2
#: Types of ScionLabASes
INFRASTRUCTURE  = 0
VM = 1
DEDICATED = 2
BOX = 3
#: Path to the connection-tester
CONN_TESTER_PATH = os.path.join(PROJECT_ROOT, "conn-tester")
CONN_TESTER_CLIENT = os.path.join(CONN_TESTER_PATH, "bin/client")
CONN_TESTER_OUTPUT_PATH = os.path.join(SCION_BOX_PATH, "conf/output.json")
CONN_TESTER_INPUT_PATH = os.path.join(SCION_BOX_PATH, "conf/config.json")
CONN_TESTER_PORTS = 100
CONN_TESTER_START_PORT = 50000
CONN_TESTER_HOST = "https://coord.scionproto.net:1025/udp-test"
#: Constants needed for RTT Test
RTT_SERVER_PORT = 10241
MEASUREMENTS = 20
#: Constants needed for BW Test
PTR_SERVER_PORT = 10242
PTR_PATH_CLIENT = "./igi-ptr-2.1/ptr-client"
OUTPUT_PATH_CLIENT = ""
REPETITIONS = 5
#: Logging
BOX_LOGFILE = "Box.log"
LINK_TEST_LOGFILE = "linkTest.log"
FORMAT = '%(asctime)s - %(message)s'
#: Interface used for SCION
INTERFACE = "enp1s0"
