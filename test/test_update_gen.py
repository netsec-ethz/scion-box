# Copyright 2018 ETH Zurich
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
:mod:`test_update_gen` --- Tests for `update_gen`
==============================================================================
"""

import os
import unittest
import json
import update_gen



class TestRemoveChildInterfaces(unittest.TestCase):
    """ Tests for the update_gen._remove_child_interfaces function.
        Note that this function is also covered in the TestFullsync.
    """

    def test_multipleBRs(self):
        # Note: only relevant fields contained in test config
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107-84": {
                  "Interfaces": {
                    "84": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-85": {
                  "Interfaces": {
                    "85": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:39"
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31134
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-93": {
                  "Interfaces": {
                    "93": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1098"
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31142
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-1": {
                  "Interfaces": {
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-2": {
                  "Interfaces": {
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1103",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-106": {
                  "Interfaces": {
                    "106": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:c2"
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31155
                        }
                      ]
                    }
                  ]
                }
            }
        }

        expectedTopo = {
            "BorderRouters": {
                "br17-ffaa_0_1107-1": {
                  "Interfaces": {
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-2": {
                  "Interfaces": {
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1103",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    }
                  ]
                }
            }
        }

        update_gen._remove_child_interfaces(topo)

        self.assertEqual(topo, expectedTopo)

    
    def test_singleBR(self):
        # Test that patching the internal address indexes works
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "84": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    },
                    "85": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 1,
                      "ISD_AS": "17-ffaa:1:39"
                    },
                    "93": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 2,
                      "ISD_AS": "17-ffaa:1:1098"
                    },
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 3,
                      "ISD_AS": "17-ffaa:0:1102",
                    },
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 4,
                      "ISD_AS": "17-ffaa:0:1103",
                    },
                    "106": {
                      "LinkTo": "CHILD",
                      "InternalAddrIdx": 5,
                      "ISD_AS": "17-ffaa:1:c2"
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31134
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31142
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31155
                        }
                      ]
                    }
                  ]
                }
            }
        }

        expectedTopo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    },
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 1,
                      "ISD_AS": "17-ffaa:0:1103",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    }
                  ]
                }
            }
        }

        update_gen._remove_child_interfaces(topo)
        self.assertEqual(topo, expectedTopo)


class TestCombineBorderRouters(unittest.TestCase):
    """ Tests for the update_gen._combine_border_routers function.
        Note that this function is also covered in the TestFullsync.
    """
    def runTest(self):
        # Note: only relevant fields contained in test config
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107-1": {
                  "Interfaces": {
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    }
                  ]
                },
                "br17-ffaa_0_1107-2": {
                  "Interfaces": {
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1103",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    }
                  ]
                }
            }
        }

        expectedTopo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "1": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    },
                    "2": {
                      "LinkTo": "PARENT",
                      "InternalAddrIdx": 1,
                      "ISD_AS": "17-ffaa:0:1103",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31046
                        }
                      ]
                    }
                  ]
                }
            }
        }

        update_gen._combine_border_routers(topo, "br17-ffaa_0_1107")
        self.assertEqual(topo, expectedTopo)


class TestRemoveInterface(unittest.TestCase):
    """ Tests for the update_gen._remove_interface function.
        Note that this function is also covered in the TestDeltasync.
    """
    def test_simple(self):
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107-84": {
                  "Interfaces": {
                    "84": {
                      "ISD_AS": "17-ffaa:1:1133",
                      "InternalAddrIdx": 0,
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    }
                  ]
                }
              }
            }

        br, ifid = update_gen._get_br_ifid_from_as("17-ffaa:1:1133", topo)
        self.assertEqual(br, "br17-ffaa_0_1107-84")
        self.assertEqual(ifid, 84)
        update_gen._remove_interface(br, ifid, topo)

        expectedTopo = {
            "BorderRouters": {}
        }
        self.assertEqual(topo, expectedTopo)

    def test_multipleIFs(self):
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "84": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    },
                    "85": {
                      "InternalAddrIdx": 1,
                      "ISD_AS": "17-ffaa:1:39"
                    },
                    "93": {
                      "InternalAddrIdx": 2,
                      "ISD_AS": "17-ffaa:1:1098"
                    },
                    "1": {
                      "InternalAddrIdx": 3,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31134
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31142
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    }
                  ]
                }
            }
        }
        br, ifid = update_gen._get_br_ifid_from_as("17-ffaa:1:39", topo)
        self.assertEqual(br, "br17-ffaa_0_1107")
        self.assertEqual(ifid, 85)
        update_gen._remove_interface(br, ifid, topo)
        
        expectedTopo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "84": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    },
                    "93": {
                      "InternalAddrIdx": 1,
                      "ISD_AS": "17-ffaa:1:1098"
                    },
                    "1": {
                      "InternalAddrIdx": 2,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31142
                        }
                      ]
                    },
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31045
                        }
                      ]
                    }
                  ]
                }
            }
        }
        self.assertEqual(topo, expectedTopo)

    def test_sharedInternalAddr(self):
        topo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "84": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    },
                    "85": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:39"
                    },
                    "93": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1098"
                    },
                    "1": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    }
                  ]
                }
            }
        }
        br, ifid = update_gen._get_br_ifid_from_as("17-ffaa:1:39", topo)
        self.assertEqual(br, "br17-ffaa_0_1107")
        self.assertEqual(ifid, 85)
        update_gen._remove_interface(br, ifid, topo)

        expectedTopo = {
            "BorderRouters": {
                "br17-ffaa_0_1107": {
                  "Interfaces": {
                    "84": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1133"
                    },
                    "93": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:1:1098"
                    },
                    "1": {
                      "InternalAddrIdx": 0,
                      "ISD_AS": "17-ffaa:0:1102",
                    }
                  },
                  "InternalAddrs": [
                    {
                      "Public": [
                        {
                          "Addr": "192.33.93.195",
                          "L4Port": 31133
                        }
                      ]
                    }
                  ]
                }
            }
        }
        self.assertEqual(topo, expectedTopo)


class MockConfig:
    def __init__(self, interface_ip, internal_ip, initialTopo, initialVPNConfig = None):
        self.interface_ip = interface_ip
        self.internal_ip = internal_ip
        self.initialTopo = initialTopo
        self.writtenTopo = {}
        self.vpnConfig = initialVPNConfig or {}

    def load_topology(self, asid):
        as_obj = None
        return as_obj, self.initialTopo

    def write_topology(self, asid, as_obj, topo):
        self.writtenTopo[asid] = topo

    def configure_vpn_ip(self, user, vpn_ip):
        self.vpnConfig[user] = vpn_ip

    def remove_vpn_ip(self, user):
        self.vpnConfig.pop(user)


class MockCoordinator:
    def  __init__(self, requestResponse):
        self.requestResponse = requestResponse
        self.ack = None

    def request_fullsync(self, asid, timestamp):
        return self.requestResponse

    def reply_fullsync(self, ack, timestamp):
        self.ack = ack
        return ack

    def request_deltasync(self, asid):
        return self.requestResponse

    def reply_deltasync(self, ack):
        self.ack = ack





def jsonLoadf(filename):
    """ Helper: load json resource file, in the data/-subdir in this module """
    with open(os.path.join(os.path.dirname(__file__), 'data', filename)) as f:
        return json.load(f)

class Tiny:
    """ Bundle test data for 'tiny' setup """
    interface_ip = '127.0.0.4'
    internal_ip = '127.0.0.9'
    asid = '1-ff00_0_110'
    def topology():
        """ The 'initial' topology configuration (with one BR with many interfaces) """
        return jsonLoadf('tiny-topology.json')
    
    def topologyManyBRs():
        """ The 'initial' topology configuration, with many BRs with one interface each """
        return jsonLoadf('tiny-topology-manyBRs.json')

    def connections():
        """ The set of connections describing the initial topology """
        return jsonLoadf('tiny-connections-initial.json')

    def connectionAdded():
        """ Data for an additional connection """
        return { 'ASID': '1-ff00:0:113',
                 'IsVPN': True,
                 'VPNUserID': 'user@example.com_4001',
                 'UserIP': '10.0.8.42',
                 'UserPort': 50000,
                 'APPort': 50023,
                 'APBRID': 23 }
    
    def topologyAdded():
        """ The topology configuration with `connectionAdded` added. """
        return jsonLoadf('tiny-topology-add.json')


class AS1_17:
    """ Bundle test data extracted from the access point at AS 1-17 (17-ffaa:0:1107) """
    interface_ip = '192.33.93.195'
    internal_ip = '192.33.93.195'
    asid = '17-ffaa_0_1107'
    
    def topology():
        """ The 'initial' topology configuration (with one BR with many interfaces) """
        return jsonLoadf('as1-17-topology.json')
    
    def topologyManyBRs():
        """ The 'initial' topology configuration, with many BRs with one interface each """
        return jsonLoadf('as1-17-topology-manyBRs.json')

    def connections():
        """ The set of connections describing the topology """
        return jsonLoadf('as1-17-connections.json')




class TestFullsync(unittest.TestCase):
    def test_tiny_nop(self):
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topology())
        coordinator = MockCoordinator(Tiny.connections())

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, Tiny.asid, 0)
   
        self.assertFalse(topo_changed)
        self.assertEqual(config.writtenTopo, {})

    def test_tiny_upgradeToSingleBR(self):
        """
        Fullsync with same set of connections, initially with one BR per connection,
        upgrade to use a single BR.
        """
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topologyManyBRs())
        coordinator = MockCoordinator(Tiny.connections())

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, Tiny.asid, 0)
   
        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[Tiny.asid], Tiny.topology())

    def test_tiny_add(self):
        """
        Fullsync with one added connection.
        """
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topology())
        connections = Tiny.connections()
        connections[Tiny.asid]['connections'].append(Tiny.connectionAdded())
        coordinator = MockCoordinator(connections)

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, Tiny.asid, 0)
   
        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[Tiny.asid], Tiny.topologyAdded())

    def test_tiny_remove(self):
        """
        Fullsync with one removed connection.
        """
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topologyAdded())
        coordinator = MockCoordinator(Tiny.connections())

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, Tiny.asid, 0)
   
        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[Tiny.asid], Tiny.topology())

    def test_as1_17_upgradeToSingleBR(self):
        """
        Fullsync with same set of connections, initially with one BR per connection,
        upgrade to use a single BR.
        """
        config = MockConfig(AS1_17.interface_ip, AS1_17.internal_ip, AS1_17.topologyManyBRs())
        coordinator = MockCoordinator(AS1_17.connections())

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, AS1_17.asid, 0)
   
        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[AS1_17.asid], AS1_17.topology())


    def test_as1_17_nop(self):
        """
        Fullsync with same set of connections
        """
        config = MockConfig(AS1_17.interface_ip, AS1_17.internal_ip, AS1_17.topology())
        coordinator = MockCoordinator(AS1_17.connections())

        topo_changed = update_gen.fullsync_local_gen(config, coordinator, AS1_17.asid, 0)
   
        self.assertFalse(topo_changed)
        self.assertEqual(config.writtenTopo, {})




class TestDeltasync(unittest.TestCase):
    def test_tiny_nop(self):
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topology())
        coordinator = MockCoordinator({ Tiny.asid: { } })
        
        topo_changed = update_gen.deltasync_local_gen(config, coordinator, Tiny.asid)

        self.assertFalse(topo_changed)
        self.assertEqual(config.writtenTopo, {})
        self.assertEqual(coordinator.ack, None) # Nothing to acknowledge

    def test_tiny_add(self):
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topology())

        connectionAdded = Tiny.connectionAdded()
        coordinator = MockCoordinator({ Tiny.asid: { 'Create' : [ connectionAdded ] } })
        
        topo_changed = update_gen.deltasync_local_gen(config, coordinator, Tiny.asid)

        self.assertTrue(topo_changed)
        self.maxDiff=None
        self.assertEqual(config.writtenTopo[Tiny.asid], Tiny.topologyAdded())
        self.assertEqual(config.vpnConfig, { connectionAdded['VPNUserID'] : connectionAdded['UserIP'] })
        self.assertEqual(coordinator.ack, { 
            Tiny.asid: {
                'Removed' : [],
                'Updated' : [],
                'Created' : [ { 'IA': connectionAdded['ASID'], 'success': True } ],
            }
        })

    def test_tiny_remove(self):
        connectionAdded = Tiny.connectionAdded()
        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topologyAdded(), { connectionAdded['VPNUserID'] : connectionAdded['UserIP'] })
        coordinator = MockCoordinator({ Tiny.asid: { 'Remove' : [ connectionAdded ] } })
        
        topo_changed = update_gen.deltasync_local_gen(config, coordinator, Tiny.asid)

        self.assertTrue(topo_changed)
        self.maxDiff=None
        self.assertEqual(config.writtenTopo[Tiny.asid], jsonLoadf('tiny-topology.json'))
        self.assertEqual(config.vpnConfig, {})
        self.assertEqual(coordinator.ack, { 
            Tiny.asid: {
                'Removed' : [ { 'IA': connectionAdded['ASID'], 'success': True } ],
                'Updated' : [],
                'Created' : [],
            }
        })

    def test_tiny_update_sameIFID(self):
        connectionAdded = Tiny.connectionAdded()
        connectionAdded['UserPort'] = 51337

        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topologyAdded())
        coordinator = MockCoordinator({ Tiny.asid: { 'Update' : [ connectionAdded ] } })
        
        topo_changed = update_gen.deltasync_local_gen(config, coordinator, Tiny.asid)
        
        # Apply expected change (only port changed)
        expectedTopo = Tiny.topologyAdded()
        next(iter(expectedTopo['BorderRouters'].values()))['Interfaces']['23']['Remote']['L4Port'] = 51337

        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[Tiny.asid], expectedTopo)
        self.assertEqual(coordinator.ack, { 
            Tiny.asid: {
                'Removed' : [],
                'Updated' : [ { 'IA': connectionAdded['ASID'], 'success': True } ],
                'Created' : [],
            }
        })

    def test_tiny_update_differentIFID(self):
        connectionAdded = Tiny.connectionAdded()
        connectionAdded['APBRID'] = 27

        config = MockConfig(Tiny.interface_ip, Tiny.internal_ip, Tiny.topologyAdded())
        coordinator = MockCoordinator({ Tiny.asid: { 'Update' : [ connectionAdded ] } })
        
        topo_changed = update_gen.deltasync_local_gen(config, coordinator, Tiny.asid)
        
        expectedTopo = Tiny.topologyAdded()
        # Rename interface entry
        br = next(iter(expectedTopo['BorderRouters'].values()))
        ifaces = br['Interfaces']
        ifaces['27'] = ifaces.pop('23')
        # Also, the port for the internal address will change (because its chosen based on the IF-ID)
        internalAddrIdx = ifaces['27']['InternalAddrIdx']
        br['InternalAddrs'][internalAddrIdx]['Public'][0]['L4Port'] += 27-23 

        self.assertTrue(topo_changed)
        self.assertEqual(config.writtenTopo[Tiny.asid], expectedTopo)
        self.assertEqual(coordinator.ack, { 
            Tiny.asid: {
                'Removed' : [],
                'Updated' : [ { 'IA': connectionAdded['ASID'], 'success': True } ],
                'Created' : [],
            }
        })


if __name__ == "__main__":
    unittest.main()

