from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

import pox.openflow.libpof_02 as pof

from digraph import *
import random
import math

log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))
# 14 node nsfnet
adjacency[1][2] = (3, 0, 1050)
adjacency[2][1] = (3, 22, 1050)
adjacency[1][3] = (1, 2, 1500)
adjacency[3][1] = (1, 24, 1500)
adjacency[1][8] = (2, 3, 2400)
adjacency[8][1] = (2, 25, 2400)
adjacency[2][3] = (2, 1, 600)
adjacency[3][2] = (2, 23, 600)
adjacency[2][4] = (3, 4, 750)
adjacency[4][2] = (1, 26, 750)
adjacency[3][6] = (3, 5, 1800)
adjacency[6][3] = (4, 27, 1800)
adjacency[4][5] = (2, 6, 600)
adjacency[5][4] = (2, 28, 600)
adjacency[4][11] = (3, 7, 1950)
adjacency[11][4] = (3, 29, 1950)
adjacency[5][6] = (1, 8, 1200)
adjacency[6][5] = (3, 30, 1200)
adjacency[5][7] = (3, 9, 600)
adjacency[7][5] = (3, 31, 600)
adjacency[6][10] = (1, 10, 1050)
adjacency[10][6] = (3, 32, 1050)
adjacency[6][14] = (2, 11, 1800)
adjacency[14][6] = (1, 33, 1800)
adjacency[7][8] = (1, 12, 750)
adjacency[8][7] = (1, 34, 750)
adjacency[7][10] = (2, 13, 1350)
adjacency[10][7] = (2, 35, 1350)
adjacency[8][9] = (3, 14, 750)
adjacency[9][8] = (1, 36, 750)
adjacency[9][10] = (2, 15, 750)
adjacency[10][9] = (1, 37, 750)
adjacency[9][12] = (3, 16, 300)
adjacency[12][9] = (2, 38, 300)
adjacency[9][13] = (4, 17, 300)
adjacency[13][9] = (3, 39, 300)
adjacency[11][12] = (2, 18, 600)
adjacency[12][11] = (3, 40, 600)
adjacency[11][13] = (1, 19, 750)
adjacency[13][11] = (1, 41, 750)
adjacency[12][14] = (1, 20, 300)
adjacency[14][12] = (3, 42, 300)
adjacency[13][14] = (2, 21, 150)
adjacency[14][13] = (2, 43, 150)

adjacency[1][1] = (4, 44, 0)
adjacency[2][2] = (4, 45, 0)
adjacency[3][3] = (4, 46, 0)
adjacency[4][4] = (4, 47, 0)
adjacency[5][5] = (4, 48, 0)
adjacency[6][6] = (5, 49, 0)
adjacency[7][7] = (4, 50, 0)
adjacency[8][8] = (4, 51, 0)
adjacency[9][9] = (5, 52, 0)
adjacency[10][10] = (4, 53, 0)
adjacency[11][11] = (4, 54, 0)
adjacency[12][12] = (4, 55, 0)
adjacency[13][13] = (4, 56, 0)
adjacency[14][14] = (4, 57, 0)

HOST9_MAC = 'b6ac0a8b5277' # 201
HOST4_MAC = '16fa3d2131de' # 205


ETH = [('DMAC', 0, 48), ('SMAC', 48, 96), ('DL_TYPE', 96, 16)]

SOURCE_ROUTING_PROTOCOL = [('TTL', 112, 8), ('port', 120, 32)]

IPV4 = [('version', 112, 4), ('IHL', 116, 4), ('tos', 120, 8),
        ('total_length', 128, 16), ('id', 144, 16), ('flags_offset', 160, 16),
        ('ttl', 176, 8), ('protocol', 184, 8), ('checksum', 192, 16),
        ('sip', 208, 32), ('dip', 240, 32)]

UDP = [('src_port', 272, 16), ('dst_port', 288, 16), ('length', 304, 16), ('checksum', 320, 16)]

def _add_protocol(protocol_name, field_list):
    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])  # field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("protocol_name", match_field_list)

def add_protocol():
    ETH_SR = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('TTL', 8), ('port', 32)]
    _add_protocol('ETH_SR', ETH_SR)

    ETH_IPv4 = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('V', 4), ('IHL', 4), ('TOS', 8),
                ('total_length', 16), ('id', 16), ('flags_offset', 16), ('TTL', 8), ('protocol', 8), ('checksum', 16),
                ('SIP', 32), ('DIP', 32)]
    _add_protocol('ETH_IPv4', ETH_IPv4)

    ETH_ARP = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('HTYPE', 16), ('PTYPE', 16),
               ('HLEN', 8), ('PLEN', 8), ('OPER', 16), ('SHA', 48), ('SPA', 32), ('THA', 48), ('TPA', 32)]
    _add_protocol('ETH_ARP', ETH_ARP)

def install_dmac_match_entry(dpid, dmac, output_port, priority = 0):
    dmac_match = core.PofManager.get_field("DMAC")[0]
    dmac_matchx = core.PofManager.new_matchx(dmac_match, dmac, 'FFffFFffFFff')
    output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=output_port)
    ins = core.PofManager.new_ins_apply_actions([output])
    entry_id = core.PofManager.add_flow_entry(dpid, core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable'),[dmac_matchx],[ins],priority)
    return entry_id

class RecoveryDemo(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()
        self.del_entry_list = []
        self.del_backup_entry_list = []

    def _handle_PortStatus(self, event):
        if event.ofp.reason == 0:
            port_id = event.ofp.desc.port_id
            core.PofManager.set_port_of_enable(event.dpid, port_id)
        elif event.ofp.reason == 2:
            if event.ofp.desc.state == 4:
                # port live
                print "port live"
                for each_entry in self.del_backup_entry_list:
                    core.PofManager.delete_flow_entry(each_entry[0], \
                                                      core.PofManager.get_flow_table_id(event.dpid, 'FirstEntryTable'),\
                                                      each_entry[1])


            elif event.ofp.desc.state == 1:
                # link down
                print "link down"
                topo = EdgeWeightedDigraph()
                topo.addGraphFromDict(adjacency)
                topo_SPTs = DijkstraSP(topo, 4)
                #
                # self.del_backup_entry_list.append(install_dmac_match_entry(5, '1ad334cdd9f8', 1, priority=1))
                # self.del_backup_entry_list.append(install_dmac_match_entry(5, '1ad334cdd9f8', 3, priority=1))

                # self.del_backup_entry_list.append((5, install_dmac_match_entry(5, '1ad334cdd9f8', 1, priority=1)))
                # self.del_backup_entry_list.append((6, install_dmac_match_entry(6, '1ad334cdd9f8', 2, priority=1)))
                # self.del_backup_entry_list.append((3, install_dmac_match_entry(3, '1ad334cdd9f8', 1, priority=1)))
                # self.del_backup_entry_list.append((0xa, install_dmac_match_entry(0xa, '1ad334cdd9f8', 2, priority=1)))

                self.del_backup_entry_list.append((9, install_dmac_match_entry(9, HOST9_MAC, 5, priority=1)))
                self.del_backup_entry_list.append((12, install_dmac_match_entry(12, HOST9_MAC, 2, priority=1)))
                self.del_backup_entry_list.append((11, install_dmac_match_entry(11, HOST9_MAC, 2, priority=1)))
                self.del_backup_entry_list.append((4, install_dmac_match_entry(4, HOST9_MAC, 3, priority=1)))

                # self.del_backup_entry_list.append((7, install_dmac_match_entry(7, '7ad0974af76b', 2, priority=1)))
                # self.del_backup_entry_list.append((0xa, install_dmac_match_entry(0xa, '7ad0974af76b', 3, priority=1)))
                # self.del_backup_entry_list.append((3, install_dmac_match_entry(3, '7ad0974af76b', 2, priority=1)))
                # self.del_backup_entry_list.append((6, install_dmac_match_entry(6, '7ad0974af76b', 1, priority=1)))
                self.del_backup_entry_list.append((4, install_dmac_match_entry(4, HOST4_MAC, 4, priority=1)))
                self.del_backup_entry_list.append((11, install_dmac_match_entry(11, HOST4_MAC, 3, priority=1)))
                self.del_backup_entry_list.append((12, install_dmac_match_entry(12, HOST4_MAC, 3, priority=1)))
                self.del_backup_entry_list.append((9, install_dmac_match_entry(9, HOST4_MAC, 3, priority=1)))


    def _handle_ConnectionUp(self,event):
        core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('DMAC')[0]])
        core.PofManager.add_flow_table(event.dpid, 'JustForFlowMod', pof.OF_MM_TABLE, 6000, \
                                       [core.PofManager.get_field('SMAC')[0]])
        import time
        time.sleep(1)

        if event.dpid == 4:
            install_dmac_match_entry(4, HOST9_MAC, 2)
            install_dmac_match_entry(4, HOST4_MAC, 4)
        elif event.dpid == 5:
            self.del_entry_list.append(install_dmac_match_entry(5, HOST9_MAC, 3))
            self.del_entry_list.append(install_dmac_match_entry(5, HOST4_MAC, 2))
        elif event.dpid == 7:
            self.del_entry_list.append(install_dmac_match_entry(7, HOST9_MAC, 1))
            self.del_entry_list.append(install_dmac_match_entry(7, HOST4_MAC, 3))
        elif event.dpid == 8:
            install_dmac_match_entry(8, HOST9_MAC, 3)
            install_dmac_match_entry(8, HOST4_MAC, 1)
        elif event.dpid == 9:
            install_dmac_match_entry(9, HOST9_MAC, 5)
            install_dmac_match_entry(9, HOST4_MAC, 1)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if isinstance(packet.next, ipv4):
            if packet.next.dstip == IPAddr('10.0.0.1'):
                src_dpid = random.randint(1, 14)
                # dst_dpid = random.randint(1, 14)
                print "hello"

                topo = EdgeWeightedDigraph()
                topo.addGraphFromDict(adjacency)
                topo_SPTs = DijkstraSP(topo, src_dpid)
                # topo_SPTs.printG()
                # import time
                # time.sleep(1)

                dmac_match = core.PofManager.get_field("SMAC")[0]
                dmac_matchx = core.PofManager.new_matchx(dmac_match, '00ff00ff00ff', 'FFffFFffFFff')
                output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                           metadata_offset=0, \
                                                           metadata_length=0, \
                                                           packet_offset=0, \
                                                           port_id=2)
                ins = core.PofManager.new_ins_apply_actions([output])
                table_id = core.PofManager.get_flow_table_id(event.dpid, 'JustForFlowMod')

                entry_dmac_forwarding = pof.ofp_flow_mod(table_id=table_id, match_field_num = 1, \
                                                         instruction_num =1 , index=1)
                entry_dmac_forwarding.match_list.append(dmac_matchx)
                entry_dmac_forwarding.instruction_list.append(ins)

                event.connection.send(entry_dmac_forwarding)

def launch():
    core.registerNew(RecoveryDemo)
