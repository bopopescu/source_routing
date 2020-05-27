'''
Created on 2016.6.1.

@author: shengrulee
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libpof_02 as pof

import time
from Queue import PriorityQueue
import math
import random

from digraph import *
from source_routing import *

log = core.getLogger()

TABLE_INIT_NUM = 50
FLOW_HOLDTIME = 1200
# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))

# switch adjacency
# adjacency[1][2] = (2, 0, 1)  # (port,link_id,weight)
# adjacency[2][1] = (2, 1, 1)
# adjacency[2][3] = (3, 2, 1)
# adjacency[3][2] = (2, 3, 1)
# adjacency[3][4] = (3, 4, 1)
# adjacency[4][3] = (2, 5, 1)

# six node topo
#adjacency[1][2] = (1, 0, 1)  # (port,link_id,weight)
#adjacency[2][1] = (1, 1, 1)  # (port,link_id,weight)
# adjacency[2][3] = (3, 2, 1)  # (port,link_id,weight)
# adjacency[3][2] = (3, 3, 1)  # (port,link_id,weight)
# adjacency[3][4] = (1, 4, 1)  # (port,link_id,weight)
# adjacency[4][3] = (1, 5, 1)  # (port,link_id,weight)
# adjacency[4][5] = (2, 6, 1)  # (port,link_id,weight)
# adjacency[5][4] = (3, 7, 1)  # (port,link_id,weight)
# adjacency[5][6] = (1, 8, 1)  # (port,link_id,weight)
# adjacency[6][5] = (3, 9, 1)  # (port,link_id,weight)
# adjacency[6][1] = (1, 10, 1)  # (port,link_id,weight)
# adjacency[1][6] = (2, 11, 1)  # (port,link_id,weight)
# adjacency[2][6] = (2, 12, 1)  # (port,link_id,weight)
# adjacency[6][2] = (2, 13, 1)  # (port,link_id,weight)
# adjacency[3][5] = (2, 14, 1)  # (port,link_id,weight)
# adjacency[5][3] = (2, 15, 1)  # (port,link_id,weight)
# adjacency[1][1] = (3, 16, 0)
# adjacency[2][2] = (4, 17, 0)
# adjacency[3][3] = (4, 18, 0)
# adjacency[4][4] = (3, 19, 0)
# adjacency[5][5] = (4, 20, 0)
# adjacency[6][6] = (4, 21, 0)

# 14 node nsfnet
adjacency[1][2] = (3, 0, 1050)
adjacency[2][1] = (3, 22, 1050)
adjacency[1][3] = (1, 2, 1500)
adjacency[3][1] = (1, 24, 1500)
adjacency[1][8] = (2, 3, 2400)
adjacency[8][1] = (2, 25, 2400)
adjacency[2][3] = (1, 1, 600)
adjacency[3][2] = (2, 23, 600)
adjacency[2][4] = (2, 4, 750)
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

# ip table
ipTable = defaultdict(lambda: defaultdict(lambda: None))
# ipTable[IPAddr('10.0.0.1')] = (1, 1)  # (dpid, port)
# ipTable[IPAddr('10.0.0.2')] = (2, 1)
# ipTable[IPAddr('10.0.0.3')] = (3, 1)
# ipTable[IPAddr('10.0.0.4')] = (4, 1)

# six node topo
# ipTable[IPAddr('10.1.0.0')] = (1, 3)  # (dpid, port)
# ipTable[IPAddr('10.2.0.0')] = (2, 4)  # (dpid, port)
# ipTable[IPAddr('10.3.0.0')] = (3, 4)
# ipTable[IPAddr('10.4.0.0')] = (4, 3)
# ipTable[IPAddr('10.5.0.0')] = (5, 4)
# ipTable[IPAddr('10.6.0.0')] = (6, 4)

# 14 Node NSFNET
ipTable[IPAddr('10.0.0.1')] = (1, 4)
ipTable[IPAddr('10.0.0.2')] = (2, 4)
ipTable[IPAddr('10.0.0.3')] = (3, 4)
ipTable[IPAddr('10.0.0.4')] = (4, 1)
ipTable[IPAddr('10.0.0.5')] = (5, 4)
ipTable[IPAddr('10.0.0.6')] = (6, 5)
ipTable[IPAddr('10.0.0.7')] = (7, 4)
ipTable[IPAddr('10.0.0.8')] = (8, 4)
ipTable[IPAddr('10.0.0.9')] = (9, 2)
ipTable[IPAddr('10.0.0.10')] = (10, 4)
ipTable[IPAddr('10.0.0.11')] = (11, 4)
ipTable[IPAddr('10.0.0.12')] = (12, 4)
ipTable[IPAddr('10.0.0.13')] = (13, 4)
ipTable[IPAddr('10.0.0.14')] = (14, 4)


topo = EdgeWeightedDigraph()
topo.addGraphFromDict(adjacency)
# topo.printG()
#
# src = 6
# dst = 2


topo_SPTs = DijkstraAllPairSP(topo)
# print topo_SPTs.path(src, dst)
# six_node_SP = DijkstraSP(six_node_graph, src)
# print
# print '--------------'
switch_resource = {}

# statistic var
total_entry_num = 0
total_flow_num = 0
reject_flow_num = 0
total_flow_entry_num = 0
avg_packet_overhead_pp = 0

# openflow statistic var
of_total_entry_num = 0
of_total_flow_num = 0
of_reject_flow_num = 0
of_total_flow_entry_num = 0
of_avg_packet_overhead_pp = 0

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

    ETH_IPv4_UDP = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('V', 4),('IHL', 4), ('TOS', 8),
         ('total_length', 16), ('id', 16), ('flags_offset', 16), ('TTL', 8), ('protocol', 8), ('checksum', 16),
         ('SIP', 32), ('DIP', 32), ('SPORT', 16), ('DPORT', 16), ('LEN', 16), ('UDPChecksum', 16)]
    _add_protocol('ETH_IPv4_UDP', ETH_IPv4_UDP)

    ETH_ARP = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('HTYPE', 16), ('PTYPE',16),
               ('HLEN', 8), ('PLEN', 8), ('OPER', 16), ('SHA', 48), ('SPA', 32), ('THA', 48), ('TPA', 32)]
    _add_protocol('ETH_ARP', ETH_ARP)

def check_ip_prefix(ip, ip_table):
    if isinstance(ip, IPAddr):
        for each_net in ip_table.keys():
            if ip.in_network(each_net, 16):
                return each_net
        return False

def port2hex(port):
    port_hex = hex(port)[2:]
    port_hex = (4 - len(port_hex)) * '0' + port_hex
    return port_hex


def drop():
    pass

def cal_route(src_dpid, dst_ip):  # for source routing
    global adjacency
    global ipTable
    global topo_SPTs

    dst_dpid = ipTable[dst_ip][0]
    out_port = ipTable[dst_ip][1]

    path_list = topo_SPTs.path(src_dpid, dst_dpid)[0]
    first_hop_outport = adjacency[path_list[0]][path_list[1]][0]

    port_list = []
    for i in xrange(1, len(path_list)-1):
        port = adjacency[path_list[i]][path_list[i+1]][0]

        port_list.append(port)
    port_list.append(out_port)

    return first_hop_outport, port_list, path_list

def cal_path(src_dpid, dst_ip):  # for ip forwarding
    global adjacency
    global ipTable
    global topo_SPTs

    dst_dpid = ipTable[dst_ip][0]
    out_port = ipTable[dst_ip][1]
    path_list = topo_SPTs.path(src_dpid, dst_dpid)[0]
    port_list = []
    for i in xrange(0, len(path_list) - 1):
        port = adjacency[path_list[i]][path_list[i + 1]][0]
        port_list.append(port)
    port_list.append(out_port)

    return port_list, path_list

def expntl(L):
    """
    negative exponential distribution
    return a double random number, L is the mean value
    """
    u = random.random()
    return -L * math.log(u)

def _install_type_match_entry(dpid, dl_type, next_table_id): # First Table
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    match = core.PofManager.get_field('DL_TYPE')[0]
    temp_matchx = core.PofManager.new_matchx(match, dl_type, 'FFFF')
    temp_ins = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [temp_ins], 0, False)

def install_arp_target_ip_match_entry(dpid, target_ip, output_port):
    target_ip_match = core.PofManager.get_field('TPA')[0]
    target_ip_matchx = core.PofManager.new_matchx(target_ip_match, target_ip, 'FFffFFff')

    table_id = core.PofManager.get_flow_table_id(dpid, 'ARPTargetIPTable')
    action_output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0,\
                                                      port_id = output_port)
    ins_action = core.PofManager.new_ins_apply_actions([action_output])
    core.PofManager.add_flow_entry(dpid, table_id, [target_ip_matchx], [ins_action], 0, False)

def install_dip_entry(dpid, dip, output_port):
    table_id = core.PofManager.get_flow_table_id(dpid, 'DIP_TABLE')
    dip_match = core.PofManager.get_field('DIP')[0]
    dip_matchx = core.PofManager.new_matchx(dip_match, dip, 'FFffFFff')

    output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                metadata_offset=0, \
                                                metadata_length=0, \
                                                packet_offset=0,\
                                                port_id = output_port)
    apply_action = core.PofManager.new_ins_apply_actions([output])
    core.PofManager.add_flow_entry(dpid, table_id, [dip_matchx], [apply_action], 0, False)


class Perhop(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()
        self.in_service_flow = PriorityQueue()
        self.has_packetin_flow_list = []
        self.has_packetin_arp = []
        self.duplicated_packetin_counter = 0

    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        core.PofManager.set_port_of_enable(event.dpid, port_id)

    def _handle_ConnectionUp(self, event):

        core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('DL_TYPE')[0]])
        arp_table = core.PofManager.add_flow_table(event.dpid, 'ARPTargetIPTable', pof.OF_MM_TABLE, 1000, \
                                       [core.PofManager.get_field('TPA')[0]])
        dip_table = core.PofManager.add_flow_table(event.dpid, 'DIP_TABLE', pof.OF_MM_TABLE, 3000, \
                                       [core.PofManager.get_field('DIP')[0]])

        time.sleep(1)
        _install_type_match_entry(event.dpid, '0806', arp_table)
        _install_type_match_entry(event.dpid, '0800', dip_table)

    def _handle_PacketIn(self, event):
        global total_entry_num
        global total_flow_num
        global reject_flow_num
        global total_flow_entry_num
        global avg_packet_overhead_pp

        global ipTable

        packet = event.parsed
        if isinstance(packet.next, ipv4):

            # dst_ip_net = check_ip_prefix(packet.next.dstip, ipTable)

            if packet.next.dstip in ipTable.keys():

                ip_addr_hex = ip2hex(packet.next.dstip.toStr())

                first_hop_outport, port_list, path_list = cal_route(event.dpid, packet.next.dstip)
                last_hop = path_list[-1]

                log.info('path: %s' % path_list)
                log.info('output port: %s' % port_list)

                install_dip_entry(event.dpid, ip_addr_hex, first_hop_outport)

                for dpid, port in zip(path_list[1:], port_list):
                    install_dip_entry(dpid, ip_addr_hex, port)

        elif isinstance(packet.next, arp):
            log.info(packet.next._to_str())
            ip_addr_hex = ip2hex(packet.next.protodst.toStr())
            # target_ip_net = check_ip_prefix(packet.next.protodst, ipTable)

            if (packet.src, packet.next.protodst) not in self.has_packetin_arp:

                if packet.next.protodst in ipTable.keys():
                    # if target_ip_net:
                    self.has_packetin_arp.append((packet.src, packet.next.protodst))

                    port_list, path_list = cal_path(event.dpid, packet.next.protodst)
                    print 'port list', port_list
                    print 'path list', path_list
                    for dpid, port in zip(path_list, port_list):
                        install_arp_target_ip_match_entry(dpid, ip_addr_hex, port)

                    # reverse path flow entry
                    port_list_rev, path_list_rev = cal_path(path_list[-1], packet.next.protosrc)
                    ip_addr_hex_rev = ip2hex(packet.next.protosrc.toStr())
                    print 'port list reverse', port_list_rev
                    print 'path list reverse', path_list_rev
                    for dpid, port in zip(path_list_rev, port_list_rev):
                        install_arp_target_ip_match_entry(dpid, ip_addr_hex_rev, port)

                else:
                    log.info('Request IP address unreachable!')
            else:
                log.info('Already packetin')

        elif isinstance(packet.next, ipv6):
            drop()


def launch():
    core.registerNew(Perhop)


if __name__ == '__main__':
    print check_ip_prefix(IPAddr('10.1.113.23'), ipTable)

