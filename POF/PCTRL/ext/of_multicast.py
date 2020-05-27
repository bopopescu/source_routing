'''
Created on 2016.6.19.

@author: shengrulee

To serve a multicast flow by splitting tree to several branches.
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libpof_02 as pof

from random import randint
from random import sample
from copy import deepcopy, copy

from digraph import *
from source_routing_mc import *


TABLE_INIT_NUM = 100
FLOW_HOLDTIME = 1200

log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))

# switch adjacency
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
# six node topo
ipTable[IPAddr('172.16.0.1')] = (1, 3)  # (dpid, port)
ipTable[IPAddr('172.16.0.2')] = (2, 4)  # (dpid, port)
ipTable[IPAddr('172.16.0.3')] = (3, 4)
ipTable[IPAddr('172.16.0.4')] = (4, 3)
ipTable[IPAddr('172.16.0.5')] = (5, 4)
ipTable[IPAddr('172.16.0.6')] = (6, 4)

ip_multicast = IPAddr('224.0.0.1')

topo = EdgeWeightedDigraph()
topo.addGraphFromDict(adjacency)
# topo.printG()
# topo_SPTs = DijkstraAllPairSP(topo)

# statistic var
total_entry_num = 0
total_flow_num = 0
reject_flow_num = 0
total_flow_entry_num = 0
avg_packet_overhead_pp = 0
receiver_num = 0

count  = 0

switch_resource = {}
switch_fork_table_resource = {}

fork_count_map = [0 for _ in range(14)]

def _add_protocol(protocol_name, field_list):
    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])  # field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("protocol_name", match_field_list)


def add_protocol():

    ETH_IPv4 = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('V', 4), ('IHL', 4), ('TOS', 8),
                ('total_length', 16), ('id', 16), ('flags_offset', 16), ('TTL', 8), ('protocol', 8), ('checksum', 16),
                ('SIP', 32), ('DIP', 32)]
    _add_protocol('ETH_IPv4', ETH_IPv4)

    ETH_IPv4_UDP = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('V', 4), ('IHL', 4), ('TOS', 8),
                    ('total_length', 16), ('id', 16), ('flags_offset', 16), ('TTL', 8), ('protocol', 8),
                    ('checksum', 16),
                    ('SIP', 32), ('DIP', 32), ('SPORT', 16), ('DPORT', 16), ('LEN', 16), ('UDPChecksum', 16)]
    _add_protocol('ETH_IPv4_UDP', ETH_IPv4_UDP)

    ETH_ARP = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('HTYPE', 16), ('PTYPE', 16),
               ('HLEN', 8), ('PLEN', 8), ('OPER', 16), ('SHA', 48), ('SPA', 32), ('THA', 48), ('TPA', 32)]
    _add_protocol('ETH_ARP', ETH_ARP)

def port2hex(port):
    port_hex = hex(port)[2:]
    port_hex = (4 - len(port_hex)) * '0' + port_hex
    return port_hex

def ip2hex(ip_addr):
    ip_list = ip_addr.split('.')
    # print ip_list
    ip_hex = ''
    for each in ip_list:
        each_hex = hex(int(each))
        each_hex = each_hex[2:]
        if len(each_hex) == 1:
            each_hex = '0' + each_hex
        # print each_hex
        ip_hex = ip_hex + each_hex
        # print ip_hex
    return ip_hex

def gen_multi_address(ip):
    '''
    Generate multiple dst IP address.
    :param ip: must be a IPAddr instance.
    :return: multiple dst IP address list, dst_ip_list
    '''
    if isinstance(ip, IPAddr):
        dst_ip_list = []
        possible_ip_set = ipTable.keys()
        # for i in range(randint(1, 3)):
        for i in range(3):
            #print len(possible_ip_set)
            dst_ip = possible_ip_set[randint(0, len(possible_ip_set)-1)]
            dst_ip_list.append(dst_ip)
            possible_ip_set.remove(dst_ip)

        return dst_ip_list
    else:
        raise TypeError('%s is not an IPAddr instance' % ip)

def gen_dpid_group(src):
    group_size = randint(2,3)
    candidate_list = adjacency.keys()
    candidate_list.remove(src)
    return sample(candidate_list, group_size)

def cut_branch(tree_adj, node):
    if node in topo_adj.keys():
        while tree_adj[node] in tree_adj.keys():
            node = tree_adj[node]
            del tree_adj[node]
    else:
        print "this node is not in this tree"

def findSplittingNodesInTree(adj, dsts):
    splitting_nodes = []
    for each in adj.keys():
        if len(adj[each]) > 1:
            # spliting node
            splitting_nodes.append(each)
        elif len(adj[each]) == 1:
            if each in dsts:
                splitting_nodes.append(each)

    return splitting_nodes


def toMulticastPathDict (tree, src, dsts):
    '''
    Returns:
    eg.
    defaultdict(<function <lambda> at 0x1028aef50>, {1: [[2, 3, 6]], 2: [[4, 7], [5, 9]], 5: [[10, 11]], 6: [[16]]})
    '''
    path_dict = defaultdict(lambda: [])
    shortestleafpath = findShortestLeafNode(tree, src, dsts)
    split_nodes = findSplittingNodesInTree(tree, dsts)
    path_dict[src].append(shortestleafpath)

    for node in split_nodes:
        if len(tree[node].keys()) > 1:
            shortestleafpath = findShortestLeafNode(tree, node, dsts)
            # cut the shortest one since it has been used as the Primary path in higher nodes
            i = shortestleafpath.index(node)
            del tree[shortestleafpath[i]][shortestleafpath[i + 1]]
        shortestleafpath = findShortestLeafNode(tree, node, dsts)  # use 2ed shortest one
        path_dict[node].append(shortestleafpath)

    return path_dict

def toMulticastPathPortDict(path_dict, adj, vport, src):
    '''

    Args:
        path_dict: {1: [[1, 2, 3, 6]], 2: [[2, 4, 7], [2, 5, 9]], 5: [[5, 10, 11]], 6: [[6, 16]]}
        adj:
        vport:

    Returns:
        {1: [[2, 1, 3]], 2: [[1, 2], [1, 1]], 5: [[1, 1]], 6: [[1]]}

    '''
    fork_node_list = path_dict.keys()
    fork_node_list.remove(src)
    path_port_dict = {}
    fork_node_output_dict = defaultdict(lambda: [])

    for encap_node in path_dict.keys():
        path_port_list = []
        for path in path_dict[encap_node]:
            port_list = []
            for i in range(len(path)-1):
                if path[i] not in fork_node_list:
                    port = adj[path[i]][path[i+1]][0]

                else:
                    port = vport
                    # port = adj[path[i]][path[i + 1]][0]
                    fork_node_output_dict[path[i]].append(adj[path[i]][path[i+1]][0])
                port_list.append(port)  # port_list include the output port on fork node
            path_port_list.append(port_list)
        path_port_dict[encap_node] = path_port_list
    return path_port_dict, fork_node_output_dict


def cal_offset_on_fork(path_dict, path_port_dict, src, dsts):
    offset_dict = {}
    for fork_node in path_dict.keys():
        if fork_node != src:
            # print fork_node
            # offset_dict[fork_node] = []
            for node in path_dict.keys():
                for path in path_dict[node]:
                    if fork_node in path[1:]:
                        if fork_node in dsts:
                            offset = ETH_HEADER_LEN
                        else:
                            i = path.index(fork_node)
                            offset = ETH_HEADER_LEN + TTL_FIELD_LEN/8 + PORT_FIELD_LEN/8 * (len(path) - i)
                        offset_dict[fork_node] = offset
    return offset_dict

def cal_tree(src_dpid, dst_dpid_group):
    '''
    :param src_dpid:
    :param dst_ip: a multicast IP address
    :return: several branches of the multicast tree
    '''
    global topo
    steiner_tree = MinSteinerTree(topo, src_dpid, dst_dpid_group)
    steiner_tree_adj = steiner_tree.toAdjacency()
    steiner_tree.printG()
    # print 'splitting_nodes', splitting_nodes
    return steiner_tree_adj

def cal_pri_output_on_forknode(path_dict, path_port_dict):
    global adjacency

    pri_port_dict = {}
    for fork_node in path_dict.keys():
        for path in path_dict[fork_node]:
            for node in path[1:]:
                if node in path_dict.keys():
                    i= path.index(node)
                    # if i < len(path)-1:
                    #     pri_port_dict[node] = adjacency[path[i]][path[i+1]]
                    try:
                        pri_port_dict[node] = adjacency[path[i]][path[i+1]][0]
                    except:
                        pri_port_dict[node] = len(adjacency[node].keys())
    return pri_port_dict


def vport_gen():
    prefix = 0x8000
    group_label = randint(1, 4095)
    return (prefix + group_label), str(hex(group_label))[2:]

class SteinerTreeExt(MinSteinerTree):
    def toShortestLeaf(self, src):
        adj = self.toAdjacency()
        SteinerTreeGraph = EdgeWeightedDigraph.addGraphFromDict(adj)
        shortest_leaf = DijkstraAllPairSP(SteinerTreeGraph)

def install_sport_entry(dpid, sip, sport, output_port_list):
    table_id = core.PofManager.get_flow_table_id(dpid, 'SIP_SPORT_Match')
    match_sport = core.PofManager.get_field('SPORT')[0]
    temp_matchx = core.PofManager.new_matchx(match_sport, port2hex(sport), 'FFff')

    match_sip = core.PofManager.get_field('SIP')[0]
    matchx_sip = core.PofManager.new_matchx(match_sip, ip2hex(sip.toStr()), 'FFffFFff')

    action_list= []
    for port in output_port_list:
        # print 'port', port
        output_action = core.PofManager.new_action_output(port_id_value_type=0, \
                                                          metadata_offset=0, \
                                                          metadata_length=0, \
                                                          packet_offset=0, \
                                                          port_id=port, \
                                                          port_id_field=None)
        action_list.append(output_action)
    ins = core.PofManager.new_ins_apply_actions(action_list)
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_sip,temp_matchx], [ins], 0, False)

def install_sip_sport_drop_entry(dpid,sip,sport):
    table_id = core.PofManager.get_flow_table_id(dpid, 'SIP_SPORT_Match')
    match_sport = core.PofManager.get_field('SPORT')[0]
    temp_matchx = core.PofManager.new_matchx(match_sport, port2hex(sport), 'FFff')

    match_sip = core.PofManager.get_field('SIP')[0]
    matchx_sip = core.PofManager.new_matchx(match_sip, ip2hex(sip.toStr()), 'FFffFFff')
    drop_action = core.PofManager.new_action_drop(0)
    ins = core.PofManager.new_ins_apply_actions([drop_action])
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_sip, temp_matchx], [ins])

class OfMulticast(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()

        self.sw_num = 0
        self.has_packetin_list = []

    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        core.PofManager.set_port_of_enable(event.dpid, port_id)

    def _handle_ConnectionUp(self, event):
        switch_resource[event.dpid] = TABLE_INIT_NUM/2 # posr
        switch_fork_table_resource[event.dpid] = TABLE_INIT_NUM/2 #posr

        # core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', pof.OF_EM_TABLE, 3000, \
        #                                [core.PofManager.get_field('SIP')[0], core.PofManager.get_field('SPORT')[0]])

        core.PofManager.add_flow_table(event.dpid, 'TypeMatch', pof.OF_MM_TABLE, 2, \
                                       [core.PofManager.get_field('DL_TYPE')[0]])

        core.PofManager.add_flow_table(event.dpid, 'SIP_SPORT_Match', pof.OF_EM_TABLE, 3000, \
                                       [core.PofManager.get_field('SIP')[0], core.PofManager.get_field('SPORT')[0]])

        import time
        time.sleep(1)

        table_id = core.PofManager.get_flow_table_id(event.dpid, 'TypeMatch')
        match = core.PofManager.get_field('DL_TYPE')[0]
        temp_matchx = core.PofManager.new_matchx(match, '0800', 'FFFF')
        next_table_id = core.PofManager.get_flow_table_id(event.dpid, 'SIP_SPORT_Match')
        temp_ins = core.PofManager.new_ins_goto_table(event.dpid, next_table_id)
        core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins], 0, False)

        self.sw_num += 1
        if self.sw_num == 14:
            print "Ready to go!"

    def _handle_PacketIn(self, event):

        global total_entry_num
        global total_flow_num
        global reject_flow_num
        global total_flow_entry_num
        global avg_packet_overhead_pp
        global adjacency
        global receiver_num

        global fork_count_maps

        global switch_fork_table_resource #posr


        packet = event.parsed

        if isinstance(packet.next, ipv4):
            src_ip = packet.next.srcip
            dst_ip = packet.next.dstip

            eth_src = packet.src.toStr()
            eth_dst = packet.dst.toStr()
            # print eth_dst
            # print eth_src

            if isinstance(packet.next.next, udp):
                dst_port = packet.next.next.dstport
                src_port = packet.next.next.srcport

                if (src_ip, src_port) not in self.has_packetin_list:
                    total_flow_num += 1

                    print 'Total number of handled flow: ', total_flow_num
                    print 'Number of rejected flow: ', reject_flow_num
                    print 'Reject rate: ', float(reject_flow_num) / total_flow_num
                    print 'Total number of flow entry:', total_flow_entry_num
                    print 'fork node map:', fork_count_map, 'sum:', sum(fork_count_map)
                    print '--------'

                    self.has_packetin_list.append((src_ip, src_port))
                    # print 'udp src port', src_port

                    # dsts = [11, 2]
                    dsts = gen_dpid_group(event.dpid)
                    receiver_num+=len(dsts)
                    print receiver_num

                    #print dsts
                    global count

                    if event.dpid in dsts:
                        count +=1
                    print 'count', count


                    global topo
                    steiner_tree = MinSteinerTree(topo, event.dpid, dsts)
                    steiner_tree_adj = steiner_tree.toAdjacency()
                    # steiner_tree.printG()


                    path_available = True
                    for each_edge in steiner_tree.SteinerEdges():
                        if switch_resource[each_edge.v] <= 0 or switch_resource[each_edge.w] <= 0:
                            path_available = False
                            break

                    fork_nodes = steiner_tree.findSplittingNodes()
                    for f in fork_nodes:
                        if f != event.dpid:
                            fork_count_map[f - 1] += 1
                            switch_fork_table_resource[f] -= 1  # posr
                    #posr
                    path_available = False
                    if switch_resource[event.dpid] > 0:
                        # print '------'
                        # print 'src', event.dpid
                        path_available = True
                        for dpid in fork_nodes:
                            # print 'dpid', dpid
                            if switch_fork_table_resource[dpid] <= 0:
                                path_available = False
                                break

                    if path_available:
                        switch_resource[event.dpid]-=1

                        leafnodes= []

                        for each_edge in steiner_tree.SteinerEdges():
                            # print each_edge.v, '-->', each_edge.w
                            output_port_list = []
                            if each_edge.v not in fork_nodes:
                                # install flow table with 1 output port
                                output_port_list.append(adjacency[each_edge.v][each_edge.w][0])
                            else:
                                for each_next_hop in steiner_tree_adj[each_edge.v].keys():
                                    # output_port = adjacency[each_edge.v][each_edge.w][0]
                                    output_port = adjacency[each_edge.v][each_next_hop][0]
                                    #print 'v-w',each_edge.v, each_next_hop
                                    output_port_list.append(output_port)

                            if each_edge.v in dsts:
                                output_port_list.append(len(adjacency[each_edge.v].keys()))

                            install_sport_entry(each_edge.v, src_ip, src_port, output_port_list)

                            #switch_resource[each_edge.v] -= 1  #posr
                            #total_flow_entry_num += 1  #posr

                            if len(steiner_tree_adj[each_edge.w].keys()) == 0:
                                leafnodes.append(each_edge.w)

                        for each_leaf in leafnodes:
                            install_sport_entry(each_leaf, src_ip, src_port, [len(adjacency[each_leaf].keys())])
                            #switch_resource[each_edge.v] -= 1 #posr
                            #total_flow_entry_num += 1 #posr

                    else:
                        reject_flow_num += 1
                        install_sip_sport_drop_entry(event.dpid, src_ip, src_port)


def launch():
    core.registerNew(OfMulticast)
