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


TABLE_INIT_NUM = 350
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
receiver_num_list = [0 for i in range(14)]
sr_encap_table_count = [0 for i in range(14)]
group_match_table_count = [0 for i in range(14)]
fork_count_map = [0 for i in range(14)]

count = 0

switch_resource = {}
switch_fork_table_resource = {}



def port2hex(port):
    port_hex = hex(port)[2:]
    port_hex = (4 - len(port_hex)) * '0' + port_hex
    return port_hex

def gen_multi_address(ip):
    '''
    Generate multiple dst IP address.
    :param ip: must be a IPAddr instance.
    :return: multiple dst IP address list, dst_ip_list
    '''
    if isinstance(ip, IPAddr):
        dst_ip_list = []
        possible_ip_set = ipTable.keys()
        # for i in range(randint(2, 4)):
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

# def cut_branch(tree_adj, node):
#     if node in topo_adj.keys():
#         while tree_adj[node] in tree_adj.keys():
#             node = tree_adj[node]
#             del tree_adj[node]
#     else:
#         print "this node is not in this tree"

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
    #print 'tree:', tree

    path_dict = defaultdict(lambda: [])
    shortestleafpath = findShortestLeafNode(tree, src, dsts)
    split_nodes = findSplittingNodesInTree(tree, dsts)
    path_dict[src].append(shortestleafpath)
    # for node in split_nodes:
    #     if node in shortestleafpath:
    #         #node  must be in the shortestleafpath
    #         i = shortestleafpath.index(node)
    #         if i != (len(shortestleafpath) - 1):
    #             del tree[shortestleafpath[i]][shortestleafpath[i + 1]]
    #         for _ in range(len(tree[node].keys())):
    #             shortestleafpath = findShortestLeafNode(tree, node, dsts)
    #             path_dict[node].append(shortestleafpath)
    #     else:
    #         print 'node not in Primary Path'
        #     for _ in range(len(tree[node].keys())):
        #         shortestleafpath = findShortestLeafNode(tree, node, dsts)
        #         path_dict[node].append(shortestleafpath)

    for node in split_nodes:
        if len(tree[node].keys()) > 1:
            shortestleafpath = findShortestLeafNode(tree, node, dsts)
            # cut the shortest one since it has been used as the Primary path in higher nodes
            i = shortestleafpath.index(node)
            del tree[shortestleafpath[i]][shortestleafpath[i + 1]]
        shortestleafpath = findShortestLeafNode(tree, node, dsts)  # use 2ed shortest one
        path_dict[node].append(shortestleafpath)


    # for node in split_nodes:
    #     i = shortestleafpath.index(node)
    #     for _ in range(len(tree[node].keys())):
    #         # if node in shortestleafpath:
    #         if tree[shortestleafpath[i+1]] not in shortestleafpath:
    #             if i != (len(shortestleafpath)-1):
    #                 del tree[shortestleafpath[i]][shortestleafpath[i + 1]]
    #             # shortestleafpath = findShortestLeafNode(tree, node, dsts)
    #             # path_dict[node].append(shortestleafpath)
    #         # else:
    #                 shortestleafpath = findShortestLeafNode(tree, node, dsts)
    #                 path_dict[node].append(shortestleafpath)
    #             else:
    #                 # it is the last node in shortestleafpath,next hop is the a new path or host
    #                 pass

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
                            offset = ETH_HEADER_LEN + TTL_FIELD_LEN/8 + PORT_FIELD_LEN/8 * (len(path) - i - 1) # -1 is for one port field has been popped
                        offset_dict[fork_node] = offset
    return offset_dict


# def vportReplace(path_dict, src, vport):
#     '''
#
#     Args:
#         path_dict:
#         src:
#         vport:
#
#     Returns:
#
#
#
#     '''
#     fork_node_list = path_dict.keys()
#     fork_node_list.remove(src)
#     for each_fork_node in path_dict.keys():
#         for path in path_dict[each_fork_node]:
#             j = path_dict[each_fork_node].index(path)
#             for node in path:
#                 if node in fork_node_list:
#                     i = path.index(node)
#                     path_dict[each_fork_node][j][i] = vport
#     return path_dict


def cal_tree(src_dpid, dst_dpid_group):
    '''
    :param src_dpid:
    :param dst_ip: a multicast IP address
    :return: several branches of the multicast tree
    '''
    global topo
    steiner_tree = MinSteinerTree(topo, src_dpid, dst_dpid_group)
    splitting_nodes = steiner_tree.findSplittingNodes()
    # branch_list = steiner_tree.toBranches()[1]
    steiner_tree_adj = steiner_tree.toAdjacency()
    # steiner_tree.printG()
    # print 'splitting_nodes', splitting_nodes
    return toMulticastPathDict(steiner_tree_adj, src_dpid, dst_dpid_group)

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


class SourceRoutingMulticast(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()
        self.sw_num = 0
        self.has_packetin_list = []

    def _handle_ConnectionUp(self, event):
        switch_resource[event.dpid] = TABLE_INIT_NUM * (float(2)/5)
        switch_fork_table_resource[event.dpid] = TABLE_INIT_NUM * (float(3)/5)

        self.sw_num += 1
        if self.sw_num == 14:
            print "Ready to go!"

    def _handle_PacketIn(self, event):

        global total_entry_num
        global total_flow_num
        global reject_flow_num
        global total_flow_entry_num
        global avg_packet_overhead_pp
        global receiver_num_list
        global group_match_table_count
        global sr_encap_table_count
        global count
        global fork_count_map

        #print 'Number of receivers: ', receiver_num


        packet = event.parsed

        if isinstance(packet.next, ipv4):
            src_ip = packet.next.srcip
            dst_ip = packet.next.dstip
            # print src_ip.toStr()
            # print dst_ip.toStr()
            # print dst_ip==IPAddr('224.0.67.67')
            # print event.dpid

            eth_src = packet.src.toStr()
            eth_dst = packet.dst.toStr()
            # print eth_dst
            # print eth_src

            if isinstance(packet.next.next, udp):
                dst_port = packet.next.next.dstport
                src_port = packet.next.next.srcport
                #print src_ip,src_port

                if (src_ip,src_port) not in self.has_packetin_list:
                    self.has_packetin_list.append((src_ip,src_port))
                    total_flow_num += 1

                    # print event.dpid
                    dsts = gen_dpid_group(event.dpid)
                    #print 'dsts', dsts
                    for dst in dsts:
                        receiver_num_list[dst-1]+=1
                    #receiver_num += len(dsts)

                    #dsts = [1,6]
                    print '==========='
                    print 'src:', event.dpid

                    print 'dsts ', dsts
                    path_dict = cal_tree(event.dpid, dsts)
                    for j in path_dict.keys():
                        if j != event.dpid:
                            fork_count_map[j-1]+=1


                    print 'path_dict ',path_dict


                    if switch_resource[event.dpid] > 0:
                        # print '------'
                        # print 'src', event.dpid
                        path_available = True
                        for dpid in path_dict.keys():
                            # print 'dpid', dpid
                            if switch_fork_table_resource[dpid] <= 0:
                                path_available = False
                                break
                        # print '----'
                    else:
                        path_available = False

                    if path_available == True:

                        for dpid in path_dict.keys():
                            if dpid == event.dpid:
                                switch_resource[dpid] -= 1
                            else:
                                switch_fork_table_resource[dpid]-=1
                            total_flow_entry_num += 1

                        print 'Total number of handled flow: ', total_flow_num
                        print 'Number of rejected flow: ', reject_flow_num
                        print 'Reject rate: ', float(reject_flow_num) / total_flow_num
                        print 'Total number of flow entry:', total_flow_entry_num
                        print 'received flows each:', receiver_num_list, 'sum:',sum(receiver_num_list)
                        print 'group label match count:', group_match_table_count, 'sum:',sum(group_match_table_count)
                        print 'sr_encap_table count:', sr_encap_table_count,'sum:', sum(sr_encap_table_count)
                        print 'node fork count map', fork_count_map, 'sum:', sum(fork_count_map)
                        #print 'count:',count
                        print '--------'


                        vport, group_label = vport_gen()
                        # print 'path dict', path_dict
                        path_port_dict, fork_node_output_dict = toMulticastPathPortDict(path_dict, adjacency, vport,
                                                                                        event.dpid)
                        primary_path_output_dict = cal_pri_output_on_forknode(path_dict, path_port_dict)

                        # print 'vport', vport
                        # print 'path_port_dict', path_port_dict
                        # print 'fork_node_output_dict', fork_node_output_dict
                        # print 'primary path output dict', primary_path_output_dict

                        packet_offset_list = cal_offset_on_fork(path_dict, path_port_dict, event.dpid, dsts)
                        fork_node_list = path_port_dict.keys()
                        #print 'path_port_dict: ', path_port_dict
                        fork_node_list.remove(event.dpid)

                        for fork_node in fork_node_list:
                            if fork_node != event.dpid:
                                # print '--------', fork_node
                                # print 'output port:', primary_path_output_dict[fork_node]
                                # print 'new path port list', path_port_dict[fork_node]
                                # print 'new output port list', path_port_dict[fork_node][0]

                                output_port_cur = primary_path_output_dict[fork_node]

                                new_output_port_list_cur = fork_node_output_dict[fork_node]
                                # for path_port in path_port_dict[fork_node]:
                                #     new_output_port_list_cur.append(path_port.pop(0))

                                new_path_port_list_cur = path_port_dict[fork_node]
                                packet_offset = packet_offset_list[fork_node]
                                # print 'packet_offset', packet_offset

                                # output_port_cur
                                # new_output_port_list_cur.pop(0)
                                # new_path_port_list_cur.pop(0)

                                for each_path_port, each_path in zip(path_port_dict[fork_node], path_dict[fork_node]):
                                    each_path_port.pop(0)
                                    if each_path[-1] in fork_node_list:
                                        each_path_port.append(vport)
                                    else:
                                        each_path_port.append(len(adjacency[each_path[-1]].keys()))

                                # TODO: Bugs here, flow entry installed less then expected
                                install_grouplabel_entry(dpid=fork_node, \
                                                         group_label=group_label, \
                                                         output_port=output_port_cur, \
                                                         new_path_port_list=new_path_port_list_cur, \
                                                         new_output_port_list=new_output_port_list_cur, \
                                                         pkt_offset=packet_offset)

                                group_match_table_count[fork_node-1] +=1
                                print 'fork node', fork_node
                                print 'output port primary:', output_port_cur
                                print 'new path port list:', new_path_port_list_cur
                                print 'new output port list cur:', new_output_port_list_cur
                                print 'packet offset', packet_offset

                        # install flow entry to src ingress node
                        port_list = path_port_dict[event.dpid]
                        for each_path_port, each_path in zip(port_list, path_dict[event.dpid]):
                            # print 'each', each_path_port, each_path
                            each_path_port.pop(0)
                            if each_path[-1] in fork_node_list:
                                last_hop_outport = vport  # fork node and the dst node
                                each_path_port.append(last_hop_outport)
                            else:
                                each_path_port.append(len(adjacency[each_path[-1]].keys()))

                        output_port_list_at_src = []
                        for each_path in path_dict[event.dpid]:
                            port = adjacency[each_path[0]][each_path[1]][0]
                            # port = vport
                            output_port_list_at_src.append(port)

                        # print 'output_port_list:', output_port_list_at_src
                        # print 'port_list:', port_list
                        ip_addr_hex = ip2hex(packet.next.srcip.toStr())
                        entry_id = encap_sr_header_by_sip_sport_multicast(dpid=event.dpid, \
                                                                      sip = ip_addr_hex,\
                                                                      sport=port2hex(src_port), \
                                                                      output_port_list=output_port_list_at_src, \
                                                                      port_list_group=port_list)
                        sr_encap_table_count[event.dpid-1]+=1

        # if event.dpid == 0xd:
        #     print event.dpid
        #     # dsts = gen_dpid_group()
        #     dsts = [11, 2]
        #     if event.dpid in dsts:
        #         dsts.remove(event.dpid)
        #     print 'dsts', dsts
        #     path_dict = cal_tree(event.dpid, dsts)
        #     vport = vport_gen()
        #     print 'path dict', path_dict
        #     path_port_dict, fork_node_output_dict = toMulticastPathPortDict(path_dict, adjacency, vport, event.dpid)
        #     primary_path_output_dict = cal_pri_output_on_forknode(path_dict, path_port_dict)
        #
        #     print 'vport', vport
        #     print 'path_port_dict', path_port_dict
        #     print 'fork_node_output_dict', fork_node_output_dict
        #     print 'primary path output dict', primary_path_output_dict
        #
        #     packet_offset_list = cal_offset_on_fork(path_dict, path_port_dict, event.dpid, dsts)
        #     fork_node_list = path_port_dict.keys()
        #     fork_node_list.remove(event.dpid)
        #     for fork_node in fork_node_list:
        #         if fork_node != event.dpid:
        #             print '--------', fork_node
        #             print 'output port:', primary_path_output_dict[fork_node]
        #             print 'new path port list', path_port_dict[fork_node]
        #             print 'new output port list', path_port_dict[fork_node][0]
        #
        #             output_port_cur = primary_path_output_dict[fork_node]
        #
        #             new_output_port_list_cur = []
        #             for path_port in path_port_dict[fork_node]:
        #
        #                 new_output_port_list_cur.append(path_port.pop(0))
        #
        #             new_path_port_list_cur = path_port_dict[fork_node]
        #             packet_offset = packet_offset_list[fork_node]
        #             print 'packet_offset', packet_offset
        #
        #
        #             # output_port_cur
        #             # new_output_port_list_cur.pop(0)
        #             # new_path_port_list_cur.pop(0)
        #
        #             print '======='
        #             print 'output port:', output_port_cur
        #             print 'new path port list', new_path_port_list_cur
        #             print 'new output port list', new_output_port_list_cur
        #
        #             install_grouplabel_entry(dpid=fork_node, \
        #                                      group_label="fffe", \
        #                                      output_port=output_port_cur, \
        #                                      new_path_port_list=new_path_port_list_cur, \
        #                                      new_output_port_list=new_output_port_list_cur, \
        #                                      pkt_offset=packet_offset)
        #
        #     # install flow entry to src ingress node
        #     ip_addr_hex = ip2hex(IPAddr('192.168.109.120').toStr())
        #     src_port = 2222
        #
        #
        #     port_list = path_port_dict[event.dpid]
        #     for each_port, each_path in zip(port_list, path_dict[event.dpid]):
        #         print 'each', each_port, each_path
        #         each_port.pop(0)
        #         last_hop_outport = len(adjacency[each_path[-1]].keys())
        #         each_port.append(last_hop_outport)
        #
        #     output_port_list_at_src = []
        #     for each_path in path_dict[event.dpid]:
        #         port = adjacency[each_path[0]][each_path[1]][0]
        #         output_port_list_at_src.append(port)
        #
        #     print 'output_port_list:', output_port_list_at_src
        #     print 'port_list:', port_list
        #     entry_id = encap_sr_header_by_sport_multicast(dpid=event.dpid,\
        #                                                   sport='0001',\
        #                                                   output_port_list= output_port_list_at_src,\
        #                                                   port_list_group= port_list)
        #
        #
        #     #
        #     # entry_id = encap_sr_header_by_dip_sport_w_pktout(dpid=event.dpid, \
        #     #                                                  dip=ip_addr_hex, \
        #     #                                                  dip_mask='FFffFFff', \
        #     #                                                  sport=port2hex(src_port), \
        #     #                                                  sport_mask='FFff', \
        #     #                                                  output_port=first_hop_outport, \
        #     #                                                  port_list=port_list, \
        #     #                                                  event=event, \
        #     #                                                  out_dpid=last_hop)

                    else:
                        reject_flow_num += 1
                        ip_addr_hex = ip2hex(packet.next.srcip.toStr())
                        encap_sr_header_by_sip_sport_drop(event.dpid, ip_addr_hex, port2hex(src_port), 'FFff')



def launch():
    core.registerNew(SourceRoutingMulticast)
