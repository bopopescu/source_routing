'''
Created on 2016.6.19.

@author: shengrulee

To serve a multicast flow by splitting tree to several branches.
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libpof_02 as pof

from random import randint
from copy import deepcopy, copy

from digraph import *
from source_routing import *



log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))

# switch adjacency
adjacency[2][3] = (3, 2, 1)  # (port,link_id,weight)
adjacency[3][2] = (3, 3, 1)  # (port,link_id,weight)
adjacency[3][4] = (1, 4, 1)  # (port,link_id,weight)
adjacency[4][3] = (1, 5, 1)  # (port,link_id,weight)
adjacency[4][5] = (2, 6, 1)  # (port,link_id,weight)
adjacency[5][4] = (3, 7, 1)  # (port,link_id,weight)
adjacency[5][6] = (1, 8, 1)  # (port,link_id,weight)
adjacency[6][5] = (3, 9, 1)  # (port,link_id,weight)
adjacency[6][1] = (1, 10, 1)  # (port,link_id,weight)
adjacency[1][6] = (2, 11, 1)  # (port,link_id,weight)
adjacency[2][6] = (2, 12, 1)  # (port,link_id,weight)
adjacency[6][2] = (2, 13, 1)  # (port,link_id,weight)
adjacency[3][5] = (2, 14, 1)  # (port,link_id,weight)
adjacency[5][3] = (2, 15, 1)  # (port,link_id,weight)
adjacency[1][1] = (3, 16, 0)
adjacency[2][2] = (4, 17, 0)
adjacency[3][3] = (4, 18, 0)
adjacency[4][4] = (3, 19, 0)
adjacency[5][5] = (4, 20, 0)
adjacency[6][6] = (4, 21, 0)

# ip table
ipTable = defaultdict(lambda: defaultdict(lambda: None))
# six node topo
ipTable[IPAddr('172.16.0.1')] = (1, 3)  # (dpid, port)
ipTable[IPAddr('172.16.0.2')] = (2, 4)  # (dpid, port)
ipTable[IPAddr('172.16.0.3')] = (3, 4)
ipTable[IPAddr('172.16.0.4')] = (4, 3)
ipTable[IPAddr('172.16.0.5')] = (5, 4)
ipTable[IPAddr('172.16.0.6')] = (6, 4)


topo = EdgeWeightedDigraph()
topo.addGraphFromDict(adjacency)
# topo.printG()
# topo_SPTs = DijkstraAllPairSP(topo)

# multicast group
multicastGroup = defaultdict(lambda: defaultdict(lambda: None))
multicastGroup[IPAddr('192.168.1.1')] = [IPAddr('172.16.0.1'), IPAddr('172.16.0.2'), IPAddr('172.16.0.3')]

def gen_multi_address(ip):
    '''
    Generate multiple dst IP address.
    :param ip: must be a IPAddr instance.
    :return: multiple dst IP address list, dst_ip_list
    '''
    if isinstance(ip, IPAddr):
        dst_ip_list = []
        possible_ip_set = ipTable.keys()
        for i in range(randint(1, 3)):
            #print len(possible_ip_set)
            dst_ip = possible_ip_set[randint(0, len(possible_ip_set)-1)]
            dst_ip_list.append(dst_ip)
            possible_ip_set.remove(dst_ip)

        return dst_ip_list
    else:
        raise TypeError('%s is not an IPAddr instance' % ip)

def cal_tree(src_dpid, dst_ip_list):
    '''
    :param src_dpid:
    :param dst_ip: a multicast IP address
    :return: several branches of the multicast tree
    '''
    global topo

    dst_dpid = []
    for each_ip in dst_ip_list:
        print each_ip.toStr()
        dpid = (ipTable[each_ip])[0]
        if dpid not in dst_dpid:
            dst_dpid.append(dpid)

    print 'src dpid', src_dpid
    print 'dst dpid', dst_dpid

    steiner_tree = MinSteinerTree(topo, src_dpid, dst_dpid)
    branch_list = steiner_tree.toBranches()[1]
    splitting_nodes = steiner_tree.findSplittingNodes()
    return branch_list, splitting_nodes


class SourceRoutingMulticast(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if isinstance(packet.next, ipv4):
            ip_addr_hex = ip2hex(packet.next.dstip.toStr())
            dsts = gen_multi_address(packet.next.dstip)
            path_list, splitting_nodes = cal_tree(event.dpid, dsts)

            log.info('path list: %s' % path_list)
            print 'dsts', dsts

            encap_sr_header_w_pktout_multicast(dpid = event.dpid, \
                                               dip = ip_addr_hex,\
                                               dip_mask='FFffFFff',\
                                               output_port_list=[2,3],\
                                               port_list_group=[['02','03'], ['01','03','04']])

    # def _handle_ConnectionUp(self)

def launch():
    core.registerNew(SourceRoutingMulticast)

