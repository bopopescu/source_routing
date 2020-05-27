from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
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

TABLE_INIT_NUM = 100
FLOW_HOLDTIME = 10

def new_bucket(action_list, watch_port, slot_id = 0):
    bucket = pof.ofp_bucket()
    bucket.action_num = len(action_list)
    bucket.action_list = action_list
    bucket.watch_port = watch_port
    return bucket

def add_ff_group_table(dpid, group_id, bucket_list):
    group = pof.ofp_group_mod()
    group.command = pof.OFPGC_ADD
    group.group_type = pof.OFPGT_FF
    group.group_id = group_id
    group.slot_id = 0
    group.counter_id = 0
    group.bucket_list = bucket_list
    group.bucket_num = len(bucket_list)

    core.PofManager.write_of(dpid, group)

def install_match_port_entry(dpid, port_id):
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckPortNumTable')



class SouceRoutingProtect(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):

        ip_addr_hex = '0a0a0a0a'
        first_hop_outport = 1
        port_list = []

        entry_id = encap_sr_header_by_dip(dpid=event.dpid, \
                                          dip=ip_addr_hex, \
                                          dip_mask='FFffFFff', \
                                          output_port=first_hop_outport, \
                                          port_list=port_list)

        self._group_mod(event.dpid, first_hop_outport, 2)

    def _group_mod(self, dpid, output_port, back_output_port):

        metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=32)
        output_action1 = core.PofManager.new_action_output(port_id_value_type=1, \
                                                          metadata_offset=0, \
                                                          metadata_length=0, \
                                                          packet_offset=0, \
                                                          port_id=output_port, \
                                                          port_id_field=metadata_port)

        bucket1 = new_bucket([output_action1], watch_port = output_port)

        #------
        output_action2 = core.PofManager.new_action_output(port_id_value_type=1, \
                                                           metadata_offset=0, \
                                                           metadata_length=0, \
                                                           packet_offset=0, \
                                                           port_id=back_output_port, \
                                                           port_id_field=metadata_port)

        bucket2 = new_bucket([output_action2], watch_port= back_output_port)

        add_ff_group_table(dpid = dpid, group_id = back_output_port, bucket_list = [bucket1, bucket2])


def launch():
    core.registerNew(SouceRoutingProtect)