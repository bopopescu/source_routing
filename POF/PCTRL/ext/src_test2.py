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
import string
from digraph import *
from source_routing import *
from source_routing_protection import *
dpid212= 6
dpid219= 7
dpid217= 5
dpid216= 4
dpid222_1= 8
dpid222_2= 10
dpid201 = 9
dpid209 = 11
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

def install_match_port_entry(dpid, port_id,backup_port_list):
    #print"##############################################"
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckPortNumTable')
    match = pof.ofp_match20(field_id=-1, offset=56, length=8)
    matchx_port = core.PofManager.new_matchx(match,port_id,"FF")
    backup_port_len=len(backup_port_list)
    port_str = ''
    ins0 = core.PofManager.new_ins_write_metadata_from_packet(64,120,0)    
    for port in backup_port_list:
        if port<16:
            port_str =port_str + '0' + hex(port)[2:]
        else:
            port_str =port_str + hex(port)[2:]
            
    ins1 = core.PofManager.new_ins_write_metadata(184,backup_port_len*8,port_str)
    metadata_ttl = pof.ofp_match20(field_id=-1, offset=176, length=8)
    ins2 = core.PofManager.new_ins_calculate_field(0,0,metadata_ttl,backup_port_len)
    new_action1 = core.PofManager.new_action_group(string.atoi(port_id))
    ins3 = core.PofManager.new_ins_apply_actions([new_action1])
    core.PofManager.add_flow_entry(dpid,table_id,[matchx_port],[ins0,ins1,ins2,ins3])
    #print"********************************************************************************"

class SouceRoutingProtect(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        
    def _handle_ConnectionUp(self, event):
        
        ip_addr_hex = '0a000002'
        first_hop_outport = 2
        port_list = [3,1,3,2]
        
        
       # print"111111111111111111111111111"
        if event.dpid == dpid216:
            entry_id = encap_sr_header_by_dip(dpid=event.dpid, \
                                          dip=ip_addr_hex, \
                                          dip_mask='FFffFFff', \
                                          output_port=first_hop_outport, \
                                          port_list=port_list)
        
        
        
        time.sleep(1)
        backup_port_list=[1,2]
        
        
        if event.dpid == dpid216:
            install_match_port_entry(event.dpid,"02",backup_port_list)
            self._group_mod(event.dpid, 0x2, 0x3,2)
        elif event.dpid == dpid217:
            install_match_port_entry(event.dpid,"03",backup_port_list)
            self._group_mod(event.dpid, 0x3, 0x1,2)
        elif event.dpid == dpid219:
            install_match_port_entry(event.dpid,"01",backup_port_list)
            self._group_mod(event.dpid,0x1,0x2,2)
        elif event.dpid == dpid222_1: 
            install_match_port_entry(event.dpid,"03",backup_port_list)
            self._group_mod(event.dpid,0x3,0x2,2) 
        elif event.dpid == dpid201: 
            install_match_port_entry(event.dpid,"02",backup_port_list)
            self._group_mod(event.dpid,0x2,0x3,2) 
        elif event.dpid == dpid212:   
            install_match_port_entry(event.dpid,"01",backup_port_list)
            self._group_mod(event.dpid,0x1,0x3,2)
        elif event.dpid == dpid222_2:
            install_match_port_entry(event.dpid,"02",backup_port_list)
            self._group_mod(event.dpid,0x2,0x3,2)
            
            
            
            
        ip_addr_hex = '0a000001'
        first_hop_outport = 1
        port_list = [1,3,2,3]
        
        
        # print"111111111111111111111111111"
        if event.dpid == dpid201:
            entry_id = encap_sr_header_by_dip(dpid=event.dpid, \
                                          dip=ip_addr_hex, \
                                          dip_mask='FFffFFff', \
                                          output_port=first_hop_outport, \
                                          port_list=port_list)
        
        
        
        time.sleep(1)
        backup_port_list=[3,2]
        if event.dpid == dpid201:
            install_match_port_entry(event.dpid,"01",backup_port_list)
            self._group_mod(event.dpid, 0x1, 0x2,2)
        elif event.dpid == dpid222_1:
            install_match_port_entry(event.dpid,"01",backup_port_list)
            self._group_mod(event.dpid, 0x1, 0x2,2)
        elif event.dpid == dpid219:
            install_match_port_entry(event.dpid,"03",backup_port_list)
            self._group_mod(event.dpid, 0x3, 0x2,2)
        elif event.dpid == dpid217:
            install_match_port_entry(event.dpid,"02",backup_port_list)
            self._group_mod(event.dpid, 0x2, 0x3,2)
        elif event.dpid == dpid216:
            install_match_port_entry(event.dpid,"03",backup_port_list)
            self._group_mod(event.dpid,0x3,0x2,2)
        elif event.dpid == dpid212:   
            install_match_port_entry(event.dpid,"02",backup_port_list)
            self._group_mod(event.dpid,0x2,0x3,2)
        elif event.dpid == dpid222_2:
            install_match_port_entry(event.dpid,"03",backup_port_list)
            self._group_mod(event.dpid,0x3,0x2,2)
    """    
    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        if(event.dpid == dpid212):
            if port_id == 0x9 or port_id == 0x5:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if(event.dpid == dpid217):
            if port_id == 0x3 or port_id == 0x5:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if(event.dpid == dpid219):
            if port_id == 0x3 or port_id == 0x4 or port_id == 0x5:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
            
    """            
        

    def _group_mod(self, dpid, output_port, backup_output_port,backup_port_len):

        metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=32)
        output_action1 = core.PofManager.new_action_output(port_id_value_type=1, \
                                                          metadata_offset=0, \
                                                          metadata_length=0, \
                                                          packet_offset=0, \
                                                          port_id=output_port, \
                                                          port_id_field=metadata_port)

        bucket1 = new_bucket([output_action1], watch_port = output_port)

        #------
        output_action2 = core.PofManager.new_action_output(port_id_value_type=0, \
                                                           metadata_offset=64, \
                                                           metadata_length=120+backup_port_len*8, \
                                                           packet_offset=15, \
                                                           port_id=backup_output_port, \
                                                           )

        bucket2 = new_bucket([output_action2], watch_port= backup_output_port)

        add_ff_group_table(dpid = dpid, group_id =output_port, bucket_list = [bucket1, bucket2])


def launch():
    core.registerNew(SouceRoutingProtect)