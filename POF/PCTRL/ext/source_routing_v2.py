'''
Created on 2016.7.4.

@author: shengrulee
'''
from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

import pox.openflow.libpof_02 as pof

import math

# import networkx as nx

log = core.getLogger()

# switch dpid
switches = [2215146867, 2215152430, 2215152298]
# switches = [1,2,3,4,5,7,8,9]

ETH = [('DMAC', 0, 48), ('SMAC', 48, 96), ('DL_TYPE', 96, 16)]

SOURCE_ROUTING_PROTOCOL = [('TTL', 112, 8), ('port', 120, 32)]

IPV4 = [('version', 112, 4), ('IHL', 116, 4), ('tos', 120, 8),
        ('total_length', 128, 16), ('id', 144, 16), ('flags_offset', 160, 16),
        ('ttl', 176, 8), ('protocol', 184, 8), ('checksum', 192, 16),
        ('sip', 208, 32), ('dip', 240, 32)]

UDP = [('src_port', 272, 16), ('dst_port', 288, 16), ('length', 304, 16), ('checksum', 320, 16)]

'''
Table start id on switch
'''
MM_start_id = 0
LPM_start_id = 8
EM_start_id = 10
DT_start_id = 16

'''
Table id explanation.
'''
FIRST_TABLE_ENTRY = 0
TTL_MATCH_TABLE = 1
WRITE_PORT_TO_METADATA = DT_start_id
OUTPUT_TABLE = DT_start_id + 1
IPV4_UDP_MATCH_TABLE = 2

TTL_FIELD_OFFSET = 112  # bit
TTL_FIELD_LEN = 8  # bit
PORT_FIELD_OFFSET = 120  # bit
PORT_FIELD_LEN = 8  # bit

MAX_BYTE_WRITE_METADATA_INS = 16
MAX_BIT_OUTPUT_PORT = 32


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

def _install_type_match_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    match = core.PofManager.get_field('DL_TYPE')[0]
    matchx = core.PofManager.new_matchx(match, '0908', 'FFFF')

    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
        metadata_offset=32 + MAX_BIT_OUTPUT_PORT - PORT_FIELD_LEN, \
        write_length=PORT_FIELD_LEN, \
        packet_offset=120)
    next_table_id = core.PofManager.get_flow_table_id(dpid, '') #TODO
    ins_goto_next_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [matchx],[ins_write_port_to_metadata, ins_goto_next_table])


class SourceRouting(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        add_protocol()

    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        core.PofManager.set_port_of_enable(event.dpid, port_id)

    def _handle_ConnectionUp(self, event):
        # add_flow_table(self, switch_id, table_name, table_type, table_size, match_field_list = [])
        core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('DL_TYPE')[0]])
        core.PofManager.add_flow_table(event.dpid, 'SplittingCheckTable', pof.OF_MM_TABLE, 128,\
                                       [core.PofManager.get_field('')[0]])
        core.PofManager.add_flow_table(event.dpid, 'CheckTTL', pof.OF_MM_TABLE, 2, \
                                       [core.PofManager.get_field('TTL')[0]])
        core.PofManager.add_flow_table(event.dpid, 'OutputTable', pof.OF_LINEAR_TABLE, 1)
        core.PofManager.add_flow_table(event.dpid, 'SRHeaderEncapTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('DIP')[0]])
        core.PofManager.add_flow_table(event.dpid, 'ARPTargetIPTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('TPA')[0]])

        import time
        time.sleep(1)  # error if not sleep, maybe send flowmod too fast.

        _install_type_match_entry(event.dpid)
        _install_write_port_to_metadata_entry(event.dpid)
        _install_ttl_match_entry(event.dpid, match_value='01', match_mask='FF', prior=0x0700)
        _install_ttl_match_entry(event.dpid, match_value='01', match_mask='00')
        _install_output_entry(event.dpid)

        # ingress node table
        _install_srheader_encap_table(event.dpid)

        install_arp_type_match_entry(event.dpid)


def launch():
    core.registerNew(SourceRouting)
