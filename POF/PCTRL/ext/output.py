'''
Created on 2016.5.10.

@author: shengrulee
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time
import pox.openflow.libpof_02 as pof

import math
import string
# import networkx as nx

log = core.getLogger()

# switch dpid
switches = [2215146867, 2215152430, 2215152298]
# switches = [1,2,3,4,5,7,8,9]

ETH = [('DMAC', 0, 48), ('SMAC', 48, 48), ('DL_TYPE', 96, 16)]

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


def _install_type_match_entry(dpid):  # First Table
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    match = core.PofManager.get_field('DL_TYPE')[0]
    temp_matchx = core.PofManager.new_matchx(match, '0800', 'FFFF')
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'AddFieldTable')
    ins_goto_addfield_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [ins_goto_addfield_table])


def _install_write_port_to_metadata_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
        metadata_offset=32 , \
        write_length=32, \
        packet_offset=120)
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'OutputTable')
    ins_goto_output_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [], [ins_write_port_to_metadata, ins_goto_output_table])


def _install_output_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    match = core.PofManager.get_field('SIP')[0]
    temp_matchx = core.PofManager.new_matchx(match, '0a000001', 'FFFFFFFF')
    metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=8)




    output_action = core.PofManager.new_action_output(port_id_value_type=0, \
                                                      metadata_offset=32, \
                                                      metadata_length=32, \
                                                      packet_offset=120, \
                                                      port_id=2, \
                                                      port_id_field=metadata_port)


    ins_apply_action = core.PofManager.new_ins_apply_actions([output_action])

    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
        metadata_offset=32 , \
        write_length=32, \
        packet_offset=120)

    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [ins_apply_action])


def _install_addfield_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'AddFieldTable')
    match = core.PofManager.get_field('SIP')[0]
    temp_matchx = core.PofManager.new_matchx(match, '0a000001', 'FFFFFFFF')
    addfield_action = core.PofManager.new_action_add_field(0, 112, 40, '3400000001')


    next_table_id = core.PofManager.get_flow_table_id(dpid, 'SetFieldTable')
    ins_goto_setfield_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    ins_apply_action = core.PofManager.new_ins_apply_actions([addfield_action])
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [ins_apply_action, ins_goto_setfield_table])


def _install_setfield_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'SetFieldTable')


    match = core.PofManager.get_field('SIP')[0]
    temp_matchx = core.PofManager.new_matchx(match, '0a000001', 'FFFFFFFF')

    match_dl_type = core.PofManager.get_field('DL_TYPE')[0]
    dl_type_field = core.PofManager.new_matchx(match_dl_type, '0908', 'FFFF')
    setfield_action = core.PofManager.new_action_set_field(dl_type_field)



    ins_apply_action = core.PofManager.new_ins_apply_actions([setfield_action])

    next_table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    ins_goto_writeporttometadata_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [ins_apply_action, ins_goto_writeporttometadata_table])


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
                                       [core.PofManager.get_field('SIP')[0]])
        log.info("after add flow table FirstEntryTable")

        # core.PofManager.add_flow_table(event.dpid, 'AddFieldTable', pof.OF_LINEAR_TABLE, 128)
        # log.info("after add flow table AddFieldTable")
        #
        # core.PofManager.add_flow_table(event.dpid, 'SetFieldTable', pof.OF_LINEAR_TABLE, 128)
        # log.info("after add flow table SetFieldTable")
        #
        # core.PofManager.add_flow_table(event.dpid, 'WritePortToMetadataTable', pof.OF_LINEAR_TABLE, 128)
        # log.info("after add flow table WritePortToMetadataTable")
        #
        # core.PofManager.add_flow_table(event.dpid, 'OutputTable', pof.OF_LINEAR_TABLE, 128)
        # log.info("after add flow table OutputTable")





        # _install_type_match_entry(event.dpid)
        # log.info("after add flow entry ")
        #
        # _install_addfield_entry(event.dpid)
        # log.info("after add flow entry addfield")
        #
        # _install_setfield_entry(event.dpid)
        # log.info("after add flow entry setfield")
        #
        # _install_write_port_to_metadata_entry(event.dpid)
        # log.info("after add flow entry write_port_to_metadata")

        _install_output_entry(event.dpid)
        log.info("after add flow entry output")






def launch():
    core.registerNew(SourceRouting)
