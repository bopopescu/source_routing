'''
Created on 2016.7.19.

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
'''
    0 bit       Metadata           32 bit
    +------------------------------+
    |           Reserved           |
 32 +--------------+---------------+
    | Padding (16) |Port Buffer(16)|
 64 +--------------+---------------+
    |            Path 1            |
    +------------------------------+
    |            Path 2            |
    +------------------------------+
    |             ...              |
    +------------------------------+
'''

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
PORT_FIELD_LEN = 16  # bit

MAX_BYTE_WRITE_METADATA_INS = 16
MAX_BIT_OUTPUT_PORT = 32
ETH_HEADER_LEN = 14 # bytes


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
    ETH_SR = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('TTL', 8), ('port', 16)]
    _add_protocol('ETH_SR', ETH_SR)

    ETH_SR_MC = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('TTL', 8), ('ForkFlag', 4), ('GroupLabel', 12)]
    _add_protocol('ETH_SR_MC', ETH_SR_MC)

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


def _install_type_match_entry(dpid):  # First Table
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    match = core.PofManager.get_field('DL_TYPE')[0]
    temp_matchx = core.PofManager.new_matchx(match, '0908', 'FFFF')
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [temp_ins],0, False)


def _install_write_port_to_metadata_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    # use MAX_BIT_OUTPUT_PORT - PORT_FIELD_LEN length padding to 4 Bytes
    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
                                                        metadata_offset=32 + MAX_BIT_OUTPUT_PORT - PORT_FIELD_LEN, \
                                                        write_length=PORT_FIELD_LEN, \
                                                        packet_offset=120)
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'CheckTTL_Fork')
    ins_goto_check_ttl_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [], [ins_write_port_to_metadata, ins_goto_check_ttl_table],0, False)

def _install_ttl_match_entry(dpid, match_value, match_mask, prior=0x0800):
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckTTL')
    match_ttl = core.PofManager.get_field('TTL')[0]
    temp_matchx = core.PofManager.new_matchx(match_ttl, match_value, match_mask)
    ins_list = []

    if match_mask == 'FF':  # last hop
        del_field_action = core.PofManager.new_action_delete_field(field_position=TTL_FIELD_OFFSET, \
                                                                   length_value_type=0, \
                                                                   length_value=TTL_FIELD_LEN + PORT_FIELD_LEN, \
                                                                   )
        dl_type_field = core.PofManager.new_matchx(match_dl_type, '0800', 'FFFF')
        set_field_action = core.PofManager.new_action_set_field(dl_type_field)
        ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action, set_field_action])
        ins_list.append(ins_apply_action)

    else:
        del_field_action = core.PofManager.new_action_delete_field(field_position=PORT_FIELD_OFFSET, \
                                                                   length_value_type=0, \
                                                                   length_value=PORT_FIELD_LEN, \
                                                                   )
        ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action])
        ins_decrease_ttl = core.PofManager.new_ins_calculate_field(pof.OFPCT_SUBTRACT, 0, \
                                                                   match_ttl, 1)
        ins_list.append(ins_apply_action)
        ins_list.append(ins_decrease_ttl)

    next_table_id = core.PofManager.get_flow_table_id(dpid, 'CheckFork')
    ins_go_to_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    ins_list.append(ins_go_to_table)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], ins_list, 0, False)

# flow entry for checking fork node
def install_checkfork_entry(dpid):
    # 0 - unicast, 1 - multicast
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckFork')
    forkflag_match = core.PofManager.get_field('ForkFlag')[0]

    # 1. Yes, it is the fork node
    forkflag_matchx = core.PofManager.new_matchx(forkflag_match, '8', '8')
    group_match_table_id = core.PofManager.get_flow_table_id(dpid, 'GroupMatchTable')
    ins_goto_group_match_table = core.PofManager.new_ins_goto_table(dpid, group_match_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [forkflag_matchx], [ins_goto_group_match_table],0, False)

    #2. No, forwarding normally
    notforkflag_matchx = core.PofManager.new_matchx(forkflag_match, '0', '8')
    output_table_id = core.PofManager.get_flow_table_id(dpid, 'OutputTable') # output table is a DT
    ins_goto_output_tables = core.PofManager.new_ins_goto_table(dpid, output_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [notforkflag_matchx], [ins_goto_output_tables],0, False)

def install_check_ttl_fork_entry(dpid):
    '''
    +-------------------------------------------+
    |                  Table 3                  |
    +--------+----------------------------------+
    |ttl+Fork|           Instructions           |
    +--------+----------------------------------+
    |00000001| Apply-Action:                    |
    |1       | Del-Field (TTL + Port)           |
    |        +----------------------------------+
    |        | Go-To-Table: 4                   |
    +--------+----------------------------------+
    |00000001| Apply-Action:                    |
    |0       | Del-Field (TTL+Port)             |
    |        |                                  |
    |        | Output(Port Buffer)              |
    +--------+----------------------------------+
    |********| Apply-Action:                    |
    |1       | Del-Field (Port)                 |
    |        +----------------------------------+
    |        | Go-To-Table: 4                   |
    +--------+----------------------------------+
    |********| Apply-Action:                    |
    |0       | Del-Field (Port)                 |
    |        |                                  |
    |        | Output(Port Buffer)              |
    +--------+----------------------------------+
    '''
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckTTL_Fork')
    match_ttl = core.PofManager.get_field('TTL')[0]
    match_fork = core.PofManager.get_field('ForkFlag')[0]

    # 1.
    matchx_ttl1 = core.PofManager.new_matchx(match_ttl, '01', 'FF')
    match_fork1 = core.PofManager.new_matchx(match_fork, '8', '8')
    del_field_action = core.PofManager.new_action_delete_field(field_position=TTL_FIELD_OFFSET, \
                                                               length_value_type=0, \
                                                               length_value=TTL_FIELD_LEN + PORT_FIELD_LEN, \
                                                               )
    match_dl_type = core.PofManager.get_field('DL_TYPE')[0]
    dl_type_field = core.PofManager.new_matchx(match_dl_type, '0800', 'FFFF')
    set_field_action = core.PofManager.new_action_set_field(dl_type_field)
    ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action, set_field_action])
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'GroupMatchTable')
    ins_go_to_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_ttl1, match_fork1], [ins_apply_action, ins_go_to_table],0, False)

    # 2.
    matchx_ttl1 = core.PofManager.new_matchx(match_ttl, '01', 'FF')
    match_fork1 = core.PofManager.new_matchx(match_fork, '0', '8')
    del_field_action = core.PofManager.new_action_delete_field(field_position=TTL_FIELD_OFFSET, \
                                                               length_value_type=0, \
                                                               length_value=TTL_FIELD_LEN + PORT_FIELD_LEN, \
                                                               )
    match_dl_type = core.PofManager.get_field('DL_TYPE')[0]
    dl_type_field = core.PofManager.new_matchx(match_dl_type, '0800', 'FFFF')
    set_field_action = core.PofManager.new_action_set_field(dl_type_field)
    metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=32)
    output_action = core.PofManager.new_action_output(port_id_value_type=1, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=0, \
                                                      port_id_field=metadata_port)
    ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action, set_field_action, output_action])
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_ttl1, match_fork1], [ins_apply_action], 0, False)

    #3.
    matchx_ttl1 = core.PofManager.new_matchx(match_ttl, '01', '00')
    match_fork1 = core.PofManager.new_matchx(match_fork, '8', '8')
    ins_decrease_ttl = core.PofManager.new_ins_calculate_field(pof.OFPCT_SUBTRACT, 0, \
                                                               match_ttl, 1)
    del_field_action = core.PofManager.new_action_delete_field(field_position=PORT_FIELD_OFFSET, \
                                                               length_value_type=0, \
                                                               length_value=PORT_FIELD_LEN, \
                                                               )

    ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action])
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'GroupMatchTable')
    ins_go_to_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_ttl1, match_fork1], [ins_decrease_ttl, ins_apply_action, ins_go_to_table],0, False)

    # 4.
    matchx_ttl1 = core.PofManager.new_matchx(match_ttl, '01', '00')
    match_fork1 = core.PofManager.new_matchx(match_fork, '0', '8')
    ins_decrease_ttl = core.PofManager.new_ins_calculate_field(pof.OFPCT_SUBTRACT, 0, \
                                                               match_ttl, 1)
    del_field_action = core.PofManager.new_action_delete_field(field_position=PORT_FIELD_OFFSET, \
                                                               length_value_type=0, \
                                                               length_value=PORT_FIELD_LEN, \
                                                               )
    metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=32)
    output_action = core.PofManager.new_action_output(port_id_value_type=1, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=0, \
                                                      port_id_field=metadata_port)
    ins_apply_action = core.PofManager.new_ins_apply_actions([del_field_action, output_action])
    core.PofManager.add_flow_entry(dpid, table_id, [matchx_ttl1, match_fork1], [ins_decrease_ttl, ins_apply_action], 0, False)

# different encoding for different group
def install_grouplabel_entry(dpid, group_label, output_port, new_path_port_list, new_output_port_list, pkt_offset):
    table_id = core.PofManager.get_flow_table_id(dpid, 'GroupMatchTable')
    grouplabel_match = core.PofManager.get_field('GroupLabel')[0]
    grouplabel_match = pof.ofp_match20(field_id=-1, offset=52, length=12)
    grouplabel_matchx = core.PofManager.new_matchx(grouplabel_match, group_label, 'FF'*(PORT_FIELD_LEN/8))

    ins_list = []
    md_offset = 64
    md_offset_cur = md_offset
    # for primary path
    output_action_list = []
    output_action_pri = core.PofManager.new_action_output(port_id_value_type=0, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=output_port, \
                                                      port_id_field=None)
    output_action_list.append(output_action_pri)

    md_len = 0
    #TODO: Delete
    # print "new_path_port_list", new_path_port_list
    # print 'new_outoput_port_list', new_output_port_list
    for path_port, output_port in zip(new_path_port_list, new_output_port_list):
        # print 'metadata offset b4:', md_offset
        each_ins_list, md_offset = _assemble_sr_header_in_metadata_on_forknode(path_port, metadata_offset=md_offset)
        ins_list = ins_list + each_ins_list
        # print 'metadata offset after:', md_offset

        md_len = md_offset - md_offset_cur
        output_action = core.PofManager.new_action_output(port_id_value_type=0, \
                                                          metadata_offset=md_offset_cur, \
                                                          metadata_length=md_len, \
                                                          packet_offset=pkt_offset, \
                                                          port_id=output_port, \
                                                          port_id_field=None)
        output_action_list.append(output_action)
        md_offset_cur += md_len
    # output_action_list.append(output_action_pri)

    apply_action_ins = core.PofManager.new_ins_apply_actions(output_action_list)
    ins_list.append(apply_action_ins)

    core.PofManager.add_flow_entry(dpid, table_id, [grouplabel_matchx], ins_list,0, False)


def _install_output_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'OutputTable')
    metadata_port = pof.ofp_match20(field_id=-1, offset=32, length=32)
    output_action = core.PofManager.new_action_output(port_id_value_type=1, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=0, \
                                                      port_id_field=metadata_port)
    ins_apply_action = core.PofManager.new_ins_apply_actions([output_action])
    core.PofManager.add_flow_entry(dpid, table_id, [], [ins_apply_action],0, False)


def _install_srheader_encap_table(dpid):
    '''
    Match destination IP address, encapsulate the source routing header.
    :param dpid: switch_id
    :return: None
    '''
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    type_match = core.PofManager.get_field('DL_TYPE')[0]
    ipv4_matchx = core.PofManager.new_matchx(type_match, '0800', 'FFFF')
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'SRHeaderEncapTable')
    ins_goto_sr_header_encap_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [ipv4_matchx], [ins_goto_sr_header_encap_table],0, False)


def encap_sr_header(dpid, matchx, output_port, port_list):
    # table_id = core.PofManager.get_flow_table_id(dpid, 'SRHeaderEncapTable')
    # ins_list, metadata_offset_current = _assemble_sr_header_in_metadata(port_list)
    #
    # '''
    # 5. Output action.
    # '''
    # action_output_list = source_routing_output([output_port], 32, [port_list])
    # ins_action = core.PofManager.new_ins_apply_actions(action_output_list)
    # ins_list.append(ins_action)
    # core.PofManager.add_flow_entry(dpid, table_id, [matchx], ins_list)
    ######
    return encap_sr_header_multicast(dpid, matchx, output_port, port_list)


def encap_sr_header_multicast(dpid, matchx_list, output_port_list, port_list_group):
    if len(output_port_list) != len(port_list_group):
        return False
    table_id = core.PofManager.get_flow_table_id(dpid, 'SRHeaderEncapTable')
    metadata_offset_current = 32
    metadata_start_pos_each_header = []
    ins_list = []
    for port, port_list in zip(output_port_list, port_list_group):
        ins_writemd_list, metadata_offset = _assemble_sr_header_in_metadata_on_src(port_list, metadata_offset_current)
        # print metadata_offset
        metadata_start_pos_each_header.append(
            (metadata_offset_current, metadata_offset - metadata_offset_current))  # element:(offset, length)
        metadata_offset_current = metadata_offset
        ins_list += ins_writemd_list

    action_list = []
    # # set dl_type to 0x0908
    # # dl_type_match = core.PofManager.get_field('DL_TYPE')[0]
    # dl_type_match = pof.ofp_match20(field_name = 'dl_type', field_id = -1, offset = 128, length = 16 )
    # dl_type_matchx = core.PofManager.new_matchx(dl_type_match, '0908','FFff')
    # action_set_dl_type = core.PofManager.new_action_set_field(dl_type_matchx)
    #
    # action_list.append(action_set_dl_type)

    # the number of output port must be less than 6, since 1 instruction only support 6 actions at most
    for port, port_list, metadata_offset in zip(output_port_list, port_list_group, metadata_start_pos_each_header):
        # print 'metadata offset', metadata_offset
        action_output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                          metadata_offset=metadata_offset[0], \
                                                          metadata_length=metadata_offset[1], \
                                                          packet_offset=14, \
                                                          port_id=port)
        action_list.append(action_output)
        # metadata_offset += TTL_FIELD_LEN + len(port_list) * PORT_FIELD_LEN

    ins_action_list = core.PofManager.new_ins_apply_actions(action_list)
    ins_list.append(ins_action_list)
    flow_entry_id = core.PofManager.add_flow_entry(dpid, table_id, matchx_list, ins_list,0, False)
    return flow_entry_id

def encap_sr_header_by_sip_sport_multicast(dpid,sip, sport, output_port_list, port_list_group):
    sip_match = core.PofManager.get_field('SIP')[0]
    sip_matchx = core.PofManager.new_matchx(sip_match, sip, 'FFffFFff')
    sport_match = core.PofManager.get_field('SPORT')[0]
    sport_matchx = core.PofManager.new_matchx(sport_match, sport, 'FFff')
    encap_sr_header_multicast(dpid, [sip_matchx, sport_matchx], output_port_list, port_list_group)


def _assemble_sr_header_in_metadata(port_list, metadata_offset=32):
    ins_list = []
    # Step 1:
    metadata_offset_current = metadata_offset
    ins_write_ethaddr_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
                                                                            metadata_offset=metadata_offset_current, \
                                                                            write_length=96, \
                                                                            packet_offset=0)
    ins_list.append(ins_write_ethaddr_to_metadata)
    metadata_offset_current = metadata_offset_current + 96

    # Step 2:
    ins_write_dltype_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                          write_length=16, \
                                                                          value='0908')
    ins_list.append(ins_write_dltype_to_metadata)
    metadata_offset_current = metadata_offset_current + 16

    # Step 3:
    ttl = len(port_list)
    if ttl < 16:
        ttl_hex_str = '0' + hex(ttl)[2:]
    else:
        ttl_hex_str = hex(ttl)[2:]

    ins_write_ttl_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                       write_length=8, \
                                                                       value=ttl_hex_str)
    ins_list.append(ins_write_ttl_to_metadata)
    metadata_offset_current = metadata_offset_current + 8

    # Step 4
    port_num_each_ins = MAX_BYTE_WRITE_METADATA_INS / (PORT_FIELD_LEN / 8)
    for k in range(int(math.ceil(float(ttl) / port_num_each_ins))):
        port_each_ins_str = ''
        if ttl < port_num_each_ins:
            n = ttl
        else:
            n = port_num_each_ins

        for i in range(n):
            port = port_list[k * port_num_each_ins + i]
            if port >=16:
                port_each_ins_str = port_each_ins_str + str(port)
            else:
                port_each_ins_str = port_each_ins_str + '0' + str(port)

        ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                            write_length=PORT_FIELD_LEN * n, \
                                                                            value=port_each_ins_str)
        ins_list.append(ins_write_port_to_metadata)
        metadata_offset_current = metadata_offset_current + PORT_FIELD_LEN * n
        ttl = ttl - n

    return ins_list, metadata_offset_current

def _assemble_sr_header_in_metadata_on_src(port_list, metadata_offset=32):
    ins_list = []
    # Step 1: Ethernet header
    metadata_offset_current = metadata_offset
    ins_write_ethaddr_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
                                                                            metadata_offset=metadata_offset_current, \
                                                                            write_length=96, \
                                                                            packet_offset=0)
    ins_list.append(ins_write_ethaddr_to_metadata)
    metadata_offset_current = metadata_offset_current + 96

    # step 2: dl_type


    # Step 3: source routing header
    ttl = len(port_list)
    if ttl < 16:
        ttl_hex_str = '0' + hex(ttl)[2:]
    else:
        ttl_hex_str = hex(ttl)[2:]

    # ins_write_ttl_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
    #                                                                    write_length=8, \
    #                                                                    value=ttl_hex_str)
    # ins_list.append(ins_write_ttl_to_metadata)
    # metadata_offset_current = metadata_offset_current + 8

    port_num_each_ins = MAX_BYTE_WRITE_METADATA_INS / (PORT_FIELD_LEN / 8)

    port_each_ins_str = '0908' + ttl_hex_str

    # if ttl < port_num_each_ins:
    #     n = ttl
    # else:
    #     n = port_num_each_ins
    # print '-----port_list:', port_list, ttl
    for i in range(ttl):
        port = port_list[i]
        if isinstance(port, int):
            if port >=4096:
                port_each_ins_str = port_each_ins_str + str(hex(port))[2:]
            elif port < 4096 and port >= 256:
                port_each_ins_str = port_each_ins_str + '0' + str(hex(port))[2:]
            elif port < 256 and port >= 16:
                port_each_ins_str = port_each_ins_str + '00' + str(hex(port))[2:]
            else:
                port_each_ins_str = port_each_ins_str + '000' + str(hex(port))[2:]
        elif isinstance(port, str):
            # print 'port!!!!', port
            port_each_ins_str = port_each_ins_str + '00' + port


    # print '----write metadata:', port_each_ins_str
    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                        write_length=16+TTL_FIELD_LEN + PORT_FIELD_LEN * ttl, \
                                                                        value=port_each_ins_str)
    ins_list.append(ins_write_port_to_metadata)
    metadata_offset_current = metadata_offset_current + 16+ PORT_FIELD_LEN * ttl + 8 # 16 is for l_type, 8 is for ttl field

    return ins_list, metadata_offset_current

def _assemble_sr_header_in_metadata_on_forknode(port_list, metadata_offset=32):
    ins_list = []
    # Step 1: Ethernet header
    metadata_offset_current = metadata_offset
    ins_write_ethaddr_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
                                                                            metadata_offset=metadata_offset_current, \
                                                                            write_length=96, \
                                                                            packet_offset=0)
    ins_list.append(ins_write_ethaddr_to_metadata)
    metadata_offset_current = metadata_offset_current + 96

    # Step 2: source routing header
    ttl = len(port_list)
    if ttl < 16:
        ttl_hex_str = '0' + hex(ttl)[2:]
    else:
        ttl_hex_str = hex(ttl)[2:]

    # ins_write_ttl_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
    #                                                                    write_length=8, \
    #                                                                    value=ttl_hex_str)
    # ins_list.append(ins_write_ttl_to_metadata)
    # metadata_offset_current = metadata_offset_current + 8

    port_num_each_ins = MAX_BYTE_WRITE_METADATA_INS / (PORT_FIELD_LEN / 8)

    port_each_ins_str = '0908'+ttl_hex_str

    # if ttl < port_num_each_ins:
    #     n = ttl
    # else:
    #     n = port_num_each_ins

    for i in range(ttl):
        port = port_list[i]
        if isinstance(port, int):
            if port >=4096:
                port_each_ins_str = port_each_ins_str + str(hex(port))[2:]
            elif port < 4096 and port >= 256:
                port_each_ins_str = port_each_ins_str + '0' + str(hex(port))[2:]
            elif port < 256 and port >= 16:
                port_each_ins_str = port_each_ins_str + '00' + str(hex(port))[2:]
            else:
                port_each_ins_str = port_each_ins_str + '000' + str(hex(port))[2:]

        elif isinstance(port, str):
            # print 'port!!!!', port
            port_each_ins_str = port_each_ins_str + '00' + port

    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                        write_length=16+TTL_FIELD_LEN + PORT_FIELD_LEN * ttl, \
                                                                        value=port_each_ins_str)
    ins_list.append(ins_write_port_to_metadata)
    metadata_offset_current = 16+metadata_offset_current + PORT_FIELD_LEN * ttl + 8 # 8 is for ttl field

    return ins_list, metadata_offset_current

# TODO: update this function when finish the write metadata related instruction
def source_routing_output(output_port_list, metadata_offset, port_list_group):
    splitting_num = len(output_port_list)
    if len(port_list_group) != splitting_num:
        return False

    action_output_list = []
    for i in range(splitting_num):
        action_output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                          metadata_offset=metadata_offset, \
                                                          metadata_length=112 + TTL_FIELD_LEN \
                                                                          + len(port_list_group[i]) * PORT_FIELD_LEN, \
                                                          packet_offset=14, \
                                                          port_id=output_port_list[i])
        action_output_list.append(action_output)
        metadata_offset += TTL_FIELD_LEN + len(port_list_group[i]) * PORT_FIELD_LEN
    return action_output_list


def encap_sr_header_w_pktout(dpid, matchx, output_port, port_list, event, out_dpid):
    packetout_msg = pof.ofp_packet_out()
    packetout_msg.actions.append(pof.ofp_action_output(port_id=int(port_list[-1])))
    packetout_msg.data = event.ofp
    packetout_msg.in_port = event.port
    core.PofManager.write_of(out_dpid, packetout_msg)
    return encap_sr_header(dpid, matchx, output_port, port_list)


def encap_sr_header_w_pktout_multicast(dpid, dip, dip_mask, output_port_list, port_list_group):
    # def encap_sr_header_by_dip_w_pktout(dpid, dip, dip_mask, output_port, port_list, event, out_dpid):
    dip_match = core.PofManager.get_field('DIP')[0]
    dip_matchx = core.PofManager.new_matchx(dip_match, dip, dip_mask)

    encap_sr_header_multicast(dpid, dip_matchx, output_port_list, port_list_group)


def encap_sr_header_by_dip(dpid, dip, dip_mask, output_port, port_list):
    dip_match = core.PofManager.get_field('DIP')[0]
    dip_matchx = core.PofManager.new_matchx(dip_match, dip, dip_mask)

    encap_sr_header(dpid, dip_matchx, output_port, port_list)


def encap_sr_header_by_dip_w_pktout(dpid, dip, dip_mask, output_port, port_list, event, out_dpid):
    dip_match = core.PofManager.get_field('DIP')[0]
    dip_matchx = core.PofManager.new_matchx(dip_match, dip, dip_mask)

    return encap_sr_header_w_pktout(dpid, dip_matchx, output_port, port_list, event, out_dpid)

def encap_sr_header_by_sip_sport_drop(dpid, sip, sport, sport_mask):
    table_id = core.PofManager.get_flow_table_id(dpid, 'SRHeaderEncapTable')
    sip_match = core.PofManager.get_field('SIP')[0]
    sip_matchx = core.PofManager.new_matchx(sip_match, sip, 'FFffFFff')

    sport_match = core.PofManager.get_field('SPORT')[0]
    sport_matchx = core.PofManager.new_matchx(sport_match, sport, sport_mask)

    drop_action = core.PofManager.new_action_drop(0)
    action_ins = core.PofManager.new_ins_apply_actions([drop_action])
    core.PofManager.add_flow_entry(dpid, table_id, [sip_matchx, sport_matchx], [action_ins])

def install_arp_type_match_entry(dpid):
    '''
    Broadcast the arp packet.
    '''
    dltype_match = core.PofManager.get_field('DL_TYPE')[0]
    arp_matchx = core.PofManager.new_matchx(dltype_match, '0806', 'FFff')

    # broadcast_output_action = core.PofManager.new_action_output(0, 0, 0, 0, 255)
    # action_ins = core.PofManager.new_ins_apply_actions([broadcast_output_action])
    # table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    # core.PofManager.add_flow_entry(dpid, table_id, [arp_matchx], [action_ins])
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'ARPTargetIPTable')
    ins_goto_target_match = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    table_id = core.PofManager.get_flow_table_id(dpid, 'FirstEntryTable')
    core.PofManager.add_flow_entry(dpid, table_id, [arp_matchx], [ins_goto_target_match],0, False)


def install_arp_target_ip_match_entry(dpid, target_ip, output_port):
    target_ip_match = core.PofManager.get_field('TPA')[0]
    target_ip_matchx = core.PofManager.new_matchx(target_ip_match, target_ip, 'FFffFFff')

    table_id = core.PofManager.get_flow_table_id(dpid, 'ARPTargetIPTable')
    action_output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                      metadata_offset=0, \
                                                      metadata_length=0, \
                                                      packet_offset=0, \
                                                      port_id=output_port)
    ins_action = core.PofManager.new_ins_apply_actions([action_output])
    core.PofManager.add_flow_entry(dpid, table_id, [target_ip_matchx], [ins_action],0, False)


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
        core.PofManager.add_flow_table(event.dpid, 'WritePortToMetadataTable', pof.OF_LINEAR_TABLE, 1)
        core.PofManager.add_flow_table(event.dpid, 'CheckTTL_Fork', pof.OF_MM_TABLE, 4, \
                                       [core.PofManager.get_field('TTL')[0], core.PofManager.get_field('ForkFlag')[0]])
        core.PofManager.add_flow_table(event.dpid, 'OutputTable', pof.OF_LINEAR_TABLE, 1)
        core.PofManager.add_flow_table(event.dpid, 'SRHeaderEncapTable', pof.OF_EM_TABLE, 3000, \
                                       [core.PofManager.get_field('SIP')[0], core.PofManager.get_field('SPORT')[0]])
        core.PofManager.add_flow_table(event.dpid, 'ARPTargetIPTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('TPA')[0]])
        # multicast table
        # core.PofManager.add_flow_table(event.dpid, 'CheckFork', pof.OF_MM_TABLE, 2, \
        #                                [core.PofManager.get_field('ForkFlag')[0]])
        metadata_port = pof.ofp_match20(field_id=-1, offset=52, length=12)
        core.PofManager.add_flow_table(event.dpid, 'GroupMatchTable', pof.OF_EM_TABLE, 3000, [metadata_port])

        import time
        time.sleep(1)  # error if not sleep, maybe send flowmod too fast.

        _install_type_match_entry(event.dpid)
        _install_write_port_to_metadata_entry(event.dpid)
        # _install_ttl_match_entry(event.dpid, match_value='01', match_mask='FF', prior=0x0700)
        # _install_ttl_match_entry(event.dpid, match_value='01', match_mask='00')
        _install_output_entry(event.dpid)

        # ingress node table
        _install_srheader_encap_table(event.dpid)

        install_arp_type_match_entry(event.dpid)

        # fork node
        # install_checkfork_entry(event.dpid)
        install_check_ttl_fork_entry(event.dpid)
        # install_grouplabel_entry(event.dpid, "fffe", 1, [[2,3,4], [1,2]], [2,3], 16)


def launch():

    print '''
        ____  ____  _____ ____
       / __ \/ __ \/ ___// __ \
      / /_/ / / / /\__ \/ /_/ /
     / ____/ /_/ /___/ / _, _/
    /_/    \____//____/_/ |_|
                            '''
    core.registerNew(SourceRouting)

