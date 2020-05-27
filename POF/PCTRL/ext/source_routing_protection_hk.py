'''
Created on 2016.5.10.

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
    ETH_SR = [('DMAC', 48), ('SMAC', 48), ('DL_TYPE', 16), ('TTL', 8), ('port', 8)]
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
    temp_matchx = core.PofManager.new_matchx(match, '0908', 'FFFF')
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], [temp_ins])


def _install_write_port_to_metadata_entry(dpid):
    table_id = core.PofManager.get_flow_table_id(dpid, 'WritePortToMetadataTable')
    ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
        metadata_offset=32 + MAX_BIT_OUTPUT_PORT - PORT_FIELD_LEN, \
        write_length=PORT_FIELD_LEN, \
        packet_offset=120)
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'CheckTTL')
    ins_goto_check_ttl_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    core.PofManager.add_flow_entry(dpid, table_id, [], [ins_write_port_to_metadata, ins_goto_check_ttl_table])


def _install_ttl_match_entry(dpid, match_value, match_mask, prior= 800):
    table_id = core.PofManager.get_flow_table_id(dpid, 'CheckTTL')
    match_ttl = core.PofManager.get_field('TTL')[0]
    temp_matchx = core.PofManager.new_matchx(match_ttl, match_value, match_mask)
    ins_list = []

    if match_mask == 'FF':  # last hop
        del_field_action = core.PofManager.new_action_delete_field(field_position=TTL_FIELD_OFFSET, \
                                                                   length_value_type=0, \
                                                                   length_value=TTL_FIELD_LEN + PORT_FIELD_LEN, \
                                                                   )
        match_dl_type = core.PofManager.get_field('DL_TYPE')[0]
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

    #next_table_id = core.PofManager.get_flow_table_id(dpid, 'OutputTable')
    next_table_id = core.PofManager.get_flow_table_id(dpid, 'CheckPortNumTable')
    ins_go_to_table = core.PofManager.new_ins_goto_table(dpid, next_table_id)
    ins_list.append(ins_go_to_table)
    core.PofManager.add_flow_entry(dpid, table_id, [temp_matchx], ins_list, prior, False)


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
    core.PofManager.add_flow_entry(dpid, table_id, [], [ins_apply_action])


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
    core.PofManager.add_flow_entry(dpid, table_id, [ipv4_matchx], [ins_goto_sr_header_encap_table], 0, False)


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
    return encap_sr_header_multicast(dpid, matchx, [output_port], [port_list])


def encap_sr_header_multicast(dpid, matchx, output_port_list, port_list_group):
    if len(output_port_list) != len(port_list_group):
        return False
    table_id = core.PofManager.get_flow_table_id(dpid, 'SRHeaderEncapTable')
    metadata_offset_current = 32
    metadata_start_pos_each_header = []
    for port, port_list in zip(output_port_list, port_list_group):
        ins_list, metadata_offset = _assemble_sr_header_in_metadata(port_list, metadata_offset_current)
        print metadata_offset
        metadata_start_pos_each_header.append(\
            (metadata_offset_current, metadata_offset - metadata_offset_current))  # element:(offset, length)
        metadata_offset_current = metadata_offset

    action_output_list = []
    # the number of output port must be less than 6, since 1 instruction only support 6 actions at most
    for port, port_list, metadata_offset in zip(output_port_list, port_list_group, metadata_start_pos_each_header):
        print 'metadata offset', metadata_offset
        action_output = core.PofManager.new_action_output(port_id_value_type=0, \
                                                          metadata_offset=metadata_offset[0], \
                                                          metadata_length=metadata_offset[1], \
                                                          packet_offset=14, \
                                                          port_id=port)
        action_output_list.append(action_output)
        # metadata_offset += TTL_FIELD_LEN + len(port_list) * PORT_FIELD_LEN

    ins_action_output_list = core.PofManager.new_ins_apply_actions(action_output_list)
    ins_list.append(ins_action_output_list)
    flow_entry_id = core.PofManager.add_flow_entry(dpid, table_id, [matchx], ins_list)
    return flow_entry_id


def _assemble_sr_header_in_metadata(port_list, metadata_offset=32):
    '''

    Args:
        port_list: output port on each hop, like port_list = [2,3,1,2]
        metadata_offset: the start position of sr header in metadata memory.

    Returns:
        ins_list: a list of write metadata instructions for path written to metadata
        metadata_offset_current: the offset in metadata after write the source routing header in metadata

    '''
    ins_list = []
    # Step 1: write the Ethernet header in metadata
    metadata_offset_current = metadata_offset
    ins_write_ethaddr_to_metadata = core.PofManager.new_ins_write_metadata_from_packet( \
        metadata_offset=metadata_offset_current, \
        write_length=96, \
        packet_offset=0)
    ins_list.append(ins_write_ethaddr_to_metadata)
    metadata_offset_current = metadata_offset_current + 96

    # Step 2: write dltype field in metadata
    ins_write_dltype_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                          write_length=16, \
                                                                          value='0908')
    ins_list.append(ins_write_dltype_to_metadata)
    metadata_offset_current = metadata_offset_current + 16

    # Step 3: write the TTL field to metadata
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

    # Step 4: write the all port fields to metadata
    port_num_each_ins = MAX_BYTE_WRITE_METADATA_INS / (PORT_FIELD_LEN / 8)
    for k in range(int(math.ceil(float(ttl) / port_num_each_ins))):
        port_each_ins_str = '0'
        if ttl < port_num_each_ins:
            n = ttl
        else:
            n = port_num_each_ins

        for i in range(n):
            port_each_ins_str = port_each_ins_str + '0' +str(port_list[k * port_num_each_ins + i])
        print port_each_ins_str

        ins_write_port_to_metadata = core.PofManager.new_ins_write_metadata(metadata_offset=metadata_offset_current, \
                                                                            write_length=PORT_FIELD_LEN * n, \
                                                                            value=port_each_ins_str)
        ins_list.append(ins_write_port_to_metadata)
        metadata_offset_current = metadata_offset_current + PORT_FIELD_LEN * n
        ttl = ttl - n

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
    core.PofManager.add_flow_entry(dpid, table_id, [arp_matchx], [ins_goto_target_match])


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
    core.PofManager.add_flow_entry(dpid, table_id, [target_ip_matchx], [ins_action])


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
        core.PofManager.add_flow_table(event.dpid, 'CheckTTL', pof.OF_MM_TABLE, 2, \
                                       [core.PofManager.get_field('TTL')[0]])
        core.PofManager.add_flow_table(event.dpid, 'OutputTable', pof.OF_LINEAR_TABLE, 1)
        core.PofManager.add_flow_table(event.dpid, 'SRHeaderEncapTable', pof.OF_MM_TABLE, 3000, \
                                       [core.PofManager.get_field('DIP')[0]])
        core.PofManager.add_flow_table(event.dpid, 'ARPTargetIPTable', pof.OF_MM_TABLE, 128, \
                                       [core.PofManager.get_field('TPA')[0]])

        # check port for protection
        core.PofManager.add_flow_table(event.dpid, 'CheckPortNumTable', pof.OF_MM_TABLE, 20,\
                                       [pof.ofp_match20(field_id=-1, offset=56, length=8)])

        import time
        time.sleep(1)  # error if not sleep, maybe send flowmod too fast.

        _install_type_match_entry(event.dpid)
        _install_write_port_to_metadata_entry(event.dpid)
        _install_ttl_match_entry(event.dpid, match_value='01', match_mask='FF', prior=900)
        _install_ttl_match_entry(event.dpid, match_value='01', match_mask='00')
        _install_output_entry(event.dpid)

        # ingress node table
        _install_srheader_encap_table(event.dpid)

        install_arp_type_match_entry(event.dpid)


def launch():
    core.registerNew(SourceRouting)
