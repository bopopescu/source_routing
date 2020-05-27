'''
Author: Qinkun Bao
Date: 2016.5.10
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as pof



def _add_protocol(protocol_name, field_list):

    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])   #field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("protocol_name", match_field_list)

def add_protocol():
    field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                  ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32)]
    _add_protocol('ETH_IPv4', field_list)


class Test(EventMixin):

    def __init__(self):
        add_protocol()
        core.openflow.addListeners(self)

    def enable_port(self, device_id):
        core.PofManager.set_port_of_enable(device_id, port_id= 0x2)
        core.PofManager.set_port_of_enable(device_id, port_id= 0x3)
        core.PofManager.set_port_of_enable(device_id, port_id= 0x1)

    def install_table_mod(self, device_id):
        core.PofManager.add_flow_table(device_id, table_name='FirstEntryTable', table_type=pof.OF_MM_TABLE, table_size=32, match_field_list = [core.PofManager.get_field("Eth_Type")[0]])

        table_id = core.PofManager.get_flow_table_id(device_id, table_name='FirstEntryTable')  # 0
        match = core.PofManager.get_field("Eth_Type")[0]
        temp_matchx = core.PofManager.new_matchx(match, '0888', 'FFFF')

        action_1 = core.PofManager.new_action_group(group_id = 1)
        temp_ins = core.PofManager.new_ins_apply_actions([action_1])
        core.PofManager.add_flow_entry(device_id, global_table_id = table_id, matchx_list = [temp_matchx], instruction_list = [temp_ins])



    def install_group_mod(self, device_id):
        action1 = pof.ofp_action_output(port_id= 0x2)
        bucket1 = pof.ofp_bucket()
        bucket1.action_list.append(action1)
        bucket1.action_num = len(bucket1.action_list)
        bucket1.watch_slot_id = 0
        bucket1.watch_port = 0x2
        bucket1.watch_group = 8

        action2 = pof.ofp_action_output(port_id= 0x3)
        bucket2 = pof.ofp_bucket()
        bucket2.action_list.append(action2)
        bucket2.action_num = len(bucket2.action_list)
        bucket2.watch_slot_id = 0
        bucket2.watch_port = 0x3
        bucket2.watch_group = 8

        group_msg = pof.ofp_group_mod()
        group_msg.command = pof.OFPGC_ADD
        group_msg.group_type = pof.OFPGT_FF
        group_msg.group_id = 1
        group_msg.slot_id = 0
        group_msg.counter_id = 3
        group_msg.bucket_list.append(bucket1)
        group_msg.bucket_list.append(bucket2)
        group_msg.bucket_num = len(group_msg.bucket_list)

        print group_msg.show()

        core.PofManager.write_of(device_id, group_msg)

def launch():
    core.registerNew(Test)
