'''
Author: Shengru Lee
Date: 2016.5.3

./pox.py py test_group
POX> core.Test.install_group_mod(device_id)
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as pof

    
class Test(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self)
        
    def get_all_switches(self):
        print core.PofManager.get_all_switch_id()

        
    def install_group_mod(self, device_id):
        action1 = pof.ofp_action_drop(reason = 1)
        
        action2 = pof.ofp_action_output(port_id = 1)

        bucket1 = pof.ofp_bucket()
        bucket1.action_list.append(action1)
        bucket1.action_list.append(action2)
        bucket1.action_num = len(bucket1.action_list)
        bucket1.watch_slot_id = 0
        bucket1.watch_port = 2
        bucket1.watch_group = 8


        group_msg = pof.ofp_group_mod()
        group_msg.command = pof.OFPGC_ADD
        group_msg.group_type = pof.OFPGT_FF
        group_msg.group_id = 1
        group_msg.slot_id = 0
        group_msg.counter_id = 3
        group_msg.bucket_list.append(bucket1)
        group_msg.bucket_num = len(group_msg.bucket_list)
        
        print group_msg.show()
    
        core.PofManager.write_of(device_id, group_msg)
        
    def install_group_mod_e(self,device_id):
        group_msg = pof.ofp_group_mod()
        core.PofManager.write_of(device_id, group_msg)
        
    def install_meter_mod(self,device_id):
        meter_msg = pof.ofp_meter_mod()
        meter_msg.command = 0
        meter_msg.meter_id = 1
        meter_msg.slot_id = 0
        core.PofManager.write_of(device_id, meter_msg)
               
               
def launch():
    core.registerNew(Test)

