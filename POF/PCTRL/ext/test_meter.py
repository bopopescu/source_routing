from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as pof

class TestMeter(EventMixin):
	def __init__ (self):
		self.add_protocol()
		core.openflow.addListeners(self, priority=0)

	def add_protocol(self):
		field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                      ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32),
                      ("UDP_Sport",16), ("UDP_Dport",16), ("UDP_Len",16), ("UDP_Checksum",16)]
		match_field_list = []
		total_offset = 0
		for field in field_list:
			field_id = core.PofManager.new_field(field[0], total_offset, field[1])
			#print "field_id: ", field_id
			total_offset += field[1]
			match_field_list.append(core.PofManager.get_field(field_id))
		print 'protocol_id: ', core.PofManager.add_protocol("ETH_IPV4_UDP", match_field_list)

	def _handle_ConnectionUp (self, event):
		meter_id = core.PofManager.add_meter_entry(event.dpid, 100)

		core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', pof.OF_MM_TABLE, 32, [core.PofManager.get_field(0)])

		temp_matchx = core.PofManager.new_matchx(0, '000000000000', '000000000000')
		temp_ins = core.PofManager.new_ins_meter(meter_id)
		core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    	

def launch ():
    core.registerNew(TestMeter)