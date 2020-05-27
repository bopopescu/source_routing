import os
import time

from ostinato.core import ost_pb, DroneProxy
from ostinato.protocols.mac_pb2 import mac
from ostinato.protocols.ip4_pb2 import ip4, Ip4
from ostinato.protocols.udp_pb2 import udp
from ostinato.protocols.payload_pb2 import payload

host_name = '192.168.109.201'
tx_port_number = 6
# rx_port_number = 6
drone = DroneProxy(host_name)

drone.connect()

port_id_list = drone.getPortIdList()
port_config_list = drone.getPortConfig(port_id_list)

print('Port List')
print('---------')
for port in port_config_list.port:
    print('%d.%s (%s)' % (port.port_id.id, port.name, port.description))

tx_port = ost_pb.PortIdList()
tx_port.port_id.add().id = tx_port_number

# rx_port = ost_pb.PortIdList()
# rx_port.port_id.add().id = rx_port_number;

stream_id = ost_pb.StreamIdList()
stream_id.port_id.CopyFrom(tx_port.port_id[0])
stream_id.stream_id.add().id = 1
drone.addStream(stream_id)

stream_cfg = ost_pb.StreamConfigList()
stream_cfg.port_id.CopyFrom(tx_port.port_id[0])
s = stream_cfg.stream.add()
s.stream_id.id = stream_id.stream_id[0].id
s.core.is_enabled = True
s.core.frame_len = 200
s.control.unit = 0
s.control.num_packets = 10000000
s.control.packets_per_sec = 10

# setup stream protocols as mac:eth2:ip4:udp:payload
# Step 1
p = s.protocol.add()
# Step 2: assign a protocol id
p.protocol_id.id = ost_pb.Protocol.kMacFieldNumber
# Step 3: configure the field
p.Extensions[mac].dst_mac = 0x001122334455
p.Extensions[mac].src_mac = 0x00aabbccddee

p = s.protocol.add()
p.protocol_id.id = ost_pb.Protocol.kEth2FieldNumber

p = s.protocol.add()
p.protocol_id.id = ost_pb.Protocol.kIp4FieldNumber
# reduce typing by creating a shorter reference to p.Extensions[ip4]
ip = p.Extensions[ip4]
ip.src_ip = 0x01020304
ip.dst_ip = 0x05060708
ip.dst_ip_mode = 1

p = s.protocol.add()
p.protocol_id.id = ost_pb.Protocol.kUdpFieldNumber
p.Extensions[udp].is_override_dst_port = True
p.Extensions[udp].dst_port = 0xf

p = s.protocol.add()
p.protocol_id.id = ost_pb.Protocol.kPayloadFieldNumber
p.Extensions[payload].pattern_mode = 1
p.Extensions[payload].pattern = 3
s.protocol.add().protocol_id.id = ost_pb.Protocol.kPayloadFieldNumber

drone.modifyStream(stream_cfg)

drone.clearStats(tx_port)
# drone.clearStats(rx_port)

# drone.startCapture(rx_port)
drone.startTransmit(tx_port)

# wait for transmit to finish
# time.sleep(7)
#
# drone.stopTransmit(tx_port)
# # drone.stopCapture(rx_port)
tx_stats = drone.getStats(tx_port)

# raw_input('\nPress Enter to stop sending!')
import signal, sys
def signal_handle(signal, frame):
    global  stream_id, tx_stats, tx_port, drone
    print('Stop sending packets.')
    drone.stopTransmit(tx_port)
    # print tx_stats
    drone.deleteStream(stream_id)
    drone.disconnect()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handle)
print('Press Ctrl+C')
signal.pause()

#print rx_stats
# drone.stopTransmit(tx_port)
# print tx_stats
# drone.deleteStream(stream_id)
# drone.disconnect()
