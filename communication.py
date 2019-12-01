from typing import List

from formatting import *
from extract import *
from pcap_dictionary import *
import struct


class DataLinkFrame:  # Ethernet II, IEEE 802.3

	def __init__(self, bytes_data, index):
		self.raw_data = bytes_data
		self.data_len = len(bytes_data)
		self.data_len_on_cable = self.on_cable_len()
		self.index = index
		self.dst_mac, self.src_mac, layer_type, self.inner_data = extract_data_link_header(bytes_data)
		comparable_type = int(layer_type, 16)
		if comparable_type > 0x05DC:  # Ethernet II > 0x05DC
			self.layer_type_name = 'Ethernet II'
			self.ether_type = layer_type
			self.ether_type_name = ether_type_dictionary.get(self.ether_type)
		else:
			self.layer_type_name = 'IEEE 802.3'
			self.length = layer_type
			name_extension, self.ether_type, self.inner_data = extract_ieee(self.inner_data)
			self.ether_type_name = ether_type_dictionary.get(self.ether_type)
			self.layer_type_name += name_extension

		if self.ether_type_name == 'IPv4':
			self.network_layer = IPv4(self.inner_data)
		elif self.ether_type_name == 'IPv6':
			self.network_layer = IPv6(self.inner_data)
		elif self.ether_type_name == 'ARP':
			self.network_layer = ARP(self.inner_data)
		else:
			self.network_layer = NetworkLayer(self.inner_data[2:])

	def print_info(self):
		print("\nFrame {}: {}".format(self.index, self.layer_type_name))
		print("{} bytes on wire, {} bytes captured".format(self.data_len_on_cable, self.data_len))
		print("Source MAC: {} Destination MAC: {}".format(self.src_mac, self.dst_mac))
		print("{} ({})".format(self.ether_type_name, self.ether_type))
		self.network_layer.print_info()

	def return_str(self):
		return "\nFrame {}: {}".format(self.index, self.layer_type_name) + \
		       "{} bytes on wire, {} bytes captured".format(self.data_len_on_cable, self.data_len) + \
		       "Source MAC: {} Destination MAC: {}".format(self.src_mac, self.dst_mac) + \
		       "{} ({})".format(self.ether_type_name, self.ether_type) + \
		       self.network_layer.return_str()

	def on_cable_len(self):
		return max(self.data_len + 4, 64)


class NetworkLayer:  # IPv4, ARP, IPv6
	def __init__(self, inner_data, protocol='Not Supported', source_ip='None', destination_ip='None'):
		self.source_ip = source_ip
		self.destination_ip = destination_ip
		self.inner_data = inner_data
		self.protocol = protocol
		self.protocol_name = protocol_dictionary.get(protocol)
		if self.protocol_name == 'TCP':
			self.transport_layer = TCP(self.inner_data)
		elif self.protocol_name == 'UDP':
			self.transport_layer = UDP(self.inner_data)
		elif self.protocol_name == 'ICMP':
			self.transport_layer = ICMP(self.inner_data)
		else:
			self.transport_layer = TransportLayer(- 1, - 1, self.inner_data)

	def print_info(self):
		print("Unsupported Protocol:")
		self.transport_layer.print_info()

	def return_str(self):
		return "Source IP: {} Destination IP: {}".format(self.source_ip, self.destination_ip) + \
		       "Protocol: {} ({})".format(self.protocol_name, self.protocol) + \
		       self.transport_layer.return_str()


class ARP(NetworkLayer):
	def __init__(self, raw_data):
		protocol, \
		self.operation, \
		self.source_hw_addr, \
		source_ip, \
		self.target_hw_addr, \
		target_ip, \
		inner_data = extract_arp_header(raw_data)
		if self.operation == '0x0001':
			self.operation_name = 'Request'
		elif self.operation == '0x0002':
			self.operation_name = 'Reply'
		super().__init__(inner_data, protocol, source_ip, target_ip)
		self.protocol_name = ether_type_dictionary.get(self.protocol)

	def return_str(self):
		return "Protocol: {} ({}) Operation: {} ({})".format(self.protocol_name,
		                                                    self.protocol,
		                                                    self.operation_name,
		                                                    self.operation) + \
		       "Source HW address: {} Source IP: {}".format(self.source_hw_addr, self.source_ip) +\
		       "Destination HW address: {} Destination IP: {}".format(self.target_hw_addr, self.destination_ip) + \
		       super().return_str()

	def print_info(self):
		print("Protocol: {} ({}) Operation: {} ({})".format(self.protocol_name,
		                                                    self.protocol,
		                                                    self.operation_name,
		                                                    self.operation))
		print("Source HW address: {} Source IP: {}".format(self.source_hw_addr, self.source_ip))
		print("Destination HW address: {} Destination IP: {}".format(self.target_hw_addr, self.destination_ip))
		self.transport_layer.print_info()


class IPv6(NetworkLayer):
	def __init__(self, bytes_data):
		self.version, protocol, source_ip, destination_ip, inner_data = extract_ipv6_header(bytes_data)
		super().__init__(inner_data, protocol, source_ip, destination_ip)

	def print_info(self):
		print("Version: {} Protocol: {} ({})".format(self.version, self.protocol_name, self.protocol))
		print("Source IP: {} Destination IP: {}".format(self.source_ip, self.destination_ip))
		self.transport_layer.print_info()


class IPv4(NetworkLayer):
	def __init__(self, bytes_data):
		self.version, \
		self.ihl, \
		self.ttl, \
		inner_protocol, \
		source_ip, \
		destination_ip, \
		inner_data = extract_ipv4_header(bytes_data)
		super().__init__(inner_data, inner_protocol, source_ip, destination_ip)

	def print_info(self):
		print("Version: {} IHL: {} TTL: {} Protocol: {} ({})".format(self.version,
		                                                             self.ihl,
		                                                             self.ttl,
		                                                             self.protocol_name,
		                                                             self.protocol))

		print("Source IP: {} Destination IP: {}".format(self.source_ip, self.destination_ip))
		self.transport_layer.print_info()


class TransportLayer:  # TCP, UDP, ICMP
	def __init__(self, src_port, dst_port, payload):
		self.source_port = src_port
		self.target_port = dst_port
		self.protocol = port_dictionary.get(str(self.target_port))
		if self.protocol is None:
			self.protocol = ''
		self.payload = payload

	def print_info(self):
		if self.protocol is not None:
			print("Protocol: {}".format(self.protocol))
		if not self.source_port == - 1:
			print("Source port: {} Destination port: {}".format(self.source_port, self.target_port))
		print("Payload:\n{}".format(format_hex(self.payload)))

	def return_str(self):
		if not self.source_port == -1 and not self.payload == '':
			return "Protocol: {}".format(self.protocol) + \
			       "Source port: {} Destination port: {}".format(self.source_port, self.target_port) + \
			       "Payload:\n {}".format(format_hex(self.payload))
		elif self.payload == '':
			return "Protocol: {}".format(self.protocol) + \
			       "Source port: {} Destination port: {}".format(self.source_port, self.target_port)
		else:
			return "Payload:\n{}".format(format_hex(self.payload))


class TCP(TransportLayer):
	def __init__(self, raw_data):
		source_port, target_port, self.h_len, self.flags, payload = extract_tcp(raw_data)
		super().__init__(source_port, target_port, payload)

	def print_info(self):
		print("Flags: {}".format(self.flags))
		super().print_info()

	def return_str(self):
		return "Flags: {}".format(self.flags) + \
		       super().return_str()


class UDP(TransportLayer):
	def __init__(self, raw_data):
		src_port, dst_port, payload = extract_udp(raw_data)
		super().__init__(src_port, dst_port, payload)


class ICMP(TransportLayer):
	def __init__(self, raw_data):
		self.message_type, self.code, payload = extract_icmp(raw_data)
		super().__init__(- 1, - 1, payload)

	def print_info(self):
		print("Message type: {} Code: {}".format(self.message_type, self.code))
		super().print_info()

	def return_str(self):
		return "Message type: {} Code: {}".format(self.message_type, self.code) + \
		       super().return_str()


class Communication:
	def __init__(self, frame: DataLinkFrame):
		if frame.ether_type_name == 'ARP':
			self.type = 'ARP'
			self.operation = frame.network_layer.operation_name
		else:
			self.type = frame.network_layer.protocol_name + '/' + frame.network_layer.transport_layer.protocol
			self.operation = 'None'
		self.complete = False
		self.client_ip = frame.network_layer.source_ip
		self.server_ip = frame.network_layer.destination_ip
		self.frames: List[DataLinkFrame] = []
		self.frames.append(frame)

	def add_last_frame(self, frame: DataLinkFrame):
		self.complete = True
		self.frames.append(frame)

	def add_frame(self, frame: DataLinkFrame):
		self.frames.append(frame)

		if frame.ether_type_name == 'ARP':
			if frame.network_layer.operation_name == 'Reply':
				if self.operation == 'Request':
					self.complete = True
			if frame.network_layer.operation_name == 'Request':
				if self.operation == 'Reply':
					self.complete = True

	def print_info(self):
		print("\n\n-- COMMUNICATION --")
		print("Type: {} Complete: {}".format(self.type, self.complete))
		print("Client IP: {} Server IP: {}".format(self.client_ip, self.server_ip))
		print("Frames: {}".format(len(self.frames)))
		self.print_frames()

	def return_str(self):
		return "Type: {} Complete: {}".format(self.type, self.complete) +\
		       "Client IP: {} Server IP: {}".format(self.client_ip, self.server_ip)

	def print_frames(self):
		for frame in self.frames:
			frame.print_info()


def ip_match(frame: DataLinkFrame, com: Communication):
	if com.client_ip == frame.network_layer.source_ip:
		if com.server_ip == frame.network_layer.destination_ip:
			return True
	if com.client_ip == frame.network_layer.destination_ip:
		if com.server_ip == frame.network_layer.source_ip:
			return True
	return False


def insert_to_communications(frame: DataLinkFrame, communications: List[Communication]):
	if frame.ether_type_name == 'ARP':
		for com in communications:
			if ip_match(frame, com):
				com.add_frame(frame)
				return
		communications.append(Communication(frame))

	if frame.network_layer.protocol_name == 'TCP':
		if frame.network_layer.transport_layer.flags.__contains__('SYN'):
			communications.append(Communication(frame))
			return
		elif frame.network_layer.transport_layer.flags.__contains__('FIN'):
			for com in communications:
				if ip_match(frame, com):
					if not com.complete:
						com.add_last_frame(frame)
						return
		else:
			for com in communications:
				if ip_match(frame, com):
					if not com.complete:
						com.add_frame(frame)
						return


def print_all_communications(communications: List[Communication]):
	print("\n")
	for com in communications:
		com.print_info()
