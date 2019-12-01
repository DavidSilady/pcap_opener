from formatting import *
from pcap_dictionary import LSAP_dictionary
import os
import struct


def extract_ipv4_header(raw_data):
	version_header_length = raw_data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 0x0f) * 4

	ttl, protocol, src_ip, target_ip = struct.unpack('! 8x B 1s 2x 4s 4s', raw_data[:20])
	return version, header_length, ttl, \
	       format_protocol(protocol), \
	       format_ip_address(src_ip), \
	       format_ip_address(target_ip), \
	       raw_data[header_length:]


def extract_ipv6_header(raw_data):
	version = raw_data[0] >> 4
	next_header, source_ip, destination_ip = struct.unpack("! 6x 2s 2x 6s 6s", raw_data[:20])
	return version, \
	       next_header, \
	       format_ip_address(source_ip), \
	       format_ip_address(destination_ip),\
	       raw_data[20:]


def extract_arp_header(raw_data):
	proto, op_code, source_hw_addr, source_ip, target_hw_addr, target_ip = struct.unpack("! 2x 2s 2x 2s 6s 4s 6s 4s",
	                                                                                     raw_data[:28])
	return format_protocol(proto), \
	       format_protocol(op_code), \
	       format_mac_address(source_hw_addr), \
	       format_ip_address(source_ip), \
	       format_mac_address(target_hw_addr), \
	       format_ip_address(target_ip), \
	       raw_data[28:]


def extract_data_link_header(raw_data):
	destination_mac, source_mac, layer_type = struct.unpack('! 6s 6s 2s', raw_data[:14])
	return format_mac_address(destination_mac), \
	       format_mac_address(source_mac), \
	       format_protocol(layer_type), \
	       raw_data[14:]


def extract_ieee(raw_data):
	dsap, ssap, raw_type = struct.unpack("! 1s 1s 4x 2s", raw_data[:8])
	dsap, ssap = format_protocol(dsap), format_protocol(ssap)
	ssap_id = LSAP_dictionary.get(ssap)
	dsap_id = LSAP_dictionary.get(dsap)
	ether_type = format_protocol(raw_type)
	if ssap_id == 'STP':
		name = ' STP'
		ether_type = 'None'
	elif ssap_id == 'IPX':
		name = ' LLC IPX'
		ether_type = 'None'
	elif ssap_id == 'RAW':
		name = ' RAW'
		ether_type = 'None'
	elif ssap == 'SNAP':  # Unpack further
		name = ' LLC SNAP'
	else:
		name = ' LLC'
		ether_type = 'None'
	return name, ether_type, raw_data[8:]


def extract_tcp(raw_data):
	source_port, target_port, h_len_flags = struct.unpack("! 2s 2s 8x 2s", raw_data[:14])
	flags = []
	h_len_flags = int(format_protocol(h_len_flags), 16)
	h_len = raw_data[12] >> 12
	flag_bits = h_len_flags & 0x3f
	if flag_bits & 0x20:
		flags.append('URG')
	if flag_bits & 0x10:
		flags.append('ACK')
	if flag_bits & 0x08:
		flags.append('PSH')
	if flag_bits & 0x04:
		flags.append('RST')
	if flag_bits & 0x02:
		flags.append('SYN')
	if flag_bits & 0x01:
		flags.append('FIN')
	return int(format_protocol(source_port), 16),  int(format_protocol(target_port), 16), h_len, flags, raw_data[h_len:]


def extract_udp(raw_data):
	source_port, target_port = struct.unpack("! 2s 2s", raw_data[:4])
	return int(format_protocol(source_port), 16), int(format_protocol(target_port), 16), raw_data[8:]


def extract_icmp(raw_data):
	icmp_type, code = struct.unpack("! 1s 1s", raw_data[:2])
	return format_protocol(icmp_type), format_protocol(code), raw_data[8:]


