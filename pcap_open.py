
import socket
import struct
from typing import List

from communication import *
from scapy.all import *


def main():
	command_listener()


def get_pcap(filename):
	path = os.getcwd() + '\\pcap\\'
	return rdpcap(path + filename)


def ip_histogram(frames: List[DataLinkFrame]):
	ip_hist = {}
	for frame in frames:
		curr_ip = frame.network_layer.source_ip
		ip_hist[curr_ip] = ip_hist.get(curr_ip, 0) + 1
	return ip_hist


def print_histogram(hist, filter_word=''):
	output = []
	for element in hist:
		if not element == filter_word:
			output.append("{} {}".format(hist[element], element))
	output.sort(key=lambda l: int(l.split()[0]), reverse=True)
	for line in output:
		print(line)


def open_pcap(filename='trace-1.pcap'):
	frames = []
	communications = []
	index = 1
	try:
		packet_array = get_pcap(filename)
	except FileNotFoundError:
		print("File not found.")
		return None, None
	print("File opened.")
	for packet_data in packet_array:
		frame = DataLinkFrame(raw(packet_data), index)
		index += 1
		frames.append(frame)
		insert_to_communications(frame, communications)
	return frames, communications


def print_all_frames(frames: List[DataLinkFrame]):
	for frame in frames:
		frame.print_info()


def filter_frames(frames: List[DataLinkFrame], str_filter):
	filtered_list: List[DataLinkFrame] = []
	for frame in frames:
		if re.search(str_filter, frame.return_str()):
			filtered_list.append(frame)
	return filtered_list


def filter_communications(communications: List[Communication], str_filter):
	filtered_list: List[Communication] = []
	for com in communications:
		if re.search(str_filter, com.return_str()):
			filtered_list.append(com)
	return filtered_list


def print_raw_frames(frames: List[DataLinkFrame]):
	for frame in frames:
		print("________________________" * NUM_OF_COL)
		print("{}".format(format_hex(frame.raw_data)))


def command_listener():
	command = ""
	frames = []
	communications = []

	while True:
		command = input().split()
		print("Executing: ", command)
		if command[0] == 'open':
			if len(command) == 1:
				filename = input("Filename: ")
				if filename == 'cancel':
					continue
			else:
				filename = command[1]
			frames, communications = open_pcap(filename)
		if command[0] == 'print':
			if len(command) == 1:
				print_all_frames(frames)
			elif command[1] == 'raw':
				print_raw_frames(filter_frames(frames, ' '.join(command[2:])))
			elif command[1] == 'all':
				if len(command) >= 3:
					if command[2] == 'raw':
						print_raw_frames(filter_frames(frames, ' '.join(command[2:])))
				print_all_frames(filter_frames(frames, ' '.join(command[1:])))
			elif command[1] == 'communications' or command[1] == 'com':
				print_all_communications(filter_communications(communications, ' '.join(command[2:])))
			else:
				print_all_frames(filter_frames(frames, ' '.join(command[1:])))
		if command[0] == 'filter':
			print_all_frames(filter_frames(frames, ' '.join(command[1:])))
		if command[0] == 'quit':
			sys.exit('Exited Successfully')
		if command[0] == 'hist':
			if len(command) == 1:
				print_histogram(ip_histogram(frames))
			else:
				print_histogram(ip_histogram(frames), ' '.join(command[1:]))


main()

