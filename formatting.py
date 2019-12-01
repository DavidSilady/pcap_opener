def format_protocol(protocol):
	return '0x' + ''.join(map('{:02x}'.format, protocol))


def format_mac_address(bytes_address):
	bytes_string = map('{:02x}'.format, bytes_address)
	return ':'.join(bytes_string).upper()


def format_ip_address(bytes_address):
	return '.'.join(map(str, bytes_address))


NUM_OF_COL = 2
COL_WIDTH = 8  # in bytes


def format_hex(data):
	i = 1
	formatted_array = ''
	formatted = ''
	for x in data:
		formatted = '{:02x}'.format(x)
		if i % (NUM_OF_COL * COL_WIDTH) == 0:
			formatted = formatted + '\n'
		elif i % COL_WIDTH == 0:
			formatted = formatted + '  '
		else:
			formatted = formatted + ' '
		formatted_array += formatted
		i += 1
	return formatted_array.upper()
