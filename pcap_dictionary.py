import os


def import_dictionary(filename='protocol_dictionary.txt'):
	path = os.getcwd() + '\\'
	local_dict = {}
	with open(path + filename) as f:
		for line in f:
			if not line[0] == '#':
				(key, val) = line.split()
				local_dict[key] = val
	return local_dict


ether_type_dictionary = import_dictionary('ether_type_dictionary.txt')
LSAP_dictionary = import_dictionary('LSAP_dictionary.txt')
port_dictionary = import_dictionary('port_dictionary.txt')
protocol_dictionary = import_dictionary('protocol_dictionary.txt')
