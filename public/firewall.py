#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
	self.wall_rules = open(config['rule'], 'r')
	self.geo = []
	self.TCP_rules = []
	self.UDP_rules = []
	self.ICMP_rules = []

        # http log state variables
        self.TCP_connections = {}
        self.http_logFile = open('http.log', 'w+')

	with open(config['rule'], 'r') as file:
		for line in file:
			if line[0] != "\n" and line[0] != '%':
                                if line[0].upper() == 'L' and line[1].upper() == 'O' and line[2].upper() == 'G':
                                        self.TCP_rules.append(line)
				if line[5].upper() == 'T' and line[6].upper() == 'C' and line[7].upper() == 'P':
					self.TCP_rules.append(line)
				if line[5].upper() == 'U' and line[6].upper() == 'D' and line[7].upper() == 'P':
					self.UDP_rules.append(line)
				if line[5].upper() == 'I' and line[6].upper() == 'C' and line[7].upper() == 'M' and line[8].upper() == 'P':	
					self.ICMP_rules.append(line)
				if line[5].upper() == 'D' and line[6].upper() == 'N' and line[7].upper() == 'S':
					self.UDP_rules.append(line)

	with open('geoipdb.txt', 'r') as file2:
		for line2 in file2:
			self.geo.append(line2)
   
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
	try:
		internal_port = 0
		external_port = 0
		internal_address = 0
		external_address = 0
		domain_name = ''
		QType = 0
		DNS = False
		IHL = ord(pkt[0]) & 0x0f
	      	if IHL < 5:
			return
		protocol = ord(pkt[9])
		if protocol != 6 and protocol != 17 and protocol != 1:
			if pkt_dir == PKT_DIR_INCOMING:
				self.iface_int.send_ip_packet(pkt)
				return
			else:
				self.iface_ext.send_ip_packet(pkt)
				return
		if pkt_dir == PKT_DIR_OUTGOING:
			external_address = socket.inet_ntoa(pkt[16:20])
			internal_address = socket.inet_ntoa(pkt[12:16])                        
		else:
			external_address = socket.inet_ntoa(pkt[12:16]) 
			internal_address = socket.inet_ntoa(pkt[16:20])                        
		if protocol == 6 or protocol == 17:
			if pkt_dir == PKT_DIR_OUTGOING:
				external_port = struct.unpack('!H', pkt[IHL*4 + 2: IHL*4 + 4])[0]
                                internal_port = struct.unpack('!H', pkt[IHL*4: IHL*4 + 2])[0]
			else:
				external_port = struct.unpack('!H', pkt[IHL*4: IHL*4 + 2])[0]
                                internal_port = struct.unpack('!H', pkt[IHL*4 + 2: IHL*4 + 4])[0]
			if protocol == 17:
				DNS_offset = IHL*4 + 8
				question_offset = DNS_offset + 12
				if pkt[question_offset:]:
					length_qname = 0
					while ord(pkt[question_offset + length_qname: question_offset + length_qname + 1]) != 0:
						length_qname += 1
					length_qname += 1
					store_length = length_qname
					QType_offset = question_offset + length_qname
					QDCount = struct.unpack('!H', pkt[DNS_offset + 4 : DNS_offset + 6])[0]
					QType = struct.unpack('!H', pkt[QType_offset : QType_offset + 2])[0]
					QClass = struct.unpack('!H', pkt[QType_offset + 2 : QType_offset + 4])[0]
					if pkt_dir == PKT_DIR_OUTGOING and QDCount == 1 and (QType == 1 or QType == 28) and QClass == 1 and external_port == 53:
						DNS = True
						domain_name = ''
						new_offset = question_offset
						while 1:
							length_byte = ord(pkt[new_offset])
							if length_byte == 0:
								break
							count = 1
							length_qname -= 1
							while length_byte > 0:
								domain_name += pkt[new_offset + count]
								count += 1
								length_byte -= 1
								length_qname -= 1
							new_offset += count
							if length_qname > 1:
								domain_name += '.'
	
		if protocol == 1:
			external_port = ord(pkt[IHL])
		deny_pass = self.handle_rules(protocol, internal_address, internal_port, pkt_dir, external_address, external_port, domain_name, DNS, pkt)
		if deny_pass == True:
                        print("through")
			if pkt_dir == PKT_DIR_INCOMING:
				self.iface_int.send_ip_packet(pkt)
			else:
				self.iface_ext.send_ip_packet(pkt)
			return
		elif deny_pass == False:
			print("never")
			if protocol == 6:
				self.make_RST(pkt, IHL*4, pkt_dir)
			if DNS == True and QType == 1:
				self.make_DNS(pkt, IHL*4, DNS_offset, store_length, pkt_dir)
			return
	except (socket.error, struct.error, IndexError, KeyError, TypeError, ValueError, UnboundLocalError):
		print("mistakes were made")
		return
    def handle_rules(self, protocol, internal_address, internal_port, pkt_dir, external_address, external_port, domain_name, DNS, pkt):

	matches_DNS = False
        http = external_port == 80 #true if packet is an http request or response
        
	if protocol == 17:
                print "p - 17"
		rules = list(self.UDP_rules)
		while len(rules) > 0:
			rule = rules.pop()
			rule_split = rule.lower().split()
			if DNS == True:
				if rule_split[2] == domain_name:
					matches_DNS = True
				elif '*' in rule_split[2]:
					DNS_name = rule_split[2].replace('*', '')
					if domain_name.endswith(DNS_name):
						matches_DNS = True
                            
			matches_port = False
			matches_address = False
			if rule_split[2] == 'any' or external_address == rule_split[2]:
				matches_address = True
			elif '/' in rule_split[2]:
				address = struct.unpack('!L', socket.inet_aton(external_address))[0]
				interpret = rule_split[2].split('/')
				network_prefix, mask_bits = interpret[0], interpret[1]
				address2 = struct.unpack('!L', socket.inet_aton(network_prefix))[0]
				netmask = ~((1 << 32 - int(mask_bits)) - 1)
				if address & netmask == address2 & netmask:
					matches_address = True
			elif rule_split[2] != 'any' and rule_split[2].isalpha():
				matches_address = self.bin_geo_search(rule_split[2], external_address, 0, len(self.geo) - 1)
			if len(rule_split) == 4:
				if rule_split[3] == 'any' or rule_split[3] == str(external_port):
					matches_port = True
				elif '-' in rule_split[3]:
					port_range = rule_split[3].split('-')
					if external_port in range(int(port_range[0]), int(port_range[1]) + 1):
						matches_port = True 
			if matches_port == True and matches_address == True:
				if rule_split[0] == 'drop' or rule_split[0] == 'deny':
					return False
				return True
			if DNS == True and matches_DNS == True:
				if rule_split[0] == 'drop' or rule_split[0] == 'deny':
					return False
				return True
			else:
				continue
		return True
	else:
		if protocol == 1:
                        print "p = 1"
			rules2 = list(self.ICMP_rules)
		else:
                        print "p = 6"
			rules2 = list(self.TCP_rules)
		
		while len(rules2) > 0:
                        print "tcp rules length ", len(rules2)
			rule = rules2.pop()
			rule_split = rule.lower().split()

                        #if the rule is log, process seperately
                        if rule_split[0] == 'log':
                            print "in log rule"
                            if http:
                                print "in http connection",
                                #defines identifier (5-tuple curr) and pair_id (5_tuple pair)
                                identifier = (internal_address, internal_port, external_address, external_port, pkt_dir)
                                if pkt_dir == PKT_DIR_INCOMING:
                                    pair_dir = PKT_DIR_OUTGOING
                                else:
                                    pair_dir = PKT_DIR_INCOMING
                                pair_id = (internal_address, internal_port, external_address, external_port, pair_dir)

                                #find the start of the TCP payload (i.e. the http header)
                                IHL = ord(pkt[0]) & 0x0f
                                TCP_offset = ord(pkt[IHL*4 + 12]) & 0xf0
                                TCP_payload = pkt[IHL*4 + TCP_offset * 4:]
                                TCP_seq = struct.unpack('!L', pkt[IHL*4 + 4: IHL*4 + 8])[0]                            

                                #existing connection
                                if identifier in self.TCP_connections:
                                    http_packet, pkt_seq = self.TCP_connections.get(identifier)[0], self.TCP_connections.get(identifier)[1]
                                    #if seq is what's expected, recognize as the next packet in line
                                    FIN_flag = ord(pkt[IHL*4 + 13]) & 0x01
                                    if FIN_flag:
                                        next_seq = TCP_seq + 1
                                    elif pkt_seq == TCP_seq:
                                        http_packet += TCP_payload
                                        next_seq = pkt_seq + len(TCP_payload)/4
                                    #let through old packets and drop all ones past expected
                                    if pkt_seq < TCP_seq:
                                        continue
                                    if pkt_seq > TCP_seq:
                                        return False

                                #new connection, grab the http portion of the packet and calc the expected next seq
                                #note: if not SYN packet, cannot be new connection/out of order packet, therefore ignore
                                else:
                                    SYN_flag = ord(pkt[IHL*4 + 13]) & 0x02
                                    http_packet = TCP_payload
                                    if SYN_flag:
                                        next_seq = TCP_seq + 1
                                    else:
                                        continue

                                #once the packet is fully transmitted
                                if "\r\n\r\n" in http_packet:
                                    print http_packet
                                    #parse the http information
                                    http_header = http_packet.split("\r\n\r\n")[0]
                                    http_header1 = http_header.lower().split("\r\n")
                                    http_header = []
                                    for line in http_header1:
                                        if ':' in line:
                                            field = line.split(":")
                                            http_header.append(field[0])
                                            http_header.append(field[1])
                                        else:
                                            http_header.append(line)

                                    # if it's a request http packet
                                    if pkt_dir == PKT_DIR_OUTGOING:
                                        # get host name
                                        if "host" in http_header:
                                            http_host = http_header[http_header.index("host") + 1]
                                        else:
                                            http_host = external_address

                                        #reusing domain matching algorithm, but modified for host name
                                        hostNameMatch = False
			                if rule_split[2] == http_host:
				            hostNameMatch = True
			                elif '*' in rule_split[2]:
				            host_name = rule_split[2].replace('*', '')
				            if http_host.endswith(host_name):
				                hostNameMatch = True

                                        #if it matches, start parsing
                                        if hostNameMatch:
                                            fields = {}
                                            print http_header[0]
                                            fields["host"] = host_name
                                            fields["method"] = http_header[0].split(" ")[0].upper()
                                            fields["path"] = http_header[0].split(" ")[1]
                                            fields["version"] = http_header[0].split(" ")[2].upper()

                                            #save to TCP_connections
                                            self.TCP_connections[identifier] = ("", next_seq, True, fields)

                                    #if it's a response packet
                                    else:
                                        #check for valid partner
                                        partner = self.TCP_connections.get(pair_id)
                                        if pair_id in self.TCP_connections and self.TCP_connections.get(pair_id)[2]:
                                            #parse necessary fields
                                            fields = self.TCP_connections.get(identifier)
                                            fields["status"] = http_header[0].split(" ")[1]
                                            fields["size"] = http_header[http_header.index("content-type") + 1]    

                                            #create log
                                            http_log = fields["host"] + fields["method"] + fields["path"] + fields["version"] + fields["status"] + fields["size"] + "/r/n"

                                            #delete the packet string
                                            TCP_connections[identifier] = ("", next_seq, False, {})

                                            #save log and print the results
                                            print http_log
                                            self.http_logFile.write(http_log)
                                            
                                #if the packet is not fully transmitted
                                else:
                                    #save existing packet information to the connections
                                    self.TCP_connections[identifier] = (http_packet, next_seq, False, {})
                                    continue

                            # log rules do nothing for non http packets
                            else:
                                continue
                                    
                        #run normal tcp_rulematching otherwise
                        else:
                                print "in tcp normal matchmaking"
				matches_port = False
			        matches_address = False
			        if rule_split[2] == 'any' or external_address == rule_split[2]:
				        matches_address = True
			        elif '/' in rule_split[2]:
				        address = struct.unpack('!L', socket.inet_aton(external_address))[0]
				        interpret = rule_split[2].split('/')
				        network_prefix, mask_bits = interpret[0], interpret[1]
				        address2 = struct.unpack('!L', socket.inet_aton(network_prefix))[0]
				        netmask = ~((1 << 32 - int(mask_bits)) - 1)
				        if address & netmask == address2 & netmask:
					        matches_address = True
			        elif rule_split[2] != 'any' and rule_split[2].isalpha():
				        matches_address = self.bin_geo_search(rule_split[2], external_address, 0, len(self.geo) - 1)
			        if rule_split[3] == 'any' or rule_split[3] == str(external_port):
				        matches_port = True
			        elif '-' in rule_split[3]:
				        port_range = rule_split[3].split('-')
				        if external_port in range(int(port_range[0]), int(port_range[1]) + 1):
					        matches_port = True 
			        if matches_port == True and matches_address == True:
				        if rule_split[0] == 'drop' or rule_split[0] == 'deny':
					        return False
				        return True
			        else:
				        continue
                #returns true
			return True
		return True		
				
    def bin_geo_search(self, country, address, first, last):
	if first > last:
		return False
	middle = (first + last) // 2
	address_range = self.geo[middle].split()
	low = self.sorry_inet_aton(address_range[0])
	high = self.sorry_inet_aton(address_range[1])
	compare = self.sorry_inet_aton(address)
	if compare >= low and compare <= high:
		if address_range[2].upper() == country.upper():
			return True
		return False
	elif compare < low:
		return self.bin_geo_search(country, address, first, middle - 1)
	else:
		return self.bin_geo_search(country, address, middle + 1, last)

    def sorry_inet_aton(self, address):
	num = address.split('.')
	return int(num[3]) + 1000 * int(num[2]) + 1000000 * int(num[1]) + 1000000000 * int(num[0])

    def make_DNS(self, pkt, header_offset, DNS_offset, qname_length, pkt_dir):
	DNS_packet = ''
	DNS_packet += struct.pack('!B', 0x45)
	DNS_packet += pkt[1:2]
	packet_length = 20 + 8 + 12 + qname_length + 4 + qname_length + 10 + 4
	DNS_packet += struct.pack('!H', packet_length)
	#DNS_packet += pkt[4:8]
	DNS_packet += struct.pack('!L', 0x0)
	DNS_packet += struct.pack('!L', 0x80110000)
	DNS_packet += pkt[16:20]
	DNS_packet += pkt[12:16]
	checksum = self.calc_checksum(20, DNS_packet)
	DNS_packet = DNS_packet[0:10] + checksum + DNS_packet[12:20]
	DNS_packet += struct.pack('!H', 0x35)
	DNS_packet += pkt[header_offset:header_offset+2]
	DNS_packet += struct.pack('!H', packet_length - 20)
	DNS_packet += struct.pack('!H', 0x0)
	DNS_packet += pkt[DNS_offset: DNS_offset+2]
	DNS_packet += struct.pack('!B', 0x81)
	DNS_packet += struct.pack('!B', 0x00)
	DNS_packet += struct.pack('!L', 0x00010001)
	DNS_packet += struct.pack('!L', 0x0)
	question = pkt[DNS_offset + 12: DNS_offset + qname_length + 12]
	DNS_packet += question 
	DNS_packet += struct.pack('!L', 0x00010001)
	DNS_packet += question
	DNS_packet += struct.pack('!L', 0x00010001)
	DNS_packet += struct.pack('!L', 0x3C)
	DNS_packet += struct.pack('!H', 0x4)
	DNS_packet += struct.pack('!L', 0xA9E53182)
	if pkt_dir == PKT_DIR_INCOMING:
		self.iface_int.send_ip_packet(DNS_packet)
	else:
		self.iface_ext.send_ip_packet(DNS_packet)

    def make_RST(self, pkt, header_offset, pkt_direction):
	RST_packet = ''
	RST_packet += struct.pack('!B', 0x45)
	RST_packet += pkt[1]
	RST_packet += struct.pack('!H', 0x28)
	#RST_packet += pkt[4:8]
	RST_packet += struct.pack('!L', 0x0)
	#RST_packet += struct.pack('!B', 0x80)
	#RST_packet += struct.pack('!B', 0x6)
	#RST_packet += struct.pack('!H', 0x0)
	RST_packet += struct.pack('!L', 0x80060000)
	RST_packet += pkt[16:20]
	RST_packet += pkt[12:16]
	checksum = self.calc_checksum(20, RST_packet)
	RST_packet = RST_packet[0:10] + checksum + RST_packet[12:20]
	TCP = ''
	TCP += pkt[header_offset+2:header_offset+4]
	TCP += pkt[header_offset:header_offset+2]
	TCP += struct.pack('!L', 0x0)
	sequence_number = struct.unpack('!L', pkt[header_offset + 4: header_offset + 8])[0]
	sequence_number += 1
	sequence_number = struct.pack('!L', sequence_number)
	TCP += sequence_number
	TCP += struct.pack('!L', 0x50140000)
	TCP += struct.pack('!L', 0x0)
	RST_packet += TCP
	pseudoheader = ''
	pseudoheader += RST_packet[16:20]
	pseudoheader += RST_packet[12:16]
	pseudoheader += struct.pack('!H', 0x0006)
	pseudoheader += struct.pack('!H', 0x14)
	pseudoheader += TCP
	checksum2 = self.calc_checksum(32, pseudoheader)
	RST_packet = RST_packet[0:36] + checksum2 + RST_packet[38:40]
	if pkt_direction == PKT_DIR_INCOMING:
		self.iface_int.send_ip_packet(RST_packet)
	else:
		self.iface_ext.send_ip_packet(RST_packet)

    def calc_checksum(self, header_size, RST_packet):
	checksum = 0
	for i in range(0, header_size, 2):
		checksum += struct.unpack('!H', RST_packet[i:i+2])[0]
		i += 2
	if checksum >> 16 != 0:
		while checksum >> 16 != 0:
			checksum = (checksum >> 16) + (checksum & 0xFFFF)
	checksum = ~checksum
	checksum = checksum & 0xFFFF
	checksum = struct.pack('!H', checksum)
	return checksum


# TODO: You may want to add more classes/functions as well.
