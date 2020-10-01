#!/usr/bin/env python3

# pip3 install scapy
# run as root [sudo python3 main.py]
import scapy.all as scapy
import argparse
import socket 

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="Target <ip_address>/<range>")
	options = parser.parse_args()
	if not options.target:
		parser.error("[ERROR] Please define target using -t or --target.\nUse --help for more info.\n")
	return options

def scan(client_ip):
	client_mac = "ff:ff:ff:ff:ff:ff"

	# set pdst to client ip
	arp_request = scapy.ARP(pdst=client_ip)

	# create ethernet frame
	broadcast = scapy.Ether()
	# set destination Mac Address
	broadcast.dst = client_mac

	# combined arp_request and broadcast as a package
	arp_request_broadcast = broadcast/arp_request

	# send a package
	# sr -> (send and recieve)
	# srp -> (send and recieve with package)
	# timeout is to keep move on if it didn't get any response
	# verbose is to hide process while sending
	# index 0 is for answered list, while index 1 is for unanswered list
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

	client_list = []
	if len(answered_list) == 0:
		print("  No Result")
	else:
		for elem in answered_list:
			client_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
			client_list.append(client_dict)
	return client_list

def get_Host_name_IP(ip): 
	try:
		host_ip = socket.gethostbyaddr(ip)[0]
	except: 
		host_ip = "None"

	return host_ip
  
def print_result(result_list):
	# \t is a tab in string
	print("-----------------------------------------------------------------------------------")
	print("| IP\t\t\t| MAC Address\t\t\t| HostName")
	print("-----------------------------------------------------------------------------------")
	for client in result_list:
		print("| " + client["ip"] + "\t\t| " + client["mac"] + "\t\t| " + get_Host_name_IP(client["ip"]))
	print("-----------------------------------------------------------------------------------\n")

options = get_args()
scan_result = scan(options.target)
print_result(scan_result)









