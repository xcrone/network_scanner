#!/usr/bin/env python3

# pip3 install scapy
# run as root [sudo python3 main.py]
import scapy.all as scapy

# def scan(client_ip):
# 	scapy.arping(client_ip)

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

	# \t is a tab in string
	print("---------------------------------------------------")
	print("| IP\t\t\t| MAC Address")
	print("---------------------------------------------------")
	if len(answered_list) == 0:
		print("  No Result")
	else:
		for elem in answered_list:
			print("| " + elem[1].psrc + "\t\t| " + elem[1].hwsrc)
	print("---------------------------------------------------\n")

scan("192.168.0.1/24")