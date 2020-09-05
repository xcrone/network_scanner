#!/usr/bin/env python3

# pip3 install scapy
# run as root [sudo python3 main.py]
import scapy.all as scapy

def scan(ip):
	scapy.arping(ip)

scan("192.168.0.1/24")