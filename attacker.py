import socket

# Attacks on target
ATTACK_TYPE = [
	'ARP_POISON',
	'DNS_HIJACK',
	'DNS_AMPLIFY',
	'SMURF',
	'SYN_FLOOD',
	'NTP_AMPLIFY',
	'INVALID'
]

class Attacker:
	def __init__(self, target:str, spoof_ip:str=None, attack=None):
		self.target_ipv4 = socket.gethostbyname(target)

		if spoof_ip is not None:
			self.spoof_ip = socket.gethostbyname(spoof_ip)

		if attack in ATTACK_TYPE:
			self.attack = attack
		else:
			self.attack = 'INVALID'

	def print_target_ip(self):
		print("[*] Target IP: " + self.target_ipv4)

	def setup_config(self):
		pass

def main():
	a = Attacker("192.168.1.2", attack="SYN_FLOOD")
	print(a.__dict__)
	a.print_target_ip()

	b = Attacker("www.absolute.com")
	print(b.__dict__)
	b.print_target_ip()

if __name__ == "__main__":
	main()