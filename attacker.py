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
	def __init__(self, target, spoof_ip=None, attack=None):
		self.target_ipv4 = socket.gethostbyname(target)

		if spoof_ip is not None:
			self.spoof_ip = socket.gethostbyname(spoof_ip)

		if attack in ATTACK_TYPE:
			self.attack = attack
		else:
			self.attack = 'INVALID'

	def print_target_ip(self):
		print("[*] Target IP: {}".format(self.target_ipv4))

	def setup_config(self):
		pass


#a = Attacker("192.168.1.2", "SYN_FLOOD")
#b = Attacker("www.absolute.com")
#c = Attacker("https://www.absolute.com")
#print(a.__dict__)
#print(b.__dict__)

