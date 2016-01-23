import datetime
from scapy.all import *

PACKETS_TO_SNIFF = 32
LOG_PATH = 'Log.txt'
RESOURCES_PATH = 'resources/'
IP_BLACKLIST_PATH = RESOURCES_PATH + 'ip_blacklist.txt'
FILES_BLACKLIST_PATH = RESOURCES_PATH + 'files_blacklist.txt'
URL_BLACKLIST_PATH = RESOURCES_PATH + 'url_blacklist.txt'



class firewall:
	def __init__(self):
		self.log = open(LOG_PATH, 'a+')
		self.ip_black_list = ['']
		self.url_black_list = ['']
		self.file_black_list = ['']
		with open(IP_BLACKLIST_PATH, 'r') as ip_file:
			self.ip_black_list = [line.rstrip('\n') for line in ip_file]
		with open(URL_BLACKLIST_PATH, 'r') as url_file:
			self.url_black_list = [line.rstrip('\n') for line in url_file]
		with open(FILES_BLACKLIST_PATH, 'r') as files_file:
			self.file_black_list = [line.rstrip('\n') for line in files_file]


	def cheack_packet(self, packet):
		self.compare_to_blacklist(packet)


	def compare_to_blacklist(self, packet):

		if IP in packet:
			if packet[IP].src in self.ip_black_list:
				self.log.write('%s\nsuspicous ip source\nsource:\t%s\tdestination:\t%s\t%s\n\n' 
					% (str(datetime.datetime.now()), packet[IP].src, packet[IP].dst, packet.summary()))
			if  packet[IP].dst in self.ip_black_list:
				self.log.write('%s\nsuspicous ip destination\nsource:\t%s\tdestination:\t%s\t%s\n\n' 
					% (str(datetime.datetime.now()), packet[IP].src, packet[IP].dst, packet.summary()))


		self.log.flush()

	def check_syn_flood(self, capture_list):
		""" CODE """
		pass

	def firewall_run(self): 
		time_text = "\nbegan snnifing at:\t%s\n\n" % str(datetime.datetime.now())
		self.log.write(time_text)
		self.log.flush()
		while True:
			sniff(PACKETS_TO_SNIFF, prn=self.cheack_packet)


def main():
	main_firewall = firewall()
	main_firewall.firewall_run()


if __name__ == '__main__':
	main()