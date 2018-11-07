import dpkt
from dpkt.tcp import TCP
import sys
import socket
import json

f = open(sys.argv[1])
pcap = dpkt.pcap.Reader(f)
d = {}



for ts,buf in pcap:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if type(ip.data) == TCP:
            if (tcp.flags & dpkt.tcp.TH_SYN) != 0 and not (tcp.flags & dpkt.tcp.TH_ACK) != 0:
               if ip.src not in d:
                    d[ip.src] = {'syn-count': 0, 'syn-ack-count': 0 }
               d[ip.src]['syn-count'] += 1
            if (tcp.flags & dpkt.tcp.TH_SYN) != 0 and (tcp.flags & dpkt.tcp.TH_ACK) != 0:
               if ip.dst not in d:
                    d[ip.dst] = {'syn-count': 0, 'syn-ack-count': 0 }
               d[ip.dst]['syn-ack-count'] += 1
    except:
        pass


for key,value in d.iteritems():
    if value['syn-count'] > 3 * value['syn-ack-count']:
        print socket.inet_ntoa(key)