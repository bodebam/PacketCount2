#!/anaconda3/bin/python3

# this counts packets for each unique pair of sourc/destination addresses

from scapy.all import *

pkts = rdpcap("dns-essex.pcapng")
Addrs = dict()
for pkt in pkts:
    #print(pkt[IP].dst)
    Addr = pkt[IP].src + " " + pkt[IP].dst
    if Addr in Addrs:
        Addrs[Addr] = Addrs[Addr]+1
    else:
        Addrs[Addr] = 1

for addr in Addrs:
    print(addr, ":", Addrs[addr])


