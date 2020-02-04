#!/anaconda3/bin/python3

# this counts packets for each unique destination addresses

from scapy.all import *

pkts = rdpcap("dns-essex.pcapng")
dstAddrs = dict()
for pkt in pkts:
    #print(pkt[IP].dst)
    dstAddr = pkt[IP].dst
    if dstAddr in dstAddrs:
        dstAddrs[dstAddr] = dstAddrs[dstAddr]+1
    else:
        dstAddrs[dstAddr] = 1

for addr in dstAddrs:
    print(addr, ":", dstAddrs[addr])
    
    
    
    
    


