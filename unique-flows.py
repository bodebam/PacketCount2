#!/anaconda3/bin/python3
# this captures each flow and prints the number of packets per flow (in each direction)
# but it has a bug, it prints both directions!

from scapy.all import *  

pkts = rdpcap("dns-essex.pcapng")
Addrs = dict()
for pkt in pkts:
    #print(pkt[IP].dst)
    # warning, this does not count non TCP or UDP flows
    # also if two flows use the same ports it will count it as one flow!
    if pkt[IP].proto == 6 or pkt[IP].proto == 17:
        Addr = pkt[IP].src + "|" + pkt[IP].dst + "|" + str(pkt[IP].proto) + "|" + str(pkt[IP].sport) + "|" + str(pkt[IP].dport)
    else:
        Addr = pkt[IP].src + "|" + pkt[IP].dst + "|" + pkt[IP].proto
        
    if Addr in Addrs:
        Addrs[Addr] = Addrs[Addr]+1
    else:
        Addrs[Addr] = 1

for addr in Addrs:
    print(addr, ":", Addrs[addr])
    raddrarr = addr.split("|")
    raddr = raddrarr[1] + "|" + raddrarr[0] + "|" + raddrarr[2] + "|" + raddrarr[4] + "|" + raddrarr[3]
    if raddr in Addrs:
        print("reverse:", raddr, ":", Addrs[raddr])
    