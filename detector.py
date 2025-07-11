from scapy.all import *
import sys

def process_pcap(pcap_fname):
    synLst = {}
    ackLst = {}
    for pkt in PcapReader(pcap_fname):
        # Your code here
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            if pkt[IP].src not in synLst:
                synLst[pkt[IP].src] = {"Count":0}
            synLst[pkt[IP].src]["Count"] += 1
            
        if pkt.haslayer(TCP) and pkt[TCP].flags == "SA":
            if pkt[IP].dst not in ackLst:
                ackLst[pkt[IP].dst] = {"Count":0}
            ackLst[pkt[IP].dst]["Count"] += 1

    for x in synLst:
        if x in ackLst:
            if (synLst[x]["Count"]) > (ackLst[x]["Count"] * 3):
                print(x)
        else:
            print(x)



if __name__=='__main__':
    if len(sys.argv) != 2:
        print('Use: python3 detector.py file.pcap')
        sys.exit(-1)
    process_pcap(sys.argv[1])
