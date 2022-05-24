from collections import Counter
from scapy.all import *
import sys
packet_list=[]
def storepkt(pkt):
    pkt = pkt.getlayer(Raw)
    
    packet_list.append(pkt)
    try:
        print(packet_list)
    except:
        pass
def help():
    print("Welcome to the help section\nthe arguements should be written as follows\nrun -i (network interface) -p\nthe arguement -i can be replaced with --iface\nthe argument -p can be replaced with --passive or -a / --active\n\npassive mode (-p/--passive) will gather connection data without active searching\nactive mode (-a/--active) will actively search connection data")
def format_input(arguement):
    arguement=arguement.split(" ")
    return arguement
def passive(runcount):
    conf.use_pcap = True
    global packet_counts
    packet_counts = Counter()
    sniff(filter="ip",prn=custom_action, count=runcount)
    g=[*(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items())]
    for x in g:
        print(x)
    
def run_output(formatted):
    if "-i" in formatted:
        net_if=formatted[formatted.index("-i")+1]
        print(net_if)
    if "-p" in formatted:
        passive(int(formatted[formatted.index("-p")+1]))
    if "-a" in formatted:
        get_active()
    if "help" in formatted:
        help()
def custom_action(packet):
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"
def get_active():

    target_ip = "192.168.0.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether/arp
    result = srp(packet, timeout=1, verbose=0)[0]
    clients = []
    for sent, received in result:

        clients.append({'ip': received.psrc})
    print("online")
    for x in clients:
        print(x["ip"])


arguement=input()
formatted=format_input(arguement)
run_output(formatted)

input()
