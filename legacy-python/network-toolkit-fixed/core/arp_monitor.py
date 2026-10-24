from scapy.all import sniff, ARP
from datetime import datetime

def monitor_arp(callback):
    def process(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:
            info = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": pkt[ARP].psrc,
                "mac": pkt[ARP].hwsrc
            }
            callback(info)
    sniff(filter="arp", prn=process, store=0)
