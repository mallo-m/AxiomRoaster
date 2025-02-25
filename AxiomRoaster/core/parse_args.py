#!/usr/bin/python3

import netifaces
import ipaddress
from argparse import ArgumentParser

class AxiomArgParser():
    args = None

    @staticmethod
    def SetProgramArgs(a):
        AxiomArgParser.args = a

    @staticmethod
    def GetProgramArgs():
        return (AxiomArgParser.args)

    def __init__(self):
        self._parser = ArgumentParser(description='Zero-auth Kerberoasting and AS-REQ roasting')

    def Parse(self):
        if self._parser is None:
            raise ValueError("AxiomArgParser was not properly initialized")

        self._parser.add_argument(
            "--iface",
            type=str,
            help='The interface to listen/attack on',
            required=True
        )

        # Note, this tool is not yet implemented to support multiple DCs. I just added the option
        # to remind me to do it later
        self._parser.add_argument(
            "--dcs",
            help='List of domain controllers to relay authenticators to. Usually one is enough.',
            nargs='+',
            default=[],
            required=True
        )

        # Those IPs will be ARP-poisoned, their network traffic will go through our box
        self._parser.add_argument(
            "--targets",
            help='List of IP to poison, at least one is required',
            nargs='+',
            default=[],
            required=True
        )

        # We need a SPN list to try and request STs for
        self._parser.add_argument(
            "--spn",
            help='List of SPNs to attack',
            nargs='+',
            default=[],
            required=True
        )

        # We obviously need to know who we are
        self._parser.add_argument(
            '--source-mac',
            type=str,
            help='Our MAC address. Where to redirect packets to. If not provided, retrieved automatically from the specified interface.'
        )

        self._args = self._parser.parse_args()

    def Validate(self):
        if self._args is None:
            raise ValueError("You must parse arguments before validating them")

        # Check that the provided interface exists
        interfaces = netifaces.interfaces()
        if self._args.iface is None or self._args.iface not in interfaces:
            raise ValueError(f"[!] Invalid interface name provided: {self._args.iface}")
        print(f"[*] Interface {self._args.iface} found")

        # Validate the provided MAC address
        if self._args.source_mac is None:
            try:
                self._args.source_mac = netifaces.ifaddresses(self._args.iface)[netifaces.AF_LINK][0]['addr']
            except:
                raise ValueError("[!] Failed to automatically retrieve the interface's mac address, try manually specifying it with --source-mac")
        print(f"[*] Using MAC: {self._args.source_mac}")

        # Check that the provided DCs and targets are valid IPs (yes it's hacky but it works)
        # If the ip is invalid it will throw a ValueError exception
        for dc in self._args.dcs:
            ipaddress.IPv4Address(dc)
        print(f"[*] Using DCs: {','.join(self._args.dcs)}")

        for target in self._args.targets:
            ipaddress.IPv4Address(target)
        print(f"[*] Targeting machines: {','.join(self._args.targets)}")

        print(f"[*] Will try and attack SPNs: {','.join(self._args.spn)}")

        AxiomArgParser.SetProgramArgs(self._args)

