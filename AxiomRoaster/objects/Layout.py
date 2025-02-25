#!/usr/bin/python3

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from typing import Literal

from AxiomRoaster.core.parse_args import AxiomArgParser
from AxiomRoaster.objects.Clock import Clock
from AxiomRoaster.objects.Poisoner import Poisoner

class AppLayout():
    _APP_LAYOUT = None

    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.logs = []
        self.tickets = []
        self.live = None
        self.roasted = []

        AppLayout._APP_LAYOUT = self

    _LOG_TYPES = Literal["INFO", "SUCCESS", "ERROR"]
    @staticmethod
    def Log(type: _LOG_TYPES, content: str):
        if AppLayout._APP_LAYOUT is None:
            raise ValueError("[!] AppLayout is not assigned")

        AppLayout._APP_LAYOUT._Log(type, content)

    def _Log(self, type: _LOG_TYPES, content: str):
        colorDispatcher = {
            'INFO': 'blue',
            'SUCCESS': 'green',
            'ERROR': 'red'
        }

        self.logs.append({
            'level': {'text': type, 'color': colorDispatcher[type]},
            'content': content
        })
        self.Update()

    def Setup(self):
        self.layout.split(
            Layout(name = "header", size = 1),
            Layout(ratio = 1, name = "main"),
            Layout(size = 20, name = "Service Tickets")
        )
        self.layout["main"].split_row(
            Layout(name = "side"),
            Layout(name = "body", ratio = 2)
        )
        self.layout["side"].split(
            Layout(name = "Domain Controllers"),
            Layout(name = "Targets"),
            Layout(name = "Service Principal Names")
        )

        self.live = Live(self.layout, screen=True, redirect_stderr=False)
        return (self.live)

    @staticmethod
    def Update():
        if AppLayout._APP_LAYOUT is None:
            raise ValueError("[!] AppLayout is not assigned")

        AppLayout._APP_LAYOUT._Update()

    def _Update(self):
        args = AxiomArgParser.GetProgramArgs()

        self.layout["header"].update(Clock())

        # Print event logs
        if len(self.logs) == 0:
            self.layout["body"].update(Panel(Align.center(
                Text("Axiom Roaster", justify="center"),
                vertical='middle'
            )))
        else:
            content = Text("")
            for log in self.logs:
                content += Text(log['level']['text'], style=log['level']['color']) \
                    + Text(" - ", style="not bold white") \
                    + Text(f"{log['content']}\n", style="not bold white")
            self.layout["body"].update(Panel(content, title="Event Logs"))

        # Print captured service tickets
        if len(self.tickets) == 0:
            content = Text("No tickets", justify="center")
        else:
            content = Text("")
            for ticket in self.tickets:
                content += Text(ticket)
        self.layout["Service Tickets"].update(Panel(content, title="Service Tickets"))

        # Print DCs
        content = Text("")
        for dc in args.dcs: #type: ignore
            content += Text(dc, style="bold yellow") + Text(f"\t({Poisoner.GetMac(dc)})\n", style="not bold blue")
        self.layout["Domain Controllers"].update(Panel(content, title="Domain Controllers", style="yellow"))

        # Print targets
        content = Text("")
        for target in args.targets: #type: ignore
            content += Text(target, style="bold red") + Text(f"\t({Poisoner.GetMac(target)})\n", style="not bold blue")
        self.layout["Targets"].update(Panel(content, title="Targets", style="red"))

        # Print SPNs
        content = Text("")
        for spn in args.spn: #type: ignore
            pwned = ("(roasted)" if spn in self.roasted else "")
            content += Text(spn, style="bold green") + Text(f"\t{pwned}\n", style="bold yellow")
        self.layout["Service Principal Names"].update(Panel(content, title="Service Principal Names", style="green"))

    _TICKET_TYPE = Literal["TGS", "ASREQ"]
    @staticmethod
    def AddTicket(type: _TICKET_TYPE, principal: str, ticket_str: str):
        save_file = "kerberoast.out" if type == "TGS" else "asreq-roast.out"

        AppLayout._APP_LAYOUT.roasted.append(principal)
        AppLayout._APP_LAYOUT.tickets.append(f"[{type}] - {ticket_str[:70]}... (saved to {save_file})\n") # type: ignore
        AppLayout.Update()

