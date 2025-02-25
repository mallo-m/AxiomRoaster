#!/usr/bin/python3

import time

from AxiomRoaster.objects.Poisoner import Poisoner
from AxiomRoaster.core.parse_args import AxiomArgParser
from AxiomRoaster.objects.Layout import AppLayout
from AxiomRoaster.objects.Sniffer import Sniffer

def main():
    # Init arguments
    parser = AxiomArgParser()
    parser.Parse()
    parser.Validate()
    # Give time to read infos
    time.sleep(0.2)

    # Start ARP poisoner
    p = Poisoner()
    p.Start()

    # Prepare UI
    layout = AppLayout()
    with layout.Setup() as live:
        AppLayout.Update()
        AppLayout.Log(type='INFO', content='All target have been poisoned, spoofer is running')
        Sniffer.Start()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            pass

    p.Stop()

if __name__ == "__main__":
    main()

