#!/usr/bin/env python3

from struct import unpack

from TLTLVs import TLVTAGS

"""Toolbox to store the state of the switch"""

class PortStatisticsPort:
    """Stats of a single port"""
    def __init__(self, portstat):
        self.number = portstat[0]
        self.enabled = portstat[1]
        self.current_mode = portstat[2]
        self.tx_good = portstat[3]
        self.tx_bad = portstat[4]
        self.rx_good = portstat[5]
        self.rx_bad = portstat[6]


class PortStatistics:
    """Stats of all port"""
    def __init__(self, packet):
        self.ports = []

        for i in packet.tlvs:
            if i.tag == TLVTAGS['MONITOR_PORT_STATISTICS'] and len(i.value) == 19:
                stat = PortStatisticsPort(unpack('>B?BIIII', i.value))
                self.ports.append(stat)

    def print_ports(self):
        """Prints the entire port statistic for all ports"""
        modes = {0: "Link Down", 1: "Auto", 2: "10Half",
                 3: "10Full", 4: "100Half", 5: "100Full", 6: "1000Full"}

        for i in self.ports:
            state = "enabled" if i.enabled else "disabled"
            mode = modes.get(i.current_mode, "Unknown")

            print('{0:2d} {1:8s} {2:16s} {3:11d} {4:11d} {5:11d} {6:11d}'
                  .format(i.number, state, mode, i.tx_good, i.tx_bad, i.rx_good, i.rx_bad))
