#!/usr/bin/env python3

from typing import Tuple, List, Dict
from struct import unpack
from TLPacket import TLPacket
from TLTLVs import TLVTAGS, TLTLV

"""Toolbox to store the state of the switch"""


class PortStatisticsPort:
    """Stats of a single port"""
    def __init__(self, portstat: Tuple[int, bool, int, int, int, int, int]):
        self.number = portstat[0]  # type: int
        self.enabled = portstat[1]  # type: bool
        self.current_mode = portstat[2]  # type: int
        self.tx_good = portstat[3]  # type: int
        self.tx_bad = portstat[4]  # type: int
        self.rx_good = portstat[5]  # type: int
        self.rx_bad = portstat[6]  # type: int


class PortStatistics:
    """Stats of all port"""
    def __init__(self, packet: TLPacket):
        self.ports = []  # type: List[PortStatisticsPort]

        for i in packet.tlvs:  # type: TLTLV
            if i.tag == TLVTAGS['MONITOR_PORT_STATISTICS'] and len(i.value) == 19:
                stat = PortStatisticsPort(unpack('>B?BIIII', i.value))  # type: PortStatisticsPort
                self.ports.append(stat)

    def print_ports(self) -> None:
        """Prints the entire port statistic for all ports"""
        modes = {0: "Link Down", 1: "Auto", 2: "10Half",
                 3: "10Full", 4: "100Half", 5: "100Full", 6: "1000Full"}  # type: Dict[int, str]

        for i in self.ports:
            state = "enabled" if i.enabled else "disabled"  # type: str
            mode = modes.get(i.current_mode, "Unknown")  # type: str

            print('{0:>2d} {1:>8s} {2:>10s} {3:>10d} {4:>10d} {5:>10d} {6:>10d}'
                  .format(i.number, state, mode, i.tx_good, i.tx_bad, i.rx_good, i.rx_bad))
