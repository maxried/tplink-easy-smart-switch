#!/usr/bin/env python3

from TLPacket import *

class PortStatisticsPort:
    def __init__(self, portnumber, enabled, mode, tg, tb, rg, rb):
        self.number = portnumber
        self.enabled = enabled
        self.current_mode = mode
        self.rx_good = rg
        self.rx_bad = rb
        self.tx_good = tg
        self.tx_bad = tb


class PortStatistics:
    def __init__(self, packet):
        self.ports = []

        for i in packet.TLVs:
            if i.tag == 16384 and len(i.value) == 19:
                stat = PortStatisticsPort(
                    i.value[0],
                    i.value[1] == 1,
                    i.value[2],
                    (i.value[3] << 24) + (i.value[4] << 16) + (i.value[5] << 8) + i.value[6],
                    (i.value[7] << 24) + (i.value[8] << 16) + (i.value[9] << 8) + i.value[10],
                    (i.value[11] << 24) + (i.value[12] << 16) + (i.value[13] << 8) + i.value[14],
                    (i.value[15] << 24) + (i.value[16] << 16) + (i.value[17] << 8) + i.value[18])

                self.ports.append(stat)

    def print_ports(self):
        modes = {0: "Link Down", 1: "Auto", 2: "10Half",
                 3: "10Full", 4: "100Half", 5: "100Full", 6: "1000Full"}

        for i in self.ports:
            state = "enabled" if i.enabled else "disabled"
            mode = modes.get(i.current_mode, "Unknown")

            print('{0:2d} {1:8s} {2:16s} {3:11d} {4:11d} {5:11d} {6:11d}'
                  .format(i.number, state, mode, i.tx_good, i.tx_bad, i.rx_good, i.rx_bad))
