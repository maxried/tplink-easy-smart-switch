#!/usr/bin/env python3

from TLPacket import *

class PortStatisticsPort:
    def __init__(self, num, ena, cMode, tg, tb, rg, rb):
        self.Number = num
        self.Enabled = ena
        self.CurrentMode = cMode
        self.RxGood = rg
        self.RxBad = rb
        self.TxGood = tg
        self.TxBad = tb


class PortStatistics:
    def __init__(self, packet):
        self.Ports = []
        for i in packet.TLVs:
            if i.Tag == 16384 and len(i.Value) == 19:
                p = PortStatisticsPort(
                    i.Value[0],
                    i.Value[1] == 1,
                    i.Value[2],
                    (i.Value[3] << 24) + (i.Value[4] << 16) + (i.Value[5] << 8) + i.Value[6], 
                    (i.Value[7] << 24) + (i.Value[8] << 16) + (i.Value[9] << 8) + i.Value[10],
                    (i.Value[11] << 24) + (i.Value[12] << 16) + (i.Value[13] << 8) + i.Value[14], 
                    (i.Value[15] << 24) + (i.Value[16] << 16) + (i.Value[17] << 8) + i.Value[18]
                    )
                self.Ports.append(p)

    def printPorts(self):
        modes = {0: "Link Down", 1: "Auto", 2: "10Half", 3: "10Full", 4: "100Half", 5: "100Full", 6: "1000Full"}

        for i in self.Ports:
            state = "enabled" if i.Enabled else "disabled"
            mode = modes.get(i.CurrentMode, "Unknown")

            print('{0:2d} {1:8s} {2:16s} {3:11d} {4:11d} {5:11d} {6:11d}'.format(i.Number, state, mode, i.TxGood, i.TxBad, i.RxGood, i.RxBad))
