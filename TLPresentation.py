#!/usr/bin/env python3

from TLPacket import *
from TLTLVs import *
from TLInfos import *


def extractTokenFromHeader(packet):
    return packet.Token
 

def isDiscovery(request, packet):
    return len(packet.TLVs) == 10 and packet.Version == 1 and packet.Opcode == 2 and packet.SequenceNumber == request.SequenceNumber

def presentDiscovery(packet):
    model = ''
    name = ''
    fwversion = ''
    ip = ''

    for t in packet.TLVs:
        if t.Tag == 8:
            model = t.getHumanReadableValue()
        elif t.Tag == 2:
            name = t.getHumanReadableValue()
        elif t.Tag == 7:
            fwversion = t.getHumanReadableValue()
        elif t.Tag == 4:
            ip = t.getHumanReadableValue()

    print('{0:31s} {1:15s} {2:31s} {3:10s}'.format(name, ip, model, fwversion))



def presentPortStatistics(packet):
    print('{0:>2s} {1:<8s} {2:<16s} {3:>10s} {4:>10s} {5:>10s} {6:>10s}'.format('#', 'State', 'Mode', 'Tx Good', 'Tx Bad', 'Rx Good', 'Rx Bad'))
    stats = PortStatistics(packet)
    stats.printPorts()


def presentCableTest(packet):
    TestResults = {0: 'no cable', 1: 'normal', 2: 'open', 3: 'short', 4: 'open and short', 5: 'cross-over'}

    for i in packet.TLVs:
        if i.Tag == 16896 and len(i.Value) == 6:
            print('Port ' + str(i.Value[0]) + ': Length ' + str(i.Value[5]) + ', Result: ' + TestResults.get(i.Value[1], 'unknown'))

    print()