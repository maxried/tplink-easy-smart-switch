#!/usr/bin/env python3

from TLPacket import *
from TLTLVs import *
from random import randint


def forgeCommonPacket(opcode, switchMAC = b'\x00\x00\x00\x00\x00\x00', computerMAC = b'\x00\x00\x00\x00\x00\x00', token = 0):
    p = TLPacket()

    p.Version = 1
    p.Opcode = opcode
    p.MACSwitch = switchMAC
    p.MACComputer = computerMAC
    p.SequenceNumber = randint(0, 1000)
    p.ErrorCode = 0
    p.Length = 0
    p.Fragment = 0
    p.Flags = 0
    p.Token = token
    p.Checksum = 0
    return p



def endTLVList(packet):
    t = TLV()
    t.Tag = 65535
    t.Length = 0
    t.Value = b''
    packet.TLVs.append(t)



def forgeDiscovery():
    p = forgeCommonPacket(0)
    endTLVList(p)

    return p.toByteArray()



def forgeGetToken(switchMAC):
    p = forgeCommonPacket(1, switchMAC)

    t = TLV()
    t.Tag = 2305
    t.Length = 0
    t.Value = b''
    p.TLVs.append(t)

    endTLVList(p)

    return p.toByteArray()



def forgeLogin(switchMAC, token, user, password):
    p = forgeCommonPacket(3, switchMAC, b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.Tag = 512
    t.setStringValue(user)
    p.TLVs.append(t)

    t = TLV()
    t.Tag = 514
    t.setStringValue(password)
    p.TLVs.append(t)

    endTLVList(p)

    return p.toByteArray()


def forgeCableTest(switchMAC, token, portnum, user, password):
    p = forgeCommonPacket(3, switchMAC,  b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.Tag = 512
    t.setStringValue(user)
    p.TLVs.append(t)

    t = TLV()
    t.Tag = 514
    t.setStringValue(password)
    p.TLVs.append(t)

    dataA = bytearray()
    dataA.append(portnum & 0xFF)
    dataA.append(0x01)
    dataA.append(0x00)
    dataA.append(0x00)
    dataA.append(0x00)
    dataA.append(0x00)
    t = TLV()
    t.Tag = 16896
    t.Value = bytes(dataA)
    t.Length = 6
    p.TLVs.append(t)

    endTLVList(p)

    return p.toByteArray()


def forgeGetPortStats(switchMAC, token):
    p = forgeCommonPacket(1, switchMAC, b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.Tag = 16384
    t.Length = 0
    t.Value = b''
    p.TLVs.append(t)

    endTLVList(p)

    return p.toByteArray()
