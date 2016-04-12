#!/usr/bin/env python3

from random import randint

from TLPacket import *
from TLTLVs import *


def forge_common_packet(opcode, switchMAC=b'\x00\x00\x00\x00\x00\x00', computerMAC=b'\x00\x00\x00\x00\x00\x00', token=0):
    p = TLPacket()

    p.version = 1
    p.opcode = opcode
    p.mac_switch = switchMAC
    p.mac_computer = computerMAC
    p.sequence_number = randint(0, 1000)
    p.error_code = 0
    p.length = 0
    p.fragment = 0
    p.flags = 0
    p.token = token
    p.checksum = 0
    return p



def end_tlv_list(packet):
    t = TLV()
    t.tag = 65535
    t.length = 0
    t.value = b''
    packet.tlvs.append(t)



def forge_discovery():
    p = forge_common_packet(0)
    end_tlv_list(p)

    return p.to_byte_array()



def forge_get_token(switchMAC):
    p = forge_common_packet(1, switchMAC)

    t = TLV()
    t.tag = 2305
    t.length = 0
    t.value = b''
    p.tlvs.append(t)

    end_tlv_list(p)

    return p.to_byte_array()



def forge_login(switchMAC, token, user, password):
    p = forge_common_packet(3, switchMAC, b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.tag = 512
    t.set_string_value(user)
    p.tlvs.append(t)

    t = TLV()
    t.tag = 514
    t.set_string_value(password)
    p.tlvs.append(t)

    end_tlv_list(p)

    return p.to_byte_array()


def forge_cable_test(switchMAC, token, portnum, user, password):
    p = forge_common_packet(3, switchMAC, b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.tag = 512
    t.set_string_value(user)
    p.tlvs.append(t)

    t = TLV()
    t.tag = 514
    t.set_string_value(password)
    p.tlvs.append(t)

    dataA = bytearray()
    dataA.append(portnum & 0xFF)
    dataA.append(0x01)
    dataA.append(0x00)
    dataA.append(0x00)
    dataA.append(0x00)
    dataA.append(0x00)
    t = TLV()
    t.tag = 16896
    t.value = bytes(dataA)
    t.length = 6
    p.tlvs.append(t)

    end_tlv_list(p)

    return p.to_byte_array()


def forge_get_port_stats(switchMAC, token):
    p = forge_common_packet(1, switchMAC, b'\x00\x00\x00\x00\x00\x00', token)

    t = TLV()
    t.tag = 16384
    t.length = 0
    t.value = b''
    p.tlvs.append(t)

    end_tlv_list(p)

    return p.to_byte_array()
