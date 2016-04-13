#!/usr/bin/env python3

"""Module to create common packets understood and used by TP-Link software and firmware"""

from random import randint

from TLPacket import TLPacket
from TLTLVs import TLV, TLVTAGS


def forge_common_packet(opcode, switch_mac=b'\x00\x00\x00\x00\x00\x00',
                        computer_mac=b'\x00\x00\x00\x00\x00\x00', token=0):
    """Creates package stub with commonly used parameters and a random sequence number."""

    packet = TLPacket()
    packet.version = 1
    packet.opcode = opcode
    packet.mac_switch = switch_mac
    packet.mac_computer = computer_mac
    packet.sequence_number = randint(0, 1000)
    packet.error_code = 0
    packet.length = 0
    packet.fragment = 0
    packet.flags = 0
    packet.token = token
    packet.checksum = 0
    return packet



def end_tlv_list(packet):
    """Puts the end of transmission TLV to the end of the packet. Use before transmission."""

    tlv = TLV(TLVTAGS['EOT'])
    packet.tlvs.append(tlv)



def forge_discovery():
    """Creates a discovery request."""

    packet = forge_common_packet(0)
    end_tlv_list(packet)

    return packet.to_byte_array()



def forge_get_token(switch_mac):
    """Create a token request."""

    packet = forge_common_packet(1, switch_mac)

    tlv = TLV(TLVTAGS['SYS_GET_TOKEN'])
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return packet.to_byte_array()



def forge_login(switch_mac, token, user, password):
    """Authorize with switch."""

    packet = forge_common_packet(3, switch_mac, b'\x00\x00\x00\x00\x00\x00', token)

    tlv = TLV(TLVTAGS['SYSUSER_OLD_NAME'], user)
    packet.tlvs.append(tlv)

    tlv = TLV(TLVTAGS['SYSUSER_OLD_PASSWORD'], password)
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return packet.to_byte_array()


def forge_cable_test(switch_mac, token, portnum, user, password):
    """Issue a cable test quest."""

    packet = forge_common_packet(3, switch_mac, b'\x00\x00\x00\x00\x00\x00', token)


    # Cable Diagnostics needs another authentication
    tlv = TLV(TLVTAGS['SYSUSER_OLD_NAME'], user)
    packet.tlvs.append(tlv)

    tlv = TLV(TLVTAGS['SYSUSER_OLD_PASSWORD'], password)
    packet.tlvs.append(tlv)

    # First byte is port number, second is 0x01, no clue why.
    payload = bytearray()
    payload.append(portnum & 0xFF)
    payload.append(0x01)
    payload.append(0x00)
    payload.append(0x00)
    payload.append(0x00)
    payload.append(0x00)
    tlv = TLV(TLVTAGS['MONITOR_CABLE_TEST'], bytes(payload))
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return packet.to_byte_array()


def forge_get_port_stats(switch_mac, token):
    """Gets PHY stats of all ports."""

    packet = forge_common_packet(1, switch_mac, b'\x00\x00\x00\x00\x00\x00', token)

    tlv = TLV(TLVTAGS['MONITOR_PORT_STATISTICS'])
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return packet.to_byte_array()
