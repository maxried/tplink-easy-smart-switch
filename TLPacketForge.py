#!/usr/bin/env python3

"""Module to create common packets understood and used by TP-Link software and firmware"""

from random import randint
from struct import pack

from TLPacket import TLPacket
from TLTLVs import TLTLV, TLVTAGS


def forge_common_packet(opcode: int, switch_mac: bytes = b'\x00\x00\x00\x00\x00\x00',
                        computer_mac: bytes = b'\x00\x00\x00\x00\x00\x00', token: int = 0) -> TLPacket:
    """Creates package stub with commonly used parameters and a random sequence number."""

    packet = TLPacket()  # type: TLPacket
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


def end_tlv_list(packet: TLPacket) -> None:
    """Puts the end of transmission TLTLV to the end of the packet. Use before transmission."""

    tlv = TLTLV(TLVTAGS['EOT'])  # type: TLTLV
    packet.tlvs.append(tlv)


def forge_discovery() -> bytes:
    """Creates a discovery request."""

    packet = forge_common_packet(TLPacket.OPCODES['DISCOVER'])  # type: TLPacket
    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_get_token(switch_mac: bytes) -> bytes:
    """Create a token request."""

    packet = forge_common_packet(TLPacket.OPCODES['GET'], switch_mac)  # type: TLPacket

    tlv = TLTLV(TLVTAGS['SYS_GET_TOKEN'])  # type: TLTLV
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_authorized_packet(switch_mac: bytes, token: int, user: str, password: str) -> TLPacket:
    packet = forge_common_packet(TLPacket.OPCODES['SET'],
                                 switch_mac, b'\x00\x00\x00\x00\x00\x00', token)  # type: TLPacket

    tlv = TLTLV(TLVTAGS['SYSUSER_OLD_NAME'], user)  # type: TLTLV
    packet.tlvs.append(tlv)

    tlv = TLTLV(TLVTAGS['SYSUSER_OLD_PASSWORD'], password)  # type: TLTLV
    packet.tlvs.append(tlv)

    return packet


def forge_login(switch_mac: bytes, token: int, user: str, password: str) -> bytes:
    """Authorize with switch."""

    packet = forge_authorized_packet(switch_mac, token, user, password)  # type: TLPacket

    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_cable_test(switch_mac: bytes, token: int, portnum: int, user: str, password: str) -> bytes:
    """Issue a cable test quest."""

    packet = forge_authorized_packet(switch_mac, token, user, password)  # type: TLPacket

    # First byte is port number, second is 0x01, no clue why.
    payload = pack('>6B', portnum, 1, 0, 0, 0, 0)  # type: bytes
    tlv = TLTLV(TLVTAGS['MONITOR_CABLE_TEST'], payload)  # type: TLTLV
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_get_port_stats(switch_mac: bytes, token: int) -> bytes:
    """Gets PHY stats of all ports."""

    packet = forge_common_packet(TLPacket.OPCODES['GET'],
                                 switch_mac, b'\x00\x00\x00\x00\x00\x00', token)  # type: TLPacket

    tlv = TLTLV(TLVTAGS['MONITOR_PORT_STATISTICS'])  # type: TLTLV
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_get_qos(switch_mac: bytes, token: int) -> bytes:
    """Gets QoS stats of all ports."""

    packet = forge_common_packet(TLPacket.OPCODES['GET'],
                                 switch_mac, b'\x00\x00\x00\x00\x00\x00', token)  # type: TLPacket

    tlv = TLTLV(TLVTAGS['QOS_BASIC_PRIORITY'])  # type: TLTLV
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return bytes(packet.to_byte_array())


def forge_question(switch_mac: bytes, token: int, tag: int) -> TLPacket:
    """Gets PHY stats of all ports."""

    packet = forge_common_packet(TLPacket.OPCODES['GET'],
                                 switch_mac, b'\x00\x00\x00\x00\x00\x00', token)  # type: TLPacket

    tlv = TLTLV(tag)  # type: TLTLV
    packet.tlvs.append(tlv)

    end_tlv_list(packet)

    return packet.to_byte_array()
