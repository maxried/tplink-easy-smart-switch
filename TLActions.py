#!/usr/bin/env python3

"""This module implements common things to do with your switch"""

from typing import List
import time
import socket

from TLCrypt import tl_rc4_crypt
from TLPacketForge import forge_cable_test, forge_discovery, \
    forge_get_token, forge_login, forge_get_port_stats, forge_get_qos
from TLPacket import TLPacket
from TLPresentation import is_discovery
from TLTLVs import TLTLV, TLVTAGS


class TLSwitch:
    """This is a switch"""
    discovered_switches = []  # type: List[TLSwitch]

    def __init__(self, packet: TLPacket):
        self.name = ...  # type: str
        self.ip4 = ...  # type: str
        self.mac = b'\x00\x00\x00\x00\x00\x00'  # type: bytes

        self.source_packet = packet  # type: TLPacket

        for i in packet.tlvs:
            if i.tag == 2:
                self.name = i.get_human_readable_value()
            elif i.tag == 4:
                self.ip4 = i.get_human_readable_value()
            elif i.tag == 3:
                self.mac = i.value


PORTCS = int.from_bytes(b'tp', 'big')  # type: int
PORTSC = PORTCS + 1  # type: int
# Ports: Computer to switch: 29808, switch to computer: 29809

BROADCAST_IP = '255.255.255.255'  # type: str
SENDER = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # type: socket
RECEIVER = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # type: socket

DEBUG = False


def tl_init_sockets() -> None:
    """Initialize sockets and bind to port."""
    SENDER.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    RECEIVER.bind(('0.0.0.0', PORTSC))
    RECEIVER.setblocking(False)


def tl_send_and_wait_for_response(
        outgoing_packet: TLPacket, target: str=BROADCAST_IP, timeout: float=1) -> TLPacket:
    """Sends packet and returns the answer, if any."""
    SENDER.sendto(tl_rc4_crypt(bytes(outgoing_packet.to_byte_array())), (target, PORTCS))
    if DEBUG:
        print(outgoing_packet)

    start = time.time()  # type: float

    while time.time() - start <= timeout:
        try:
            data = RECEIVER.recvfrom(1500)[0]  # type: bytes
            incoming_packet = TLPacket(tl_rc4_crypt(data))  # type: TLPacket

            if incoming_packet.sequence_number == outgoing_packet.sequence_number:
                if DEBUG:
                    print(incoming_packet)
                return incoming_packet

        except IOError:
            pass

    return None


def tl_discover(target: str=BROADCAST_IP, duration: float=1) -> TLSwitch:
    """Do a survey or ask a specified switch for its identity"""
    discovery_request = TLPacket(forge_discovery())  # type: TLPacket
    SENDER.sendto(tl_rc4_crypt(bytes(discovery_request.to_byte_array())), (target, PORTCS))

    if DEBUG:
        print(discovery_request)

    start = time.time()  # type: float

    while time.time() - start <= duration:
        try:
            data = RECEIVER.recvfrom(1500)[0]  # type: bytes
            packet = TLPacket(tl_rc4_crypt(data))  # type: TLPacket

            if is_discovery(discovery_request, packet):
                found = False  # type: bool
                this_one = TLSwitch(packet)  # type: TLSwitch

                if DEBUG:
                    print(packet)

                for i in TLSwitch.discovered_switches:
                    if i.ip4 == this_one.ip4:
                        found = True

                if not found:
                    TLSwitch.discovered_switches.append(this_one)
                    if target != BROADCAST_IP:
                        return this_one
        except IOError:
            pass

    if len(TLSwitch.discovered_switches) == 1:
        return TLSwitch.discovered_switches[0]
    else:
        return None


def tl_get_token(switchmac: bytes, switchip: str, timeout: float=1) -> int:
    """Retrieves a token used as a reference for a session. AKA session id."""
    forged = TLPacket(forge_get_token(switchmac))  # type: TLPacket
    result = tl_send_and_wait_for_response(forged, switchip, timeout)  # type: TLPacket
    return None if result is None else result.token


def tl_login(switchmac: bytes, switchip: str, token: int,
             user: str, password: str, timeout: float=1) -> int:
    """Performs a login: Necessary for nearly every further action"""
    forged = TLPacket(forge_login(switchmac, token, user, password))  # type: TLPacket
    result = tl_send_and_wait_for_response(forged, switchip, timeout)  # type: TLPacket

    return None if result is None else result.error_code


def tl_get_port_statistics(switchmac: bytes, switchip: str, token: int, timeout: float=1) -> TLPacket:
    """Get the statistics for all PHYs"""
    forged = TLPacket(forge_get_port_stats(switchmac, token))  # type: TLPacket
    return tl_send_and_wait_for_response(forged, switchip, timeout)


def tl_test_cable(switchmac: bytes, switchip: str, token: int, portnum: int,
                  user: str, password: str, timeout: float=10) -> TLPacket:
    """Tests the cable attached to the switch"""
    forged = TLPacket(forge_cable_test(switchmac, token, portnum, user, password))  # type: TLPacket
    return tl_send_and_wait_for_response(forged, switchip, timeout)


def tl_get_qos(switchmac: bytes, switchip: str, token: int, timeout: float=1) -> TLPacket:
    """Retrieves the QoS settings."""
    forged = TLPacket(forge_get_qos(switchmac, token))
    return tl_send_and_wait_for_response(forged, switchip, timeout)


def tl_test(test: int, switchmac: bytes, switchip: str, token: int, timeout: float=1) -> TLPacket:
    forged = TLPacket()

    forged.opcode = 1
    forged.token = token
    forged.mac_switch = switchmac
    forged.sequence_number = 2342

    nt = TLTLV(test, None)
    forged.tlvs.append(nt)

    nt = TLTLV(TLVTAGS.get('EOT', 0), None)
    forged.tlvs.append(nt)

    return forged, tl_send_and_wait_for_response(forged, switchip, timeout)