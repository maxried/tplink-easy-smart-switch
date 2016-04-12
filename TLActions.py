#!/usr/bin/env python3

"""This module implements common things to do with your switch"""

import time
import socket

from TLCrypt import tl_rc4_crypt
from TLPacketForge import forge_cable_test, forge_discovery,\
                          forge_get_token, forge_login, forge_get_port_stats
from TLPacket import TLPacket
from TLPresentation import extract_token_from_header, is_discovery

class TLSwitch:
    """This is a switch"""
    def __init__(self, packet):
        self.name = ''
        self.ip4 = ''
        self.mac = b'\x00\x00\x00\x00\x00\x00'

        self.source_packet = packet

        for i in packet.tlvs:
            if i.tag == 2:
                self.name = i.get_human_readable_value()
            elif i.tag == 4:
                self.ip4 = i.get_human_readable_value()
            elif i.tag == 3:
                self.mac = i.value


PORTCS = int.from_bytes(b'tp', 'big')
PORTSC = PORTCS + 1
BROADCAST_IP = '255.255.255.255'

DISCOVERED_SWITCHES = []


def tl_discover(target=BROADCAST_IP, duration=1):
    """Do a survey or ask a specified switch for its identity"""
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive.bind(('0.0.0.0', PORTSC))
    receive.setblocking(False)

    discovery_request = TLPacket(forge_discovery())
    send.sendto(tl_rc4_crypt(discovery_request.to_byte_array()), (target, PORTCS))

    start = time.time()

    while time.time() - start <= duration:
        try:
            data, _ = receive.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if is_discovery(discovery_request, packet):
                found = False
                this_one = TLSwitch(packet)

                for i in DISCOVERED_SWITCHES:
                    if i.ip4 == this_one.ip4:
                        found = True

                if not found:
                    #packet.printSummary()
                    #presentDiscovery(packet)
                    DISCOVERED_SWITCHES.append(this_one)
                    if target != BROADCAST_IP:
                        return
        except IOError:
            pass




def tl_get_token(switchmac, switchip, timeout=1):
    """Retrieves a token used as a reference for a session. AKA session id."""
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive.bind(('0.0.0.0', PORTSC))
    receive.setblocking(False)

    forged = TLPacket(forge_get_token(switchmac))
    send.sendto(tl_rc4_crypt(forged.to_byte_array()), (switchip, PORTCS))

    start = time.time()

    while time.time() - start <= timeout:
        try:
            data, _ = receive.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if packet.sequence_number == forged.sequence_number:
                return extract_token_from_header(packet)

        except IOError:
            pass

    return None


def tl_login(switchmac, switchip, token, user, password, timeout=1):
    """Performs a login: Necessary for nearly every further action"""
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive.bind(('0.0.0.0', PORTSC))
    receive.setblocking(False)

    forged = TLPacket(forge_login(switchmac, token, user, password))
    send.sendto(tl_rc4_crypt(forged.to_byte_array()), (switchip, PORTCS))

    start = time.time()

    while time.time() - start <= timeout:
        try:
            data, _ = receive.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if packet.sequence_number == forged.sequence_number:
                return packet.error_code

        except IOError:
            pass

    return None


def tl_get_port_statistics(switchmac, switchip, token, timeout=1):
    """Get the statistics for all PHYs"""
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive.bind(('0.0.0.0', PORTSC))
    receive.setblocking(False)

    forged = TLPacket(forge_get_port_stats(switchmac, token))
    send.sendto(tl_rc4_crypt(forged.to_byte_array()), (switchip, PORTCS))

    start = time.time()

    while time.time() - start <= timeout:
        try:
            data, _ = receive.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if packet.sequence_number == forged.sequence_number:
                return packet

        except IOError:
            pass

    return None



def tl_test_cable(switchmac, switchip, token, portnum, user, password, timeout=10):
    """Tests the cable attached to the switch"""
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive.bind(('0.0.0.0', PORTSC))
    receive.setblocking(False)

    forged = TLPacket(forge_cable_test(switchmac, token, portnum, user, password))
    send.sendto(tl_rc4_crypt(forged.to_byte_array()), (switchip, PORTCS))

    start = time.time()

    while time.time() - start <= timeout:
        try:
            data, _ = receive.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if packet.sequence_number == forged.sequence_number:
                return packet

        except IOError:
            pass

    return None
