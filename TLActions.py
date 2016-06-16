#!/usr/bin/env python3

"""This module implements common things to do with your switch"""

import time
import socket

from TLCrypt import tl_rc4_crypt
from TLPacketForge import forge_cable_test, forge_discovery,\
                          forge_get_token, forge_login, forge_get_port_stats, forge_get_qos
from TLPacket import TLPacket
from TLPresentation import is_discovery

class TLSwitch:
    """This is a switch"""

    discovered_switches = []

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


PORTCS = int.from_bytes(b'tp', 'big') # 29808
PORTSC = PORTCS + 1 # 29809
BROADCAST_IP = '255.255.255.255'
SENDER = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
RECEIVER = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def tl_init_sockets():
    """Initialize sockets and bind to port."""
    SENDER.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    RECEIVER.bind(('0.0.0.0', PORTSC))
    RECEIVER.setblocking(False)

def tl_send_and_wait_for_response(outgoing_packet, target=BROADCAST_IP, timeout=1):
    """Sends packet and returns the answer, if any."""
    SENDER.sendto(tl_rc4_crypt(outgoing_packet.to_byte_array()), (target, PORTCS))

    start = time.time()

    while time.time() - start <= timeout:
        try:
            data, _ = RECEIVER.recvfrom(1500)
            incoming_packet = TLPacket(tl_rc4_crypt(data))

            if incoming_packet.sequence_number == outgoing_packet.sequence_number:
                return incoming_packet

        except IOError:
            pass

    return None


def tl_discover(target=BROADCAST_IP, duration=1):
    """Do a survey or ask a specified switch for its identity"""
    discovery_request = TLPacket(forge_discovery())
    SENDER.sendto(tl_rc4_crypt(discovery_request.to_byte_array()), (target, PORTCS))

    start = time.time()

    while time.time() - start <= duration:
        try:
            data, _ = RECEIVER.recvfrom(1500)
            packet = TLPacket(tl_rc4_crypt(data))

            if is_discovery(discovery_request, packet):
                found = False
                this_one = TLSwitch(packet)

                for i in TLSwitch.discovered_switches:
                    if i.ip4 == this_one.ip4:
                        found = True

                if not found:
                    TLSwitch.discovered_switches.append(this_one)
                    if target != BROADCAST_IP:
                        return
        except IOError:
            pass




def tl_get_token(switchmac, switchip, timeout=1):
    """Retrieves a token used as a reference for a session. AKA session id."""
    forged = TLPacket(forge_get_token(switchmac))
    result = tl_send_and_wait_for_response(forged, switchip, timeout)
    return None if result is None else result.token


def tl_login(switchmac, switchip, token, user, password, timeout=1):
    """Performs a login: Necessary for nearly every further action"""
    forged = TLPacket(forge_login(switchmac, token, user, password))
    result = tl_send_and_wait_for_response(forged, switchip, timeout)

    return None if result is None else result.error_code


def tl_get_port_statistics(switchmac, switchip, token, timeout=1):
    """Get the statistics for all PHYs"""
    forged = TLPacket(forge_get_port_stats(switchmac, token))
    return tl_send_and_wait_for_response(forged, switchip, timeout)


def tl_test_cable(switchmac, switchip, token, portnum, user, password, timeout=10):
    """Tests the cable attached to the switch"""
    forged = TLPacket(forge_cable_test(switchmac, token, portnum, user, password))
    return tl_send_and_wait_for_response(forged, switchip, timeout)

def tl_get_qos(switchmac, switchip, token, timeout=1):
    forged = TLPacket(forge_get_qos(switchmac, token))
    result = tl_send_and_wait_for_response(forged, switchip, timeout)
    return result
