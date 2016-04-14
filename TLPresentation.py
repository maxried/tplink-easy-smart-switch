#!/usr/bin/env python3

from TLInfos import *

def extract_token_from_header(packet):
    return packet.token

def is_discovery(request, packet):
    return (len(packet.tlvs) == 10 and packet.version == 1 and
            packet.opcode == 2 and packet.sequence_number == request.sequence_number)

def present_discovery(packet):
    model = ''
    name = ''
    fwversion = ''
    ip4 = ''

    for tlv in packet.tlvs:
        if tlv.tag == TLVTAGS['SYSINFO_HARD_VERSION']:
            model = tlv.get_human_readable_value()
        elif tlv.tag == TLVTAGS['SYSINFO_DESCRIPTION']:
            name = tlv.get_human_readable_value()
        elif tlv.tag == TLVTAGS['SYSINFO_FIRM_VERSION']:
            fwversion = tlv.get_human_readable_value()
        elif tlv.tag == TLVTAGS['SYSINFO_IP']:
            ip4 = tlv.get_human_readable_value()

    print('{0:31s} {1:15s} {2:31s} {3:10s}'.format(name, ip4, model, fwversion))



def present_port_statistics(packet):
    print('{0:>2s} {1:<8s} {2:<16s} {3:>10s} {4:>10s} {5:>10s} {6:>10s}'
          .format('#', 'State', 'Mode', 'Tx Good', 'Tx Bad', 'Rx Good', 'Rx Bad'))
    stats = PortStatistics(packet)
    stats.print_ports()


def present_cable_test(packet):
    possible_test_results = {0: 'no cable', 1: 'normal',
                             2: 'open', 3: 'short',
                             4: 'open and short', 5: 'cross-over'}

    for i in packet.tlvs:
        if i.tag == TLVTAGS['MONITOR_CABLE_TEST'] and len(i.value) == 6:
            print('Port {0:2d}: Length {1:3d}m, Diagnosis: {2:14s}'
                  .format(i.value[0], i.value[5],
                          possible_test_results.get(i.value[1], 'unknown')))

def present_qos(packet):
    possible_qos_modes = {0: 'lowest', 1: 'normal', 2: 'medium', 3: 'highest'}

    print('{0:2s} {1:8s}'.format('#', 'Priority'))

    for tlv in packet.tlvs:
        if tlv.tag == TLVTAGS['QOS_BASIC_PRIORITY'] and len(tlv.value) == 2:
            print('{0:2d} {1:8s}'
                  .format(tlv.value[0], possible_qos_modes.get(tlv.value[1], 'unknown')))
