#!/usr/bin/env python3

import ipaddress
import TLActions
import TLPresentation


def name():
    return 'discover'


def setup_parser(parser):
    pass


def execute(args):
    TLActions.tl_discover(str(args.ip), args.timeout)

    for i in TLActions.TLSwitch.discovered_switches:
        TLPresentation.present_discovery(i.source_packet)

    print('Discovered ' + str(len(TLActions.TLSwitch.discovered_switches)) + ' unit(s).')