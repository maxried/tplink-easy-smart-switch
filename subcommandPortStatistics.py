#!/usr/bin/env python3

import TLActions
import TLPresentation

SWITCH = ...  # type: TLSwitch
TOKEN = ...  # type: int


def discover_and_token(args):
    global SWITCH, TOKEN
    SWITCH = TLActions.tl_discover(str(args.ip), args.timeout)
    if SWITCH is None:
        print('Found more than one unit.')
        return False
    else:
        TOKEN = TLActions.tl_get_token(SWITCH.mac, SWITCH.ip4, args.timeout)
        return True


def name():
    return 'showStats'


def setup_parser(parser):
    pass


def execute(args):
    global SWITCH, TOKEN

    if not discover_and_token(args):
        return

    stats = TLActions.tl_get_port_statistics(SWITCH.mac, SWITCH.ip4, TOKEN, args.timeout)
    print('Port Statistics of ' + SWITCH.ip4)
    TLPresentation.present_port_statistics(stats)

