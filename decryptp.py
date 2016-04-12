#!/usr/bin/env python3

import getopt
from sys import argv
from getpass import getpass

from TLPresentation import present_discovery
from TLPacket import TLPacket
from TLCrypt import *
from TLPacketForge import *
from TLActions import *

def choose_switch(switch_ip_arg):
    if switch_ip_arg != None:
        print('Only trying ' + switch_ip_arg)
        print()
        tl_discover(switch_ip_arg)
    else:
        tl_discover()

    if len(DISCOVERED_SWITCHES) > 1:
        print(' {0:2s}{1:31s} {2:15s} {3:31s} {4:10s}'
              .format('#', 'Name', 'IP', 'Model', 'Firmware'))
        for i, switch in enumerate(DISCOVERED_SWITCHES):
            print('{0:2d} '.format(i), end='')
            present_discovery(switch.source_packet)

        while selection is None:
            selection_raw = input('Select switch: ')
            if (selection_raw.isnumeric() and
                    int(selection_raw) in range(0, len(DISCOVERED_SWITCHES))):
                selection = int(selection_raw)

        selected_switch = DISCOVERED_SWITCHES[selection]
    elif len(DISCOVERED_SWITCHES) == 1:
        print('{0:31s} {1:15s} {2:31s} {3:10s}'
              .format('Name', 'IP', 'Model', 'Firmware'))
        present_discovery(DISCOVERED_SWITCHES[0].source_packet)
        selected_switch = DISCOVERED_SWITCHES[0]
        print()
    else:
        print('No switches discovered.')
        selected_switch = None

    return selected_switch


def main():
    try:
        opts, _ = getopt.getopt(argv[1:], 'di:')
    except getopt.GetoptError:
        opts = []
    except:
        raise


    only_decrypt = False
    switch_ip_arg = None
    selected_switch = None

    for opt, arg in opts:
        if opt == '-i':
            switch_ip_arg = arg
        elif opt == '-d':
            only_decrypt = True


    if only_decrypt:
        with open('test.raw', 'rb') as encrypted_file:
            data = encrypted_file.read()

        out = tl_rc4_crypt(data)

        with open('test.dec', 'wb') as outfile:
            outfile.write(out)


        packet = TLPacket(out)
        with open('test2.dec', 'wb') as outfile:
            outfile.write(packet.to_byte_array())

        packet.print_summary()
    else:
        selected_switch = choose_switch(switch_ip_arg)

        if selected_switch != None:
            token = tl_get_token(selected_switch.mac, selected_switch.ip4)

            logged_in = False
            if token != None:
                while not logged_in:
                    username = input('User: ')
                    password = getpass('Password: ')

                    if tl_login(selected_switch.mac, selected_switch.ip4,
                                token, username, password) != 0:
                        print('Wrong credentials')
                    else:
                        logged_in = True

                # stats = TLGetPortStatistics(selectedSwitch.MAC, selectedSwitch.IP, token)
                # presentPortStatistics(stats)
                for i in range(1, 9):
                    cable_test_results = tl_test_cable(selected_switch.mac, selected_switch.ip4,
                                                       token, i, username, password)
                    present_cable_test(cable_test_results)


if __name__ == '__main__':
    main()
