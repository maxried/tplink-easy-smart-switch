#!/usr/bin/env python3

"""Main module for cross platform TP-Link Easy Smart Switch Configuration tool"""


import getopt
from sys import argv
import socket

from TLPresentation import present_discovery
from TLPacket import TLPacket
from TLCrypt import tl_rc4_crypt
from TLActions import tl_discover, TLSwitch, tl_get_token,\
    PORTSC, PORTCS, tl_init_sockets, tl_test


def choose_switch(switch_ip_arg: str=None):
    """Discover switches, list details and display selection prompt."""
    if switch_ip_arg is not None:
        print('Only trying {0}\n'.format(switch_ip_arg))
        tl_discover(switch_ip_arg)
    else:
        tl_discover()

    if len(TLSwitch.discovered_switches) > 1:
        print(' {0:2s}{1:31s} {2:15s} {3:31s} {4:10s}'
              .format('#', 'Name', 'IP', 'Model', 'Firmware'))
        for i, switch in enumerate(TLSwitch.discovered_switches):
            print('{0:2d} '.format(i), end='')
            present_discovery(switch.source_packet)

        selection = None
        while selection is None:
            selection_raw = input('Select switch: ')
            if (selection_raw.isnumeric() and
                    int(selection_raw) in range(0, len(TLSwitch.discovered_switches))):
                selection = int(selection_raw)

        selected_switch = TLSwitch.discovered_switches[selection]
    elif len(TLSwitch.discovered_switches) == 1:
        print('{0:31s} {1:15s} {2:31s} {3:10s}'
              .format('Name', 'IP', 'Model', 'Firmware'))
        present_discovery(TLSwitch.discovered_switches[0].source_packet)
        selected_switch = TLSwitch.discovered_switches[0]
        print()
    else:
        print('No switches discovered.')
        selected_switch = None

    return selected_switch


def decrypt_test_dot_raw():
    """Decrypt the packet stored in test.raw, save it to test.dec and display summary"""
    with open('test.raw', 'rb') as encrypted_file:
        data = encrypted_file.read()

    out = tl_rc4_crypt(data)

    with open('test.dec', 'wb') as outfile:
        outfile.write(out)

    packet = TLPacket(out)
    with open('test2.dec', 'wb') as outfile:
        outfile.write(packet.to_byte_array())

    print(packet)


def main():
    """The main method."""
    try:
        opts = getopt.getopt(argv[1:], 'ldi:')[0]
    except getopt.GetoptError:
        opts = []
    except:
        raise

    only_decrypt = False
    only_listen_and_decrypt = False
    switch_ip_arg = None

    for opt, arg in opts:
        if opt == '-i':
            switch_ip_arg = arg
        elif opt == '-d':
            only_decrypt = True
        elif opt == '-l':
            only_listen_and_decrypt = True

    if only_listen_and_decrypt:
        receive1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receive1.bind(('0.0.0.0', PORTSC))
        receive1.setblocking(False)

        receive2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receive2.bind(('0.0.0.0', PORTCS))
        receive2.setblocking(False)

        while True:
            try:
                data = receive1.recvfrom(1500)[0]
                packet = TLPacket(tl_rc4_crypt(data))

                print('\u001B[94m-----> Switch to computer\n{0}'
                      '\n<----- Switch to computer\n\u001B[0m'.format(str(packet)))
            except IOError:
                pass

            try:
                data = receive2.recvfrom(1500)[0]
                packet = TLPacket(tl_rc4_crypt(data))

                print('\u001B[91m-----> Computer to switch\n{0}'
                      '\n<----- Computer to switch\n\u001B[0m'.format(str(packet)))
            except IOError:
                pass
    elif only_decrypt:
        decrypt_test_dot_raw()
    else:
        tl_init_sockets()
        selected_switch = choose_switch(switch_ip_arg)

        for i in range(25700, 65536):
            if i % 100 == 0:
                print(i)
            token = tl_get_token(selected_switch.mac, selected_switch.ip4)

            sent, rec = tl_test(i, selected_switch.mac, selected_switch.ip4, token, .3)
            if rec is not None:
                print('\u001B[91m-----> Computer to switch\n{0}'
                      '\n<----- Computer to switch\n\u001B[0m'.format(str(sent)))
                print('\u001B[94m-----> Switch to computer\n{0}'
                      '\n<----- Switch to computer\n\u001B[0m'.format(str(rec)))

        # stats = tl_get_port_statistics(selected_switch.mac, selected_switch.ip4, 1000)
        # present_port_statistics(stats)

        # if selected_switch is not None:
        #     token = tl_get_token(selected_switch.mac, selected_switch.ip4)
        #
        #     logged_in = False
        #     if token is not None:
        #         username = ''  # type: str
        #         password = ''  # type: str
        #
        #         while not logged_in:
        #             username = input('User: ')
        #             password = getpass('Password: ')
        #
        #             login_status = tl_login(selected_switch.mac, selected_switch.ip4,
        #                                     token, username, password)   # type: int
        #             if login_status == 1:
        #                 print('Wrong credentials\n')
        #             elif login_status != 0:
        #                 print('Login failed ({0:d})\n'.format(login_status))
        #             else:
        #                 print('Login successful\n')
        #                 logged_in = True


if __name__ == '__main__':
    main()
