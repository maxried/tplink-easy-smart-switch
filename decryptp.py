#!/usr/bin/env python3

"""Main module for cross platform TP-Link Easy Smart Switch Configuration tool"""


import getopt
from sys import argv
from getpass import getpass
import socket

from TLPresentation import present_discovery, present_cable_test, present_port_statistics, present_qos
from TLPacket import TLPacket
from TLCrypt import tl_rc4_crypt
from TLPacketForge import forge_question
from TLActions import tl_test_cable, tl_discover, TLSwitch, tl_get_token,\
    tl_login, tl_get_port_statistics, PORTSC, PORTCS, tl_init_sockets, tl_get_qos, tl_send_and_wait_for_response

def choose_switch(switch_ip_arg):
    """Discover switches, list details and display selection prompt."""
    if switch_ip_arg != None:
        print('Only trying ' + switch_ip_arg)
        print()
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

    packet.print_summary()



def main():
    """The main method."""    
    try:
        opts, _ = getopt.getopt(argv[1:], 'ldi:')
    except getopt.GetoptError:
        opts = []
    except:
        raise


    only_decrypt = False
    only_listen_and_decrypt = False
    switch_ip_arg = None
    selected_switch = None

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
                data, _ = receive1.recvfrom(1500)
                packet = TLPacket(tl_rc4_crypt(data))

                print('\033[94m' + "-----> Switch to computer")
                packet.print_summary()
                print("<----- Switch to computer\n" + '\033[0m')
            except IOError:
                pass

            try:
                data, _ = receive2.recvfrom(1500)
                packet = TLPacket(tl_rc4_crypt(data))

                print('\033[91m' + "-----> Computer to switch")
                packet.print_summary()
                print("<----- Computer to switch\n" + '\033[0m')
            except IOError:
                pass


    elif only_decrypt:
        decrypt_test_dot_raw()
    else:
        tl_init_sockets()
        selected_switch = choose_switch(switch_ip_arg)

        # stats = tl_get_port_statistics(selected_switch.mac, selected_switch.ip4, 1000)
        # present_port_statistics(stats)

        if selected_switch != None:
            token = tl_get_token(selected_switch.mac, selected_switch.ip4)

            logged_in = False
            if token != None:
                while not logged_in:
                    username = input('User: ')
                    password = getpass('Password: ')

                    login_status = tl_login(selected_switch.mac, selected_switch.ip4,
                                            token, username, password) == 7
                    if login_status == 1:
                        print('Wrong credentials\n')
                    elif login_status != 0:
                        print('Login failed ({0:d})\n'.format(login_status))
                    else:
                        print('Login successful\n')
                        logged_in = True


                
                for i in range(0, 256):
                    quest = TLPacket(forge_question(selected_switch.mac, token, i))
                    quest.opcode = 0
                    answer = tl_send_and_wait_for_response(quest, selected_switch.ip4, .3)
                    if answer is not None and answer.error_code != 0:
                        print('\033[91m' + "-----> Computer to switch")
                        quest.print_summary()
                        print("<----- Computer to switch\n" + '\033[0m')
                        print('\033[94m' + "-----> Switch to computer")
                        print(answer.print_summary() if answer != None else "No answer received.")
                        print("<----- Switch to computer\n" + '\033[0m')

                # for i in range(1, 9):
                #     cable_test_results = tl_test_cable(selected_switch.mac, selected_switch.ip4,
                #                                        token, i, username, password)
                #     present_cable_test(cable_test_results)


if __name__ == '__main__':
    main()
