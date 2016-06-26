#!/usr/bin/env python3

import argparse
import ipaddress
import subcommandPortStatistics
import subcommandDiscover
import TLActions


PARSER = argparse.ArgumentParser()
ALL_COMMANDS = []


def setup_argparser():
    PARSER.add_argument('-i', '--ip', required=False,
                        default=ipaddress.IPv4Address(TLActions.BROADCAST_IP), type=ipaddress.IPv4Address,
                        help='The IP address of the target device. Defaults to broadcast for discovery.')
    PARSER.add_argument('-t', '--timeout', type=float,
                        help='Timeout for switches to answer requests in seconds. Defaults to 1.',
                        required=False, default=1)
    PARSER.add_argument('-d', '--debug', required=False, action="store_true", help='Show debugging information.')

    sub = PARSER.add_subparsers(dest='command')

    for command in ALL_COMMANDS:
        command.setup_parser(sub.add_parser(command.name()))


def main():
    ALL_COMMANDS.append(subcommandDiscover)
    ALL_COMMANDS.append(subcommandPortStatistics)

    setup_argparser()

    result = PARSER.parse_args()
    if result is None:
        print('Error parsing arguments.')
        exit()

    if result is not None and result.command is None:
        result.command = "discover"

    TLActions.DEBUG = result.debug
    TLActions.tl_init_sockets()

    for command in ALL_COMMANDS:
        if command.name() == result.command:
            command.execute(result)
            break

    print('End.')


if __name__ == '__main__':
    main()