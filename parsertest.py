#!/usr/bin/env python3

import argparse
import ipaddress


def ip(value):
    return ipaddress.IPv4Address(value)

parser = argparse.ArgumentParser()

parser.add_argument('test', type=ip)

parser.parse_args()
