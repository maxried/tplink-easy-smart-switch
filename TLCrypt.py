#!/usr/bin/env python3

"""Module to encapsulate TP-Link packet encryption functions."""

from typing import List


def tl_rc4_crypt(packet: bytes) -> bytes:
    """Encrypt AND decrypt the packet using TP-Links default encryption."""

    # The secret crypto key
    key = ("Ei2HNryt8ysSdRRI54XNQHBEbOIRqNjQgYxsTmuW3srSVRVFyLh8mwvhBLPFQph3" +
           "ecDMLnDtjDUdrUwt7oTsJuYl72hXESNiD6jFIQCtQN1unsmn3JXjeYwGJ55pqTkV" +
           "yN2OOm3vekF6G1LM4t3kiiG4lGwbxG4CG1s5Sli7gcINFBOLXQnPpsQNWDmPbOm7" +
           "4mE7eyR3L7tk8tUhI17FLKm11hrrd1ck74bMw3VYSK3X5RrDgXelewMU6o1tJ3iX")

    sbox = list(range(256))  # type: List[int]
    j = 0  # type: int
    out = bytearray()  # type: bytearray

    # KSA Phase
    for i in range(256):  # type: int
        j = (j + sbox[i] + ord(key[i])) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]

    # PRGA Phase
    i = j = 0  # type: int
    for char in packet:  # type: int
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out.append((char ^ sbox[(sbox[i] + sbox[j]) % 256]))

    return out
