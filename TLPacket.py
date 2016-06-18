#!/usr/bin/env python3

"""TP-Link packet parser"""

from typing import List, Dict
from struct import unpack
from TLTLVs import TLV


class TLPacket:
    """Class for TP-Link packet representation"""

    OPCODES = {'DISCOVER': 0, 'GET': 1, 'SET': 3}  # type: Dict[str, int]

    def __init__(self, decrypted: bytes = None):
        if decrypted is None:
            self.version = 1  # type: int
            self.opcode = self.OPCODES['DISCOVER']  # type: int
            self.mac_switch = b'\x00\x00\x00\x00\x00\x00'  # type: bytes
            self.mac_computer = b'\x00\x00\x00\x00\x00\x00'  # type: bytes
            self.sequence_number = 0  # type: int
            self.error_code = 0  # type: int
            self.length = 0  # type: int
            self.fragment = 0  # type: int
            self.flags = 0  # type: int
            self.token = 0  # type: int
            self.checksum = 0  # type: int

            self.tlvs = []  # type: List[TLV]
        elif len(decrypted) >= 32:
            [self.version, self.opcode, self.mac_switch,
             self.mac_computer, self.sequence_number,
             self.error_code, self.length, self.fragment,
             self.flags, self.token, self.checksum] = unpack('>BB6s6sHIHHHHI', decrypted[:32])

            body = decrypted[32:]  # type: bytes

            self.tlvs = []  # type: List[TLV]
            while len(body) > 3:
                ntlv = TLV()  # type: TLV
                ntlv.tag, ntlv.length = unpack('>HH', body[:4])
                if len(body) >= ntlv.length + 4:
                    ntlv.value = bytes(body[4:ntlv.length + 4])
                    body = body[ntlv.length + 4:]

                self.tlvs.append(ntlv)

    def __str__(self) -> str:
        """Converts TLPacket to human readable summary."""
        result = ('Version:         {0}\n'
                  'Opcode:          {1}\n'
                  'MAC Switch:      {2}\n'
                  'MAC Computer:    {3}\n'
                  'Sequence Number: {4}\n'
                  'Error:           {5}\n'
                  'Length:          {6}\n'
                  'Fragment:        {7}\n'
                  'Flags:           {8}\n'
                  'Token:           {9}\n'
                  'Checksum:        {10}\n'.format(
                      str(self.version),
                      str(self.opcode),
                      ''.join([format(b, '02X') for b in self.mac_switch]),
                      ''.join([format(b, '02X') for b in self.mac_computer]),
                      str(self.sequence_number),
                      str(self.error_code),
                      str(self.length),
                      str(self.fragment),
                      str(self.flags),
                      str(self.token),
                      str(self.checksum)))

        for tlv in self.tlvs:  # type: TLV
            result += '\nTag {0} ({1})\nLength {2}\nValue: {3}\n'.format(str(tlv.tag), tlv.get_human_readable_tag(),
                                                                         str(tlv.length),
                                                                         tlv.get_human_readable_value())

        return result

    def to_byte_array(self) -> bytearray:
        """Serialize the packet described by this instance to bytearray to send it to the switch"""
        header = bytearray()  # type: bytearray
        body = bytearray()  # type: bytearray

        header.extend(self.version.to_bytes(1, 'big'))
        header.extend(self.opcode.to_bytes(1, 'big'))
        header.extend(self.mac_switch)
        header.extend(self.mac_computer)
        header.extend(self.sequence_number.to_bytes(2, 'big'))

        header.extend(self.error_code.to_bytes(4, 'big'))
        header.extend(self.length.to_bytes(2, 'big'))
        header.extend(self.fragment.to_bytes(2, 'big'))
        header.extend(self.flags.to_bytes(2, 'big'))
        header.extend(self.token.to_bytes(2, 'big'))
        header.extend(self.checksum.to_bytes(4, 'big'))

        for i in self.tlvs:
            body.extend(i.tag.to_bytes(2, 'big'))
            body.extend(i.length.to_bytes(2, 'big'))
            body.extend(i.value)

        self.length = len(header) + len(body)
        header[20] = self.length.to_bytes(2, 'big')[0]
        header[21] = self.length.to_bytes(2, 'big')[1]

        return header + body
