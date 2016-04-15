#!/usr/bin/env python3

"""TP-Link packet parser"""

from struct import unpack
from TLTLVs import TLV

class TLPacket:
    """Class for TP-Link packet representation"""

    OPCODES = {'DISCOVER': 0, 'GET': 1, 'SET': 3}

    def __init__(self, decrypted=None):
        if decrypted is None:
            self.version = 1
            self.opcode = self.OPCODES['DISCOVER']
            self.mac_switch = b'\x00\x00\x00\x00\x00\x00'
            self.mac_computer = b'\x00\x00\x00\x00\x00\x00'
            self.sequence_number = 0
            self.error_code = 0
            self.length = 0
            self.fragment = 0
            self.flags = 0
            self.token = 0
            self.checksum = 0

            self.tlvs = []
        elif len(decrypted) >= 32:
            (self.version, self.opcode, self.mac_switch,
             self.mac_computer, self.sequence_number,
             self.error_code, self.length, self.fragment,
             self.flags, self.token, self.checksum) = unpack('>BB6s6sHIHHHHI', decrypted[:32])

            body = decrypted[32:]

            self.tlvs = []
            while len(body) > 3:
                ntlv = TLV()
                ntlv.tag, ntlv.length = unpack('>HH', body[:4])
                if len(body) >= ntlv.length + 4:
                    ntlv.value = body[4:ntlv.length + 4]
                    body = body[ntlv.length + 4:]

                self.tlvs.append(ntlv)

    def __str__(self):
        """Prints a human readable summary of the packet to stdout"""
        result = ''
        result += 'Version:         ' + str(self.version) + '\n'
        result += 'Opcode:          ' + str(self.opcode) + '\n'
        result += 'MAC Switch:      ' + ''.join([format(b, '02X') for b in self.mac_switch]) + '\n'
        result += 'MAC Computer:    ' + ''.join([format(b, '02X') for b in self.mac_computer]) + '\n'
        result += 'Sequence Number: ' + str(self.sequence_number) + '\n'
        result += 'Error:           ' + str(self.error_code) + '\n'
        result += 'Length:          ' + str(self.length) + '\n'
        result += 'Fragment:        ' + str(self.fragment) + '\n'
        result += 'Flags:           ' + str(self.flags) + '\n'
        result += 'Token:           ' + str(self.token) + '\n'
        result += 'Checksum:        ' + str(self.checksum) + '\n'

        for tlv in self.tlvs:
            result += '\n'
            result += 'Tag ' + str(tlv.tag) + ' (' + tlv.get_human_readable_tag() + ')' + '\n'
            result += 'Length ' + str(tlv.length) + '\n'
            result += 'Value: ' + tlv.get_human_readable_value() + '\n'

        return result

    def to_byte_array(self):
        """Serialize the packet described by this instance to bytearray to send it to the switch"""
        header = bytearray()
        body = bytearray()

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
