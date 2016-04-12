#!/usr/bin/env python3

from TLTLVs import TLV

class TLPacket:
    def __init__(self, decrypted=None):
        if decrypted is None:
            self.version = 0
            self.opcode = 0
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
        else:
            self.version = decrypted[0]
            self.opcode = decrypted[1]
            self.mac_switch = bytes([decrypted[2], decrypted[3], decrypted[4],
                                     decrypted[5], decrypted[6], decrypted[7]])
            self.mac_computer = bytes([decrypted[8], decrypted[9], decrypted[10],
                                       decrypted[11], decrypted[12], decrypted[13]])
            self.sequence_number = (decrypted[14] << 8) + decrypted[15]
            self.error_code = ((decrypted[16] << 24) + (decrypted[17] << 16) +
                               (decrypted[18] << 8) + decrypted[19])
            self.length = (decrypted[20] << 8) + decrypted[21]
            self.fragment = (decrypted[22] << 8) + decrypted[23]
            self.flags = (decrypted[24] << 8) + decrypted[25]
            self.token = (decrypted[26] << 8) + decrypted[27]
            self.checksum = ((decrypted[28] << 24) + (decrypted[29] << 16) +
                             (decrypted[30] << 8) + decrypted[31])

            body = decrypted[32:]

            self.tlvs = []
            while len(body) > 0:
                ntlv = TLV()
                ntlv.tag = (body[0] << 8) + body[1]
                ntlv.length = (body[2] << 8) + body[3]
                ntlv.value = body[4:ntlv.length + 4]
                body = body[ntlv.length + 4:]
                self.tlvs.append(ntlv)

    def print_summary(self):
        print("version:        " + str(self.version))
        print("opcode:         " + str(self.opcode))
        print("MAC Switch:     " + "".join([format(b, "02X") for b in self.mac_switch]))
        print("MAC Computer:   " + "".join([format(b, "02X") for b in self.mac_computer]))
        print("sequence_number: " + str(self.sequence_number))
        print("Error:          " + str(self.error_code))
        print("length:         " + str(self.length))
        print("fragment:       " + str(self.fragment))
        print("flags:          " + str(self.flags))
        print("token:          " + str(self.token))
        print("checksum:       " + str(self.checksum))

        for tlv in self.tlvs:
            print()
            print("Tag " + str(tlv.tag) + " (" + tlv.get_human_readable_tag() + ")")
            print("length " + str(tlv.length))
            print("Value: " + tlv.get_human_readable_value())

    def to_byte_array(self):
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
