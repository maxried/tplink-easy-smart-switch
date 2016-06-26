#!/usr/bin/env python3

"""TP-Link packet parser"""

from typing import List, Dict
from struct import unpack
from TLTLVs import TLTLV


TLERRORCODES = {
    0: 'SYS_OK',
    -1: 'SYS_ERR_FALSE',
    -2: 'SYS_ERR',
    -3: 'SYS_ERR_CANCELLED',
    -4: 'SYS_ERR_PARAMETER',
    -5: 'SYS_ERR_TIMEOUT',
    -6: 'SYS_ERR_FULL',
    -7: 'SYS_ERR_STATE',
    -8: 'SYS_ERR_OUT_OF_RESOURCE',
    -9: 'SYS_ERR_NOT_IMPLEMENTED',
    -10: 'SYS_ERR_EXISTS',
    -11: 'SYS_ERR_NOT_FOUND',
    -12: 'SYS_ERR_FUNC_NOT_ENABLED',
    1: 'ERR_HEADER_LENGTH',
    2: 'ERR_TLV_TYPE',
    3: 'ERR_TLV_LENGTH',
    4: 'ERR_TLV_VALUE',
    5: 'ERR_USER_PWD_NOT_MATCHING',
    6: 'ERR_IP_ERROR',
    7: 'ERR_USER_PWD_CHANGED',
    8: 'ERR_TOKEN_ERROR',
    9: 'ERR_MASK_ERROR',
    10: 'ERR_GATEWAY_ERROR',
    11: 'ERR_UPGRADE_IP_CONFLICT',
    7401: 'ERR_TRUNK_VLAN',
    7403: 'ERR_TRUNK_RATELIMIT',
    7404: 'ERR_TRUNK_STORMCONTROL',
    7405: 'ERR_TRUNK_QOSPRIORITY',
    7406: 'ERR_TRUNK_PORTSPEED',
    7407: 'ERR_TRUNK_PORTDUPLEX',
    7410: 'ERR_TRUNK_PORTNEGO',
    7415: 'ERR_TRUNK_PORTNUM',
    7417: 'ERR_TRUNK_FLOWCTRL',
    7418: 'ERR_TRUNK_PORTSTATUS',
    7500: 'ERR_INPUT_STR_LEN',
    7501: 'ERR_DUPLICATE_NAME',
    7502: 'ERR_VLAN_DISABLE',
    7503: 'ERR_VLAN_ID_INVALID',
    7504: 'ERR_VLAN_ENTRY_INDEX',
    7505: 'ERR_VLAN_FULL',
    7506: 'ERR_VLAN_EXIST_PVID',
    7507: 'ERR_VLAN_EXIST',
    7508: 'ERR_VLAN_NOT_EXIST',
    7509: 'ERR_VLAN_INS_VLAN_ENTRY',
    7510: 'ERR_VLAN_DEL_VLAN_ENTRY',
    7511: 'ERR_VLAN_DEL_DEFAULT_VLAN',
    7512: 'ERR_VLAN_ENTRY_INVALID',
    7513: 'ERR_VLAN_ENTRY_DUPLICATE',
    7514: 'ERR_VLAN_TYPE',
    7515: 'ERR_VLAN_MTU_LAG_MUTEX'
}


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

            self.tlvs = []  # type: List[TLTLV]
        elif len(decrypted) >= 32:
            [self.version, self.opcode, self.mac_switch,
             self.mac_computer, self.sequence_number,
             self.error_code, self.length, self.fragment,
             self.flags, self.token, self.checksum] = unpack('>BB6s6sHIHHHHI', decrypted[:32])

            body = decrypted[32:]  # type: bytes

            self.tlvs = []  # type: List[TLTLV]
            while len(body) > 3:
                ntlv = TLTLV()  # type: TLTLV
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
                  'Error:           {5} ({6})\n'
                  'Length:          {7}\n'
                  'Fragment:        {8}\n'
                  'Flags:           {9}\n'
                  'Token:           {10}\n'
                  'Checksum:        {11}\n'.format(
                      str(self.version),
                      str(self.opcode),
                      ''.join([format(b, '02X') for b in self.mac_switch]),
                      ''.join([format(b, '02X') for b in self.mac_computer]),
                      str(self.sequence_number),
                      str(self.error_code),
                      TLERRORCODES.get(self.error_code, '?'),
                      str(self.length),
                      str(self.fragment),
                      str(self.flags),
                      str(self.token),
                      str(self.checksum)))

        for tlv in self.tlvs:  # type: TLTLV
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
