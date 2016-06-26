#!/usr/bin/env python3

"""Offers help for parsing Tag-Length-Values."""

from typing import Tuple, Dict, List


_TLVDEFINITIONS = [
    (1, 'SYSINFO_PRODUCT_MODEL', 'STRING'),
    (2, 'SYSINFO_DESCRIPTION', 'STRING'),
    (3, 'SYSINFO_MAC', 'MAC'),
    (4, 'SYSINFO_IP', 'IP'),
    (5, 'SYSINFO_MASK', 'IP'),
    (6, 'SYSINFO_GATEWAY', 'IP'),
    (7, 'SYSINFO_FIRM_VERSION', 'STRING'),
    (8, 'SYSINFO_HARD_VERSION', 'STRING'),
    (9, 'SYSINFO_DHCP_STATE', 'BOOLEAN'),
    (10, 'SYSINFO_PORT_SUPPORT', 'BYTE'),
    (512, 'SYSUSER_OLD_NAME', 'STRING'),
    (513, 'SYSUSER_NEW_NAME', 'STRING'),
    (514, 'SYSUSER_OLD_PASSWORD', 'STRING'),
    (515, 'SYSUSER_NEW_PASSWORD', 'STRING'),
    (768, 'SYSCFG_BACKUP_FILE', ''),
    (769, 'SYSCFG_RESTORE_FILE', ''),
    (773, 'SYSREBOOT_REBOOT', 'BOOLEAN'),
    (1280, 'SYSRESET_RESET', 'NULL'),
    (1536, 'SYSUPGRADE_UPGRADE_FILE', ''),
    (1793, 'DIS_LOGIN_USERNAME', 'STRING'),
    (1794, 'DIS_LOGIN_PASSWORD', 'STRING'),
    (1795, 'DIS_LOGIN_AUTH', 'STRING'),
    (1796, 'DIS_PORT_NUM', 'BYTE'),
    (2049, 'DIS_SETTING_USERNAME', 'STRING'),
    (2050, 'DIS_SETTING_PASSWORD', 'STRING'),
    (2051, 'DIS_SETTING_DESCRIPTION', 'STRING'),
    (2052, 'DIS_SETTING_MAC_ADDRESS', 'MAC'),
    (2053, 'DIS_SETTING_FIRM_VER', 'STRING'),
    (2054, 'DIS_SETTING_HARD_VER', 'STRING'),
    (2055, 'DIS_SETTING_DHCP_STATE', 'BOOLEAN'),
    (2056, 'DIS_SETTING_IP', 'IP'),
    (2057, 'DIS_SETTING_MASK', 'IP'),
    (2058, 'DIS_SETTING_GATEWAY', 'IP'),
    (2304, 'SYSCFG_SAVE_CONFIG', 'NULL'),
    (2305, 'SYS_GET_TOKEN', 'NULL'),
    (4096, 'SWITCH_PORTCONFIG', 'BINARY'),
    (4352, 'SWITCH_IGMP_STATUS', 'BOOLEAN'),
    (4353, 'SWITCH_IGMP_MULTI', 'BINARY'),
    (4354, 'SWITCH_IGMP_REPORT_MSG_SUPPRESION', 'BOOLEAN'),
    (4608, 'SWITCH_TRUNK', 'BINARY'),
    (8192, 'VLANMTU_STATUS_UPLINKPORT', 'BINARY'),
    (8448, 'VLANPORTBASE_STATUS', 'BOOLEAN'),
    (8449, 'VLANPORTBASE_PORT', 'BINARY'),
    (8450, 'VLANPORTBASE_VLAN_SUPPORT', 'BYTE'),
    (8704, 'VLAN8021Q_STATUS', 'BOOLEAN'),
    (8705, 'VLAN8021Q_PORT', 'BINARY'),
    (8706, 'VLAN8021Q_PVID', 'BINARY'),
    (8707, 'VLAN8021Q_VLAN_SUPPORT', 'BYTE'),
    (12288, 'QOS_BASIC_MODE', 'BYTE'),
    (12289, 'QOS_BASIC_PRIORITY', 'BINARY'),
    (12544, 'QOS_BANDWIDTH_INGRESS', 'BINARY'),
    (12545, 'QOS_BANDWIDTH_EGRESS', 'BINARY'),
    (12800, 'QOS_STORM_CONTROL', 'BINARY'),
    (16384, 'MONITOR_PORT_STATISTICS', 'BINARY'),
    (16640, 'MONITOR_PORT_MIRROR', 'BINARY'),
    (16896, 'MONITOR_CABLE_TEST', 'BINARY'),
    (17152, 'MONITOR_LOOP_PREVENTION', 'BOOLEAN'),
    (65535, 'EOT', 'NULL')
]  # type: List[Tuple[int, str, str]]

TLVTYPES = {numeric: representation for (numeric, readable, representation) in _TLVDEFINITIONS}  # type: Dict[int, str]
TLVNAMES = {numeric: readable for (numeric, readable, representation) in _TLVDEFINITIONS}  # type: Dict[int, str]
TLVTAGS = {readable: numeric for (numeric, readable, representation) in _TLVDEFINITIONS}  # type: Dict[str, int]


class TLTLV:
    """This is a Tag-Length-Value combination as used to communicate with the switches."""

    def __init__(self, tag: int=None, val: any=None):
        self.value = ...  # type: any
        self.length = ...  # type: int
        self.tag = 0 if tag is None else tag  # type: int

        self.set_value(val)

    def set_value(self, val: bytes) -> None:
        """Sets the value of the TLTLV to val by trying to do
        a proper conversion and sets the correct length."""

        if val is None:
            self.value = b''
        elif isinstance(val, bytes):
            self.value = val
        elif isinstance(val, str):
            self.value = bytearray(val, 'utf-8') + b'\x00'
        elif isinstance(val, bool):
            self.value = b'\x01' if val else b'\x00'
        else:
            raise ValueError(
                'set_value does not support auto conversion from {0}. '
                'Please convert it manually. Supported: NoneType, bytes, str, bool.'.format(str(type(val))))

        self.length = len(self.value)

    def get_human_readable_tag(self) -> str:
        """Returns the name of the tag."""
        return TLVNAMES.get(self.tag, '?')

    def get_human_readable_value(self) -> str:
        """Returns a string containing the value."""
        if len(self.value) == 0:
            return 'unset'

        new_tlv = TLVTYPES.get(self.tag, 'BINARY')  # type: str

        if new_tlv == 'IP':
            return ('malformed' if len(self.value) != 4 else
                    ('{:d}.{:d}.{:d}.{:d}'
                     .format(self.value[0], self.value[1], self.value[2], self.value[3])))
        elif new_tlv == 'MAC':
            return ('malformed' if len(self.value) != 6 else
                    ('{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'
                     .format(self.value[0], self.value[1], self.value[2],
                             self.value[3], self.value[4], self.value[5])))
        elif new_tlv == 'STRING':
            return 'empty' if len(self.value) == 0 else self.value[:-1].decode('utf-8')
        elif new_tlv == 'BOOLEAN':
            return ('malformed' if len(self.value) != 1 else
                    str(self.value[0] == 1))
        elif new_tlv == 'BINARY':
            return ''.join([format(b, '02X') for b in self.value])
        elif new_tlv == 'BYTE':
            return 'malformed' if len(self.value) != 1 else '{:d}'.format(self.value[0])
        else:
            return '-'
