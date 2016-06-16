#!/usr/bin/env python3

"""Offers help for parsing Tag-Length-Values."""

_TLVDEFINITIONS = {
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
    (2057, 'DIS_SETTING_MASK', ''),
    (2058, 'DIS_SETTING_GATEWAY', 'IP'),
    (2304, 'SYSCFG_SAVE_CONFIG', 'NULL'),
    (2305, 'SYS_GET_TOKEN', 'NULL'),
    (4096, 'SWITCH_PORTCONFIG', ''),
    (4352, 'SWITCH_IGMP_STATUS', ''),
    (4353, 'SWITCH_IGMP_MULTI', ''),
    (4354, 'SWITCH_IGMP_REPORT_MSG_SUPPRESION', ''),
    (4608, 'SWITCH_TRUNK', ''),
    (8192, 'VLANMTU_STATUS_UPLINKPORT', ''),
    (8448, 'VLANPORTBASE_STATUS', ''),
    (8449, 'VLANPORTBASE_PORT', ''),
    (8450, 'VLANPORTBASE_VLAN_SUPPORT', ''),
    (8704, 'VLAN8021Q_STATUS', ''),
    (8705, 'VLAN8021Q_PORT', ''),
    (8706, 'VLAN8021Q_PVID', ''),
    (8707, 'VLAN8021Q_VLAN_SUPPORT', 'BYTE'),
    (12288, 'QOS_BASIC_MODE', ''),
    (12289, 'QOS_BASIC_PRIORITY', ''),
    (12544, 'QOS_BANDWIDTH_INGRESS', ''),
    (12545, 'QOS_BANDWIDTH_EGRESS', ''),
    (12800, 'QOS_STORM_CONTROL', ''),
    (16384, 'MONITOR_PORT_STATISTICS', ''),
    (16640, 'MONITOR_PORT_MIRROR', ''),
    (16896, 'MONITOR_CABLE_TEST', ''),
    (17152, 'MONITOR_LOOP_PREVENTION', 'BOOLEAN'),
    (65535, 'EOT', 'NULL')
    }

TLVTYPES = {numeric: representation for (numeric, _, representation) in _TLVDEFINITIONS}
TLVNAMES = {numeric: readable for (numeric, readable, _) in _TLVDEFINITIONS}
TLVTAGS = {readable: numeric for (numeric, readable, _) in _TLVDEFINITIONS}


class TLV:
    """This is a Tag-Length-Value combination as used to comunicate with the switches."""

    def __init__(self, tag=None, val=None):
        self.tag = 0 if tag is None else tag
        self.set_value(val)

    def set_value(self, val):
        """Sets the value of the TLV to val by trying to do
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
            raise ValueError('set_value does not support auto conversion from ' +
                             str(type(val)) +
                             '. Please convert it manually. Supported: NoneType, bytes, str, bool.')

        self.length = len(self.value)


    def get_human_readable_tag(self):
        """Returns the name of the tag."""
        return TLVNAMES.get(self.tag, '?')

    def get_human_readable_value(self):
        """Returns a string containing the value."""
        new_tlv = TLVTYPES.get(self.tag, 'BINARY')
        result = ''

        if new_tlv == 'IP':
            result = ('malformed' if len(self.value) != 4 else
                      ('{:d}.{:d}.{:d}.{:d}'
                       .format(self.value[0], self.value[1], self.value[2], self.value[3])))
        elif new_tlv == 'MAC':
            result = ('malformed' if len(self.value) != 6 else
                      ('{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'
                       .format(self.value[0], self.value[1], self.value[2],
                               self.value[3], self.value[4], self.value[5])))
        elif new_tlv == 'STRING':
            result = 'empty' if len(self.value) == 0 else self.value[:-1].decode('utf-8')
        elif new_tlv == 'BOOLEAN':
            result = ('malformed' if len(self.value) != 1 else
                      str(self.value[0] == 1))
        elif new_tlv == 'BINARY':
            result = ''.join([format(b, '02X') for b in self.value])
        elif new_tlv == 'BYTE':
            result = 'malformed' if len(self.value) != 1 else '{:d}'.format(self.value[0])
        else:
            result = '-'

        return result


