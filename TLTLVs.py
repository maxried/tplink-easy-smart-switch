#!/usr/bin/env python3

"""Offers help for parsing Tag-Length-Values."""

TLVTAGS = {
    'SYSINFO_PRODUCT_MODEL': 1,
    'SYSINFO_DESCRIPTION': 2,
    'SYSINFO_MAC': 3,
    'SYSINFO_IP': 4,
    'SYSINFO_MASK': 5,
    'SYSINFO_GATEWAY': 6,
    'SYSINFO_FIRM_VERSION': 7,
    'SYSINFO_HARD_VERSION': 8,
    'SYSINFO_DHCP_STATE': 9,
    'SYSINFO_PORT_SUPPORT': 10,
    'SYSUSER_OLD_NAME': 512,
    'SYSUSER_NEW_NAME': 513,
    'SYSUSER_OLD_PASSWORD': 514,
    'SYSUSER_NEW_PASSWORD': 515,
    'SYSCFG_BACKUP_FILE': 768,
    'SYSCFG_RESTORE_FILE': 769,
    'SYSREBOOT_REBOOT': 773,
    'SYSRESET_RESET': 1280,
    'SYSUPGRADE_UPGRADE_FILE': 1536,
    'DIS_LOGIN_USERNAME': 1793,
    'DIS_LOGIN_PASSWORD': 1794,
    'DIS_LOGIN_AUTH': 1795,
    'DIS_PORT_NUM': 1796,
    'DIS_SETTING_USERNAME': 2049,
    'DIS_SETTING_PASSWORD': 2050,
    'DIS_SETTING_DESCRIPTION': 2051,
    'DIS_SETTING_MAC_ADDRESS': 2052,
    'DIS_SETTING_FIRM_VER': 2053,
    'DIS_SETTING_HARD_VER': 2054,
    'DIS_SETTING_DHCP_STATE': 2055,
    'DIS_SETTING_IP': 2056,
    'DIS_SETTING_MASK': 2057,
    'DIS_SETTING_GATEWAY': 2058,
    'SYSCFG_SAVE_CONFIG': 2304,
    'SYS_GET_TOKEN': 2305,
    'SWITCH_PORTCONFIG': 4096,
    'SWITCH_IGMP_STATUS': 4352,
    'SWITCH_IGMP_MULTI': 4353,
    'SWITCH_IGMP_REPORT_MSG_SUPPRESION': 4354,
    'SWITCH_TRUNK': 4608,
    'VLANMTU_STATUS_UPLINKPORT': 8192,
    'VLANPORTBASE_STATUS': 8448,
    'VLANPORTBASE_PORT': 8449,
    'VLANPORTBASE_VLAN_SUPPORT': 8450,
    'VLAN8021Q_STATUS': 8704,
    'VLAN8021Q_PORT': 8705,
    'VLAN8021Q_PVID': 8706,
    'VLAN8021Q_VLAN_SUPPORT': 8707,
    'QOS_BASIC_MODE': 12288,
    'QOS_BASIC_PRIORITY': 12289,
    'QOS_BANDWIDTH_INGRESS': 12544,
    'QOS_BANDWIDTH_EGRESS': 12545,
    'QOS_STORM_CONTROL': 12800,
    'MONITOR_PORT_STATISTICS': 16384,
    'MONITOR_PORT_MIRROR': 16640,
    'MONITOR_CABLE_TEST': 16896,
    'MONITOR_LOOP_PREVENTION': 17152,
    'EOT': 65535}


TLVNAMES = {
    1:     'SYSINFO_PRODUCT_MODEL',
    2:     'SYSINFO_DESCRIPTION',
    3:     'SYSINFO_MAC',
    4:     'SYSINFO_IP',
    5:     'SYSINFO_MASK',
    6:     'SYSINFO_GATEWAY',
    7:     'SYSINFO_FIRM_VERSION',
    8:     'SYSINFO_HARD_VERSION',
    9:     'SYSINFO_DHCP_STATE',
    10:    'SYSINFO_PORT_SUPPORT',
    512:   'SYSUSER_OLD_NAME',
    513:   'SYSUSER_NEW_NAME',
    514:   'SYSUSER_OLD_PASSWORD',
    515:   'SYSUSER_NEW_PASSWORD',
    768:   'SYSCFG_BACKUP_FILE',
    769:   'SYSCFG_RESTORE_FILE',
    773:   'SYSREBOOT_REBOOT',
    1280:  'SYSRESET_RESET',
    1536:  'SYSUPGRADE_UPGRADE_FILE', # Enables firmware upgrade mode. Download via http
    1793:  'DIS_LOGIN_USERNAME',
    1794:  'DIS_LOGIN_PASSWORD',
    1795:  'DIS_LOGIN_AUTH',
    1796:  'DIS_PORT_NUM',
    2049:  'DIS_SETTING_USERNAME',
    2050:  'DIS_SETTING_PASSWORD',
    2051:  'DIS_SETTING_DESCRIPTION',
    2052:  'DIS_SETTING_MAC_ADDRESS',
    2053:  'DIS_SETTING_FIRM_VER',
    2054:  'DIS_SETTING_HARD_VER',
    2055:  'DIS_SETTING_DHCP_STATE',
    2056:  'DIS_SETTING_IP',
    2057:  'DIS_SETTING_MASK',
    2058:  'DIS_SETTING_GATEWAY',
    2304:  'SYSCFG_SAVE_CONFIG', # wr mem
    2305:  'SYS_GET_TOKEN',
    4096:  'SWITCH_PORTCONFIG',
    4352:  'SWITCH_IGMP_STATUS',
    4353:  'SWITCH_IGMP_MULTI',
    4354:  'SWITCH_IGMP_REPORT_MSG_SUPPRESION',
    4608:  'SWITCH_TRUNK',
    8192:  'VLANMTU_STATUS_UPLINKPORT',
    8448:  'VLANPORTBASE_STATUS',
    8449:  'VLANPORTBASE_PORT',
    8450:  'VLANPORTBASE_VLAN_SUPPORT',
    8704:  'VLAN8021Q_STATUS',
    8705:  'VLAN8021Q_PORT',
    8706:  'VLAN8021Q_PVID',
    8707:  'VLAN8021Q_VLAN_SUPPORT',
    12288: 'QOS_BASIC_MODE',
    12289: 'QOS_BASIC_PRIORITY',
    12544: 'QOS_BANDWIDTH_INGRESS',
    12545: 'QOS_BANDWIDTH_EGRESS',
    12800: 'QOS_STORM_CONTROL',
    16384: 'MONITOR_PORT_STATISTICS', # Opcode 1 => Get, Opcode 3 => Clear
    16640: 'MONITOR_PORT_MIRROR',
    16896: 'MONITOR_CABLE_TEST',
    17152: 'MONITOR_LOOP_PREVENTION',
    65535: 'EOT'}

TLVTYPES = {
    1:     'STRING',
    2:     'STRING',
    3:     'MAC',
    4:     'IP',
    5:     'IP',
    6:     'IP',
    7:     'STRING',
    8:     'STRING',
    9:     'BOOLEAN',
    10:    'BYTE',
    512:   'STRING',
    513:   'STRING',
    514:   'STRING',
    515:   'STRING',
    # 768:   'SYSCFG_BACKUP_FILE',
    # 769:   'SYSCFG_RESTORE_FILE',
    773:   'BOOLEAN', # True if config should be saved to nvram before reboot
    1280:  'NULL',
    # 1536:  'SYSUPGRADE_UPGRADE_FILE',
    1793:  'STRING',
    1794:  'STRING',
    1795:  'STRING',
    1796:  'BYTE',
    2049:  'STRING',
    2050:  'STRING',
    2051:  'STRING',
    2052:  'MAC',
    2053:  'STRING',
    2054:  'STRING',
    2055:  'BOOLEAN',
    2056:  'IP',
    2057:  'IP',
    2058:  'IP',
    2304:  'NULL',
    # 2305:  'SYS_GET_TOKEN',
    # 4096:  'SWITCH_PORTCONFIG',
    # 4352:  'SWITCH_IGMP_STATUS',
    # 4353:  'SWITCH_IGMP_MULTI',
    # 4354:  'SWITCH_IGMP_REPORT_MSG_SUPPRESION',
    # 4608:  'SWITCH_TRUNK',
    # 8192:  'VLANMTU_STATUS_UPLINKPORT',
    # 8448:  'VLANPORTBASE_STATUS',
    # 8449:  'VLANPORTBASE_PORT',
    # 8450:  'VLANPORTBASE_VLAN_SUPPORT',
    # 8704:  'VLAN8021Q_STATUS',
    # 8705:  'VLAN8021Q_PORT',
    # 8706:  'VLAN8021Q_PVID',
    8707:  'BYTE',
    # 12288: 'QOS_BASIC_MODE',
    # 12289: 'QOS_BASIC_PRIORITY',
    # 12544: 'QOS_BANDWIDTH_INGRESS',
    # 12545: 'QOS_BANDWIDTH_EGRESS',
    # 12800: 'QOS_STORM_CONTROL',
    # 16384: 'MONITOR_PORT_STATISTICS',
    # 16640: 'MONITOR_PORT_MIRROR',
    # 16896: 'MONITOR_CABLE_TEST',
    # 17152: 'MONITOR_LOOP_PREVENTION',
    65535: 'NULL'}


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
                      'true' if self.value[0] == 1 else 'false')
        elif new_tlv == 'BINARY':
            result = ''.join([format(b, '02X') for b in self.value])
        elif new_tlv == 'BYTE':
            result = 'malformed' if len(self.value) != 1 else '{:d}'.format(self.value[0])
        else:
            result = '-'

        return result


