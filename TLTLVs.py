#!/usr/bin/env python3


TLVNames = {1:     'SYSINFO_PRODUCT_MODEL',
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
            1536:  'SYSUPGRADE_UPGRADE_FILE',
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
            2304:  'SYSCFG_SAVE_CONFIG',
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
            16384: 'MONITOR_PORT_STATISTICS',
            16640: 'MONITOR_PORT_MIRROR',
            16896: 'MONITOR_CABLE_TEST',
            17152: 'MONITOR_LOOP_PREVENTION',
            65535: 'EOT'}

TLVTypes = {1:     'STRING',
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
           # 773:   'SYSREBOOT_REBOOT',
           # 1280:  'SYSRESET_RESET',
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
           # 2304:  'SYSCFG_SAVE_CONFIG',
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
           # 8707:  'VLAN8021Q_VLAN_SUPPORT',
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
   # Tag = int()
   # Length = int()
   # Value = bytearray()

    def setStringValue(self, val):
      self.Length = len(val) + 1
      self.Value = bytearray(val, 'utf-8') + b'\x00'


    def getHumanReadableTag(self):
        return TLVNames.get(self.Tag, '?')
        
    def getHumanReadableValue(self):
        t = TLVTypes.get(self.Tag, 'BINARY')

        if t == 'IP':
            if len(self.Value) != 4:
                return 'malformed'
            else:
                return '{:d}.{:d}.{:d}.{:d}'.format(self.Value[0], self.Value[1], self.Value[2], self.Value[3])
        elif t == 'MAC':
            if len(self.Value) != 6:
                return 'malformed'
            else:
                return '{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'.format(self.Value[0], self.Value[1], self.Value[2], self.Value[3], self.Value[4], self.Value[5])
        elif t == 'STRING':
            if len(self.Value) == 0:
                return 'empty'
            elif len(self.Value) > 1:
                return self.Value[:-1].decode('utf-8')
            else:
                return 'malformed'
        elif t == 'BOOLEAN':
                if len(self.Value) != 1:
                    return 'malformed'
                else:
                    return 'true' if self.Value[0] == 1 else 'false'
        elif t == 'BINARY':
                return "".join(map(lambda b: format(b, "02X"), self.Value))
        elif t == 'BYTE':
            if len(self.Value) != 1:
                return 'malformed'
            else:
                return '{:d}'.format(self.Value[0])
        else:
            return '-'


