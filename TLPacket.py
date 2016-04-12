#!/usr/bin/env python3

from TLTLVs import *

class TLPacket:
  #  Version = 0
  #  Opcode = 0
  #  MACSwitch = b'\x00\x00\x00\x00\x00\x00'
  #  MACComputer = b'\x00\x00\x00\x00\x00\x00'
  #  SequenceNumber = 0
  #  ErrorCode = 0
  #  Length = 0
  #  Fragment = 0
  #  Flags = 0
  #  Token = 0
  #  Checksum = 0
  #  TLVs = []

    def __init__(self, decrypted = None):
        if decrypted == None:
            self.Version = 0
            self.Opcode = 0
            self.MACSwitch = b'\x00\x00\x00\x00\x00\x00'
            self.MACComputer = b'\x00\x00\x00\x00\x00\x00'
            self.SequenceNumber = 0
            self.ErrorCode = 0
            self.Length = 0
            self.Fragment = 0
            self.Flags = 0
            self.Token = 0
            self.Checksum = 0

            self.TLVs = []
        else:
            self.Version = decrypted[0]
            self.Opcode = decrypted[1]
            self.MACSwitch = [decrypted[2], decrypted[3], decrypted[4], decrypted[5], decrypted[6], decrypted[7]]
            self.MACComputer = [decrypted[8], decrypted[9], decrypted[10], decrypted[11], decrypted[12], decrypted[13]]
            self.SequenceNumber = (decrypted[14] << 8) + decrypted[15]
            self.ErrorCode = (decrypted[16] << 24) + (decrypted[17] << 16) + (decrypted[18] << 8) + decrypted[19]
            self.Length = (decrypted[20] << 8) + decrypted[21]
            self.Fragment = (decrypted[22] << 8) + decrypted[23]
            self.Flags = (decrypted[24] << 8) + decrypted[25]
            self.Token = (decrypted[26] << 8) + decrypted[27]
            self.Checksum = (decrypted[28] << 24) + (decrypted[29] << 16) + (decrypted[30] << 8) + decrypted[31]

            body = decrypted[32:]

            self.TLVs = []
            while len(body) > 0:
                ntlv = TLV()
                ntlv.Tag    = (body[0] << 8) + body[1]
                ntlv.Length = (body[2] << 8) + body[3]
                ntlv.Value  = body[4:ntlv.Length + 4]
                body = body[ntlv.Length + 4:]
                self.TLVs.append(ntlv)

    def printSummary(self):
        print("Version:        " + str(self.Version))
        print("Opcode:         " + str(self.Opcode))
        print("MAC Switch:     " + "".join(map(lambda b: format(b, "02x"), self.MACSwitch)))
        print("MAC Computer:   " + "".join(map(lambda b: format(b, "02x"), self.MACComputer)))
        print("SequenceNumber: " + str(self.SequenceNumber))
        print("Error:          " + str(self.ErrorCode))
        print("Length:         " + str(self.Length))
        print("Fragment:       " + str(self.Fragment))
        print("Flags:          " + str(self.Flags))
        print("Token:          " + str(self.Token))
        print("Checksum:       " + str(self.Checksum))

        for t in self.TLVs:
            print()
            print("Tag " + str(t.Tag) + " (" + t.getHumanReadableTag() + ")")
            print("Length " + str(t.Length))
            print("Value: " + t.getHumanReadableValue())

    def toByteArray(self):
        header = bytearray()
        body = bytearray()

        header.extend(self.Version.to_bytes(1, 'big'))
        header.extend(self.Opcode.to_bytes(1, 'big'))
        header.extend(self.MACSwitch)
        header.extend(self.MACComputer)
        header.extend(self.SequenceNumber.to_bytes(2, 'big'))

        header.extend(self.ErrorCode.to_bytes(4, 'big'))
        header.extend(self.Length.to_bytes(2, 'big'))
        header.extend(self.Fragment.to_bytes(2, 'big'))
        header.extend(self.Flags.to_bytes(2, 'big'))
        header.extend(self.Token.to_bytes(2, 'big'))
        header.extend(self.Checksum.to_bytes(4, 'big'))

        for i in self.TLVs:
            body.extend(i.Tag.to_bytes(2, 'big'))
            body.extend(i.Length.to_bytes(2, 'big'))
            body.extend(i.Value)

        self.Length = len(header) + len(body)
        header[20] = self.Length.to_bytes(2, 'big')[0]
        header[21] = self.Length.to_bytes(2, 'big')[1]
        
        return header + body
