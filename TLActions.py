#!/usr/bin/env python3

import time
import socket

from TLCrypt import *
from TLPacketForge import *
from TLPacket import *
from TLPresentation import *

class TLSwitch:
	def __init__(self, packet):
		for i in packet.TLVs:
			if i.Tag == 2:
				self.Name = i.getHumanReadableValue()
			elif i.Tag == 4:
				self.IP = i.getHumanReadableValue()
			elif i.Tag == 3:
				self.MAC = i.Value
		self.SourcePacket = packet



PortCS = int.from_bytes(b'tp', 'big')
PortSC = PortCS + 1
BroadcastIP = '255.255.255.255'

DiscoveredSwitches = []


def TLDiscover(target = BroadcastIP, duration = 1):
	forged = TLPacket(forgeDiscovery())

	send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receive.bind(('0.0.0.0', PortSC))
	receive.setblocking(False)

	discoveryRequest = TLPacket(forgeDiscovery())
	send.sendto(TLARCCrypt(discoveryRequest.toByteArray()), (target, PortCS))

	start = time.time()
	
	while time.time() - start <= duration:
		try:
			data, addr = receive.recvfrom(1500)
			packet = TLPacket(TLARCCrypt(data))

			if isDiscovery(discoveryRequest, packet):
				found = False
				thisOne = TLSwitch(packet)

				for i in DiscoveredSwitches:
					if i.IP == thisOne.IP:
						found = True

				if not found:
					#packet.printSummary()
					#presentDiscovery(packet)
					DiscoveredSwitches.append(thisOne)
					if target != BroadcastIP:
						return
		
		except:
			pass




def TLGetToken(switchmac, switchip, timeout = 1):
	send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receive.bind(('0.0.0.0', PortSC))
	receive.setblocking(False)

	forged = TLPacket(forgeGetToken(switchmac))
	send.sendto(TLARCCrypt(forged.toByteArray()), (switchip, PortCS))

	start = time.time()
	
	while time.time() - start <= timeout:
		try:
			data, addr = receive.recvfrom(1500)
			packet = TLPacket(TLARCCrypt(data))

			if packet.SequenceNumber == forged.SequenceNumber:
				return extractTokenFromHeader(packet)

		except:
			pass

	return None




def TLLogin(switchmac, switchip, token, user, password, timeout = 1):
	send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receive.bind(('0.0.0.0', PortSC))
	receive.setblocking(False)

	forged = TLPacket(forgeLogin(switchmac, token, user, password))
	send.sendto(TLARCCrypt(forged.toByteArray()), (switchip, PortCS))

	start = time.time()
	
	while time.time() - start <= timeout:
		try:
			data, addr = receive.recvfrom(1500)
			packet = TLPacket(TLARCCrypt(data))

			if packet.SequenceNumber == forged.SequenceNumber:
				return packet.ErrorCode

		except:
			pass

	return None




def TLGetPortStatistics(switchmac, switchip, token, timeout = 1):
	send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receive.bind(('0.0.0.0', PortSC))
	receive.setblocking(False)

	forged = TLPacket(forgeGetPortStats(switchmac, token))
	send.sendto(TLARCCrypt(forged.toByteArray()), (switchip, PortCS))

	start = time.time()
	
	while time.time() - start <= timeout:
		try:
			data, addr = receive.recvfrom(1500)
			packet = TLPacket(TLARCCrypt(data))

			if packet.SequenceNumber == forged.SequenceNumber:
				return packet

		except:
			pass

	return None



def TLTestCable(switchmac, switchip, token, portnum, user, password, timeout = 10):
	send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	receive.bind(('0.0.0.0', PortSC))
	receive.setblocking(False)

	forged = TLPacket(forgeCableTest(switchmac, token, portnum, user, password))
	send.sendto(TLARCCrypt(forged.toByteArray()), (switchip, PortCS))

	start = time.time()
	
	while time.time() - start <= timeout:
		try:
			data, addr = receive.recvfrom(1500)
			packet = TLPacket(TLARCCrypt(data))

			if packet.SequenceNumber == forged.SequenceNumber:
				return packet

		except:
			pass

	return None
