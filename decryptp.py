#!/usr/bin/env python3

from TLPresentation import *
from TLPacket import *
from TLCrypt import *
from TLPacketForge import *
from TLActions import *

import getopt
from sys import argv
from getpass import getpass


try:
	opts,args = getopt.getopt(argv[1:], 'di:')
except:
	opts = []
	pass


onlyDecrypt = False
argSwitchIP = None
selectedSwitch = None

for o, a in opts:
	if o == '-i':
		argSwitchIP = a
	elif o == '-d':
		onlyDecrypt = True


if onlyDecrypt:
	with open('test.raw', 'rb') as encrypted_file:
		data = encrypted_file.read()

	out = TLARCCrypt(data)

	with open('test.dec', 'wb') as outfile:
	    outfile.write(out)


	packet = TLPacket(out)
	with open('test2.dec', 'wb') as outfile:
	    outfile.write(packet.toByteArray())

	packet.printSummary()
else:
	if argSwitchIP != None:
		print('Only trying ' + argSwitchIP)
		TLDiscover(argSwitchIP)
	else:
		TLDiscover()

	if len(DiscoveredSwitches) > 0:
		print(' {0:2s}{1:31s} {2:15s} {3:31s} {4:10s}'.format('#', 'Name', 'IP', 'Model', 'Firmware'))
		for n, i in enumerate(DiscoveredSwitches):
			print('{0:2d} '.format(n), end ='')
			presentDiscovery(i.SourcePacket)

		selection = None if len(DiscoveredSwitches) > 1 else 0
		while selection == None:
			selectionRaw = input('Select switch: ')
			if selectionRaw.isnumeric() and int(selectionRaw) in range(0, len(DiscoveredSwitches)):
				selection = int(selectionRaw)

		selectedSwitch = DiscoveredSwitches[selection]
	else:
		print('No switches discovered.')
		selectedSwitch = None


	if selectedSwitch != None:
		token = TLGetToken(selectedSwitch.MAC, selectedSwitch.IP)

		loggedIn = False
		if token != None:
			while not loggedIn:
				username = input('User: ')
				password = getpass('Password: ')

				if TLLogin(selectedSwitch.MAC, selectedSwitch.IP, token, username, password) != 0:
					print('Wrong credentials')
				else:
					loggedIn = True

			# stats = TLGetPortStatistics(selectedSwitch.MAC, selectedSwitch.IP, token)
			# presentPortStatistics(stats)
			for i in range(1,9):
				cableTest = TLTestCable(selectedSwitch.MAC, selectedSwitch.IP, token, i, username, password)
				presentCableTest(cableTest)