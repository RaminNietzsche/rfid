#coding: utf-8
#!/usr/bin/env python

import serial
import string
import time

ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=1)
blockNtxt = 4

STX ,ADDR, LEN, CMD_STU, DATA, BCC = list(range(6))
CARD_TYPE = ['02','00']
CARD_NO_LEN = 4
ANTICOLL_ERR = 0x01
SAK_RESPONSE = 0x8
# SAK_RESPONSE = 0x18
AUTH_ERR = 0x01
CARDOPERATION_ERR = 0x11 #0x0f
CORRECT_RETURN = 0x00

def xor(fields):
	h = 0
	length = len(fields)
	for i in range(1, length):
		if type(fields[i]) is list:
			for j in fields[i]:
				h = int(hex(h ^ j), 16)
			continue
		h = int(hex(h^ fields[i]), 16)
	return h

def req_exp(card_type):
	if len(card_type) == 6:
		if card_type[2:4] != CARD_TYPE:
			err = 'rfmException: card type is not supported \n'
			err += 'use MIFARE 4K \n'
			return err
		if int(card_type[2]) == NO_CARD_ERR:
			err = 'rfmException: put card on device (10cm max distance) \n'
			return err
	else:
		return "Other req_ERR"

def Buzz_Control(time = 0x0a):
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0x00)
	protocol.insert(LEN, 0x02)
	protocol.insert(CMD_STU, 0x2c)
	protocol.insert(DATA, time)
	protocol.insert(BCC,xor(protocol))
	for item in protocol:
		ser.write(chr(item))
	ser.read(64)

def Device_LED_Control( LED1 =0X01, LED2=0X01):
	""" LED1 -> 0 = turn off LED1
	1 = turn on LED1
	LED2 -> 0 = turn off LED2
	1 = turn on LED2"""
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, 0x03)
	protocol.insert(CMD_STU, 0x2b)
	protocol.insert(DATA, [LED1, LED2])
	protocol.insert(BCC, xor(protocol) )
	for i in protocol:
		if type(i) is list:
			for j in i:
				# print (j)
				ser.write(chr(j))
			continue
		ser.write(chr(i))
	ser.read(64)

def Request_All(mode=0x52):
	"""Request mode -> = 0x52 request all card
	= 0x26 request card which is not in IDLE status
	correct return -> Card type(2 byte)"""
	msg = "out of range: choose mode in range [0x52, 0x26] \n"
	assert (mode in [0x52, 0x26]), msg
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, 0x02)
	protocol.insert(CMD_STU, 0x31)
	protocol.insert(DATA, 0x52)
	protocol.insert(BCC, xor(protocol))
	for i in protocol:
		ser.write(chr(i))
	Card_type = ser.read(6)
	Card_type = [ "%02X" % ord(x) for x in Card_type][:]
	if Card_type[2:4] != CARD_TYPE :
		# raise req_exp(card_type = Card_type)
		print req_exp(card_type = Card_type)

def Anti_Coll(parameter):
	"""Request card parameter -> = 0x93 no.1
	= 0x95 no.2
	= 0x97 no.3
	corect return -> Card series No.(4 byte) """
	msg = "out of range: choose card parameter in range [0x93, 0x95, 0x97] \n"
	assert (parameter in [0x93, 0x95, 0x97]), msg
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, 0x02)
	protocol.insert(CMD_STU, 0x32)
	protocol.insert(DATA, parameter)
	protocol.insert(BCC, xor(protocol))
	for i in protocol:
		ser.write(chr(i))
	Card_No = ser.read(9)
	Card_No = [ ord(x) for x in Card_No][4:8]
	if (len(Card_No) != CARD_NO_LEN) or (Card_No[2] == ANTICOLL_ERR):
		print "ERR Card No." 
	return Card_No

def Select_Card(parameter, card_No):
	"""Request card parameter -> = 0x93 no.1
	= 0x95 no.2
	= 0x97 no.3
	correct return -> SAK(1 byte)"""
	msg = "out of range: choose card parameter in range [0x93, 0x95, 0x97] \n"
	assert (parameter in [0x93, 0x95, 0x97]), msg
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	
	"""LEN = Request card parameter(1 byte) + Card series No(4 byte)
	+ cmd/stu"""
	protocol.insert(LEN, 0x06)
	protocol.insert(CMD_STU, 0x33)
	
	merge = [parameter]
	[merge.append(i) for i in card_No]

	protocol.insert(DATA, merge)
	protocol.insert(BCC, xor(protocol))
	
	for i in protocol:
		if type(i) is list:
			[ser.write(chr(j)) for j in i]
			continue
		ser.write(chr(i))
	SAK = ser.read(6)
	if (SAK == '') or (ord(SAK[-2]) != SAK_RESPONSE):
		print "select ERR"

def Authentication(mode, block_No, card_No):
	"""Data LEN : Authentication mode(1 byte) + block No.(1 byte) +
	card series No.(4 byte)
	Authentication mode -> = 0x60 Key A
	= 0x61 Key B
	Block No. -> 0~64(S50) or 0~255(S70)"""
	msg = "out of range: choose block number in range 0~255 \n"
	assert (block_No in list(range(255)) ), msg
	key = [0x60, 0x61]
	msg = 'out of range: choose from keyA(0x60) or keyB(0x61) \n'
	assert mode in key, msg
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, 0x07)
	protocol.insert(CMD_STU, 0x37)
	merge = [mode, block_No]
	[merge.append(i) for i in card_No]

	protocol.insert(DATA, merge)
	protocol.insert(BCC, xor(protocol))
	
	for i in protocol:
		if type(i) is list:
			[ser.write(chr(j)) for j in i]
			continue
		ser.write(chr(i))
	Auth = ser.read(5)
	if ord(Auth[3]) == AUTH_ERR:
		# raise auth_exp()
		print "Auth ERR"

def Read(block_No, block_quantity):
	"""Block No.(1 byte) + block quantity(1 byte)
	No. -> = 0~64(S50) or 0~255(S70)
	Block quantity -> = 1~4
	correct return -> Block data(16 byte* block quantity)
	"""
	msg = "out of range: choose block quantity in range 1~4 \n"
	assert (block_quantity in list(range(1,4)) ), msg
	msg = "out of range: choose block number in range 0~255 \n"
	assert (block_No in list(range(255)) ), msg
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, 0x03)
	protocol.insert(CMD_STU, 0x38)
	protocol.insert(DATA, [block_No, block_quantity])
	protocol.insert(BCC, xor(protocol))
	for i in protocol:
		if type(i) is list:
			[ser.write(chr(j)) for j in i]
			continue
		ser.write(chr(i))
	block_data = ser.read(16*block_quantity+5)
	if (len(block_data) == 5) and (ord(block_data[-2]) == CARDOPERATION_ERR):
		# raise read_exp()
		print "Read ERR"
	return block_data

def Write(block_No, block_quantity, block_data):
	"""Block No.(1 byte) + block quantity(1 byte) +
	block data(16 byte* block quantity)
	No. -> = 0~64(S50) or 0~255(S70)
	Block quantity -> = 1~4"""
	msg = "out of range: choose block quantity in range 1~4 \n"
	assert (block_quantity in list(range(1,4))), msg
	err = "wrong data type for block_data, use list type"
	assert isinstance(block_data, list), err
	msg = "out of range: choose block number in range 0~255 \n"
	assert (block_No in list(range(255))), msg
	"""block_data = 16 * block_quantity
	data_len = len(block_No) + len(block_quantity) + len(block_data) + 1"""
	data_len = len(block_data) + 3
	protocol = []
	protocol.insert(STX, 0x02)
	protocol.insert(ADDR, 0X00)
	protocol.insert(LEN, data_len)
	protocol.insert(CMD_STU, 0x39)
	merge = [block_No, block_quantity]
	[merge.append(i) for i in block_data]
	protocol.insert(DATA, merge)
	protocol.insert(BCC, xor(protocol))
	for i in protocol:
		print i
		if type(i) is list:
			[ser.write(chr(j)) for j in i]
			time.sleep(0.02)
			continue
		ser.write(chr(i))
		time.sleep(0.02)
	wr = ser.read(5)
	if (len(wr) == 5) and (ord(wr[-2]) != CORRECT_RETURN ):
		# raise write_exp()
		print "write err"

# def buzz_10():
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(2))
# 	ser.write(chr(44))
# 	ser.write(chr(10))
# 	ser.write(chr(36))
# 	result = ser.read(64)
# 	print ":".join("{0:x}".format(ord(c)) for c in result)

# def request_all():
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(2))
# 	ser.write(chr(49))
# 	ser.write(chr(82))
# 	ser.write(chr(97))
# 	ser.write(chr(26))
# 	result = ser.read(64)
# 	print ":".join("{0:x}".format(ord(c)) for c in result)

# def anti_coll():
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(2))
# 	ser.write(chr(50))
# 	ser.write(chr(147))
# 	ser.write(chr(163))
# 	ser.write(chr(26))
# 	result = ser.read(64)
# 	#result = filter(lambda x:x in string.printable, result)
# 	result = ":".join("{0:x}".format(ord(c)) for c in result)
# 	print result
# 	return result

# def select(id):
# 	myarr1 = id.split(':')[4:][:-1]
# 	print myarr1
# 	xorr = 0
# 	for item in myarr1:
# 		xorr = xorr ^ int(item, 16)
# 	xorr = xorr ^ int(6)
# 	xorr = xorr ^ int(51)
# 	xorr = xorr ^ int(147)

# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(6))
# 	ser.write(chr(51))
# 	ser.write(chr(147))
# 	for item in myarr1:
# 		ser.write(chr(int(item, 16)))
# 	ser.write(chr(xorr))
# 	ser.write(chr(26))
# 	print "select:"
# 	result = ser.read(64)
# 	result = ":".join("{0:x}".format(ord(c)) for c in result)
# 	print result

# def authentication(id):
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(7))
# 	ser.write(chr(55))
# 	ser.write(chr(96))
# 	ser.write(chr(blockNtxt))
# 	myarr1 = id.split(':')[4:][:-1]
# 	# serial = "".join(c for c in myarr1)
# 	xorr = 0
# 	for item in myarr1:
# 		xorr = xorr ^ int(item, 16)
# 		ser.write(chr(int(item, 16)))

# 	xorr = xorr ^ int(7)
# 	xorr = xorr ^ int(55)
# 	xorr = xorr ^ int(blockNtxt)
# 	xorr = xorr ^ int(96)
# 	ser.write(chr(xorr))
# 	ser.write(chr(26))
# 	print "aut"
# 	result = ser.read(64)
# 	result = ":".join("{0:x}".format(ord(c)) for c in result)
# 	print result

# def read():
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(3))
# 	ser.write(chr(56))
# 	ser.write(chr(blockNtxt))
# 	ser.write(chr(1))
# 	xor2 = 0
# 	xor2 = xor2 ^ 3 ^ 56 ^ (blockNtxt) ^ 1
# 	ser.write(chr(xor2))
# 	ser.write(chr(26))
# 	print "READ:"
# 	result = ser.read(64)
# 	result = ":".join("{0:x}".format(ord(c)) for c in result)
# 	print result

# def write(value):
# 	ser.write(chr(2))
# 	ser.write(chr(0))
# 	ser.write(chr(19))
# 	ser.write(chr(57))
# 	ser.write(chr(blockNtxt))
# 	ser.write(chr(1))
# 	writeTxt = value
# 	xor3 = 0
# 	for item in writeTxt:
# 		ser.write(item)
# 		xor3 = xor3 ^ ord(item)
# 		print ord(item)
# 	xor3 = xor3 ^ 19
# 	xor3 = xor3 ^ 57
# 	xor3 = xor3 ^ blockNtxt
# 	xor3 = xor3 ^ 1
# 	ser.write(chr(xor3))
# 	ser.write(chr(26))
# 	print "write:"
# 	result = ser.read(64)
# 	result = ":".join("{0:x}".format(ord(c)) for c in result)
# 	print result

# Buzz_Control()
# Device_LED_Control()
Request_All()
card_No = Anti_Coll(0x93)
Select_Card(0x93, card_No) 
Authentication(0x60, 4, card_No)
#result = Read(0, 1)
#result = ":".join("{0:x}".format(ord(c)) for c in result)
#print result
#Write(0, 1, [0,0,0,0,63,0,0,6,0,0,0,0,0,0,0,0])

# buzz_10()
# request_all()
# id = anti_coll()
# select (id)
# authentication(id)
# # write("111")
# read()

ser.close()