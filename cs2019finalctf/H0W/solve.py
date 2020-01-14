import sys, struct, os
from terrynini import *
import struct
goodBlocks = open('goodOutput.txt', 'rb').read()
goodBlocks = [goodBlocks[i:i+4] for i in range(0, len(goodBlocks), 4) ]
goodBlocks = goodBlocks[0:-14]

nini3()
nini1()
nini4()

chooseOfKata = list()
for block in goodBlocks:
	x = nini5(0)
	if x == -87117812:
		chooseOfKata.append(1)
	elif x == 74628:
		chooseOfKata.append(2)
	elif x == 0:
		chooseOfKata.append(3)
	else:
		chooseOfKata.append(4)

def reverse_ichinokata(x):
	x ^= 0xfaceb00c
	return x
def reverse_ninokata(x):
	x -= 0x12384
	return x

a = 0x82222222


def reverse_sannokata(x):
	x1 = x & 0x55555555
	x2 = x & 0xaaaaaaaa
	highBitMask = (2**32-1)

	x1 = (x1 >> 0x1c) | ((x1 << 4) & (highBitMask))
	x2 = (x2 >> 2) | ((x2 << 0x1e) & (highBitMask))
	x = x1 | x2
	return x

def reverse_yonnokata(x):
	x = reverse_sannokata(x)
	x = reverse_ninokata(x)
	x = reverse_ichinokata(x)
	return x

file = open('result.txt', 'wb')
for i, block in enumerate(goodBlocks):
	print(i, '/', len(goodBlocks), end='\r')
	I = chooseOfKata[i]
	if I == 1:
		x = reverse_ichinokata(int.from_bytes(block, byteorder='little'))
	elif I == 2:
		x = reverse_ninokata(int.from_bytes(block, byteorder='little'))
	elif I == 3:
		x = reverse_sannokata(int.from_bytes(block, byteorder='little'))
	elif I == 4:
		x = reverse_yonnokata(int.from_bytes(block, byteorder='little'))
	
	x.to_bytes(5, byteorder='little', signed=True)[:-1].hex()
	file.write(x.to_bytes(5, byteorder='little', signed=True)[:-1])
print(chooseOfKata)