import sys, struct, os
from terrynini import *

if len(sys.argv) != 2:
    print('Usage: python3 H0W.py filename')
    exit(0)

# nini1() use time as seed
# nini2() return time as string
# nini3() create output.txt, do some initial
# nini4() set rand
# nini5() 4 types of transform
# nini6() write bytes into file

# find the data that makes goodOutput.txt
# rand uses time = 2019/09/11 13:25:14

nini3()

f = open(sys.argv[1], 'rb').read()
if len(f) % 4 != 0:
    f += (4 - len(f) % 4) * b'\x00'

nini1()
nini4()

for i in range(0, len(f), 4):
    nini6(nini5(struct.unpack('<i', f[i:i + 4])[0]))

for i in list(map(ord, nini2())):
    nini6(i)
print('Complete')