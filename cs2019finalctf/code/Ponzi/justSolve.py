from Crypto.Hash import SHA256
import random
prefix = open('prefix.txt', 'r').read()

test = random.randint(0, 111111111111)
finishFlag = False

ID = random.random()


while not finishFlag:
	d = bytes(prefix + str(test), 'ascii')
	h = SHA256.new(data=d)
	c = h.hexdigest()
	if c[0:5] == '00000':
		if c[5] in '0123':
			file = open('goodsuffix.txt', 'a')
			file.write(str(test)+'\n')
			print(d)
			print(c)
			print(test)
			file.close()
			break
	test += 1
