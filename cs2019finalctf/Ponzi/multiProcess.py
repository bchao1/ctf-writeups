import threading
import os
N = 20

def test():
	os.system('justSolve.py')
	print('Done')
	return True

for _ in range(N):
	t = threading.Thread(target = test)
	t.start()
