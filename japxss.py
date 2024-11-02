# Author: z3nz3r0
#!/usr/bin/python3

from Utils import Utils
from RequestManager import RequestManager
import time, threading
import numpy as np

def requestBlock(rm, payloads, params, u):
	u.initProgressBar(len(payloads), '', '#')
	for payload in payloads:
		rm.sendPayload(payload)
		time.sleep(params.sleep)
		rm.checkVuln()
		u.updateProgressBar(str(rm.getErrors()))
		
def main():
	u = Utils()
	params = u.getParams()
	if u.checkParams():
		rm = RequestManager(params, u)
		wordlist = u.readWordlist()
		payloads = []
		for payload in wordlist: payloads.append(payload.lstrip().rstrip())
		
		payloads = np.array_split(np.array(payloads), params.thread) if params.thread else [payloads]
		
		blocks = []
		for payloadGroup in payloads:
			t = threading.Thread(target=requestBlock, args=(rm, payloadGroup, params, u,))
			blocks.append(t)
			t.start()
			
		for block in blocks: block.join()
		
		rm.printFindings()
				
if __name__ == '__main__':
    main()
