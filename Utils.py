import argparse,re,os,sys

class Utils:

	def __init__(self):
		self.args = {}
		self.__initParams()
		if not self.args.quite: self.__printLogo()

	def __printLogo(self):
		print('   __     ______     ______   __  __     ______     ______    ')
		print('  /\ \   /\  __ \   /\  == \ /\_\_\_\   /\  ___\   /\  ___\   ')
		print(' _\_\ \  \ \  __ \  \ \  _-/ \/_/\_\/_  \ \___  \  \ \___  \  ')
		print('/\_____\  \ \_\ \_\  \ \_\     /\_\/\_\  \/\_____\  \/\_____\ ')
		print('\/_____/   \/_/\/_/   \/_/     \/_/\/_/   \/_____/   \/_____/ ')

	def __initParams(self):
		parser = argparse.ArgumentParser(description='Sometimes it is necessary to check if the payload works in another page. JAPXSS comes in handy and automates this process.', usage='python3 japxss.py -u "https://<YOUR_TARGET>/page1" -v "https://<YOUR_TARGET>/page2" -d "name=kevin&surname=lin&sesskey=U8AbkMluUu" -j name -w wordlist.txt --cookie "sessiontoken=75e6d7f6boa5838aee254d2b69369999"')
		parser.add_argument('--urlPayload', '-u', help='The base URL to send the payload', type=str, required=True)
		parser.add_argument('--urlVuln', '-v', help='The URL used to check for the presence of the payload', type=str, required=True)
		parser.add_argument('--requestData', '-d', help='Data used in the request', type=str)
		parser.add_argument('--requestDataVuln', help='Data used in the request to check for vulnerability', type=str)
		parser.add_argument('--injectParam', '-j', help='The variable from requestData used to inject the payload into', type=str, required=True)
		parser.add_argument('--wordlist', '-w', help='The path to the wordlist to use', type=str, required=True)
		parser.add_argument('--cookies', '-c', help='Cookies to use in the request', type=str)
		parser.add_argument('--thread', '-t', help='Number of threads to use for scanning.', type=int)
		parser.add_argument('--sleep', '-s', default=1, help='Waiting time from "sending payload request" and "check for vulnerability". Default 1 second', type=int)
		parser.add_argument('--output', help='Save data to output file', type=str)
		parser.add_argument('--proxy', help='Proxy address/url to use', type=str)
		parser.add_argument('--quite', '-q', help='Dont print the logo', action="store_true")
		self.args = parser.parse_args()
		return self.args
		
	def getParams(self):
		return self.args

	def checkParams(self):
		urlRegex = "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"
		check = 'Error: '
		if not re.match(urlRegex, self.args.urlPayload): 
			check += 'There is an error with the urlPayload'
		if not re.match(urlRegex, self.args.urlVuln):
			check += 'There is an error with the urlVuln'
		if self.args.injectParam not in self.args.requestData: 
			check += 'injectParam was not found in the requestData'
		if not self.__checkPathExist(self.args.wordlist):
			check += 'The wordlist does not exist on the system'
		if self.args.thread and self.args.thread > 5:
			check += 'Thread count too high. Max thread 5'
		if self.args.proxy and not re.match(urlRegex, self.args.proxy): 
			check += 'There is an error with the proxy address/url'
			
		if len(check) > 7: print(check)
		return False if len(check) > 7 else True
		
	def readWordlist(self):
		wordlistFile = open(self.args.wordlist, "r")
		wordlist = wordlistFile.readlines()
		return wordlist
		
	def __checkPathExist(self, path):
		return os.path.isfile(path)
		
	def saveFindings(self, params):
		saveFile = open(params.output, "a")
		saveFile.write('\nurlPayload: ' + params.urlPayload + ' -- urlVuln: ' + params.urlVuln + ' -- Payload found: ' + params.requestData[params.injectParam])
		saveFile.close()
	
	def initProgressBar(self, length, suffix, fill):
		print('\n')
		self.progressBar = {'length': length, 'suffix': suffix, 'fill': fill, 'index': 0}
	
	def updateProgressBar(self, suffix):
		self.progressBar['index'] += 1
		barLength = 100
		filledUpLength = int(round(barLength * self.progressBar['index'] / float(self.progressBar['length'])))
		percentage = round(100.0 * self.progressBar['index'] / float(self.progressBar['length']),1)
		bar = self.progressBar['fill'] * filledUpLength + '-' * (barLength - filledUpLength)
		sys.stdout.write('[%s] %s%s ...%s\r' %(bar, percentage, '%', suffix))
		sys.stdout.flush()
