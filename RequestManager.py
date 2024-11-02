import requests, json, warnings
warnings.filterwarnings('ignore')

class RequestManager():

	def __init__(self, params, Utils):
		self.params = params
		self.Utils = Utils
		self.params.POST_Payload = True if params.requestData else False
		self.params.POST_Vuln = True if params.requestDataVuln else False	
		self.__initCookies()
		self.params.requestData = self.__initRequestData(self.params.requestData, self.params.urlPayload)
		self.params.requestDataVuln = self.__initRequestData(self.params.requestDataVuln, self.params.urlVuln)
		self.params.urlPayload = self.__initURL(params.requestData, params.urlPayload)
		self.params.urlVuln = self.__initURL(params.requestDataVuln, params.urlVuln)
		self.checkVulnErrors = 0
		self.sendPayloadErrors = 0
		self.findings = []
		self.__initProxy()
		
		
	def __initProxy(self):
		if self.params.proxy:
			self.params.proxy = {"http": self.params.proxy, "https": self.params.proxy}
		else: self.params.proxy = None
		
	def __initURL(self, requestData, url):
		if requestData or '?' not in url:
			return url
		elif '?' in url:
			return url[0:url.index('?')]
		
	def __findPayload(self, response, payload):
		if payload in response: return True
		if payload.replace("/","\/") in response: return True
		if payload.replace("\"","\\\"") in response: return True

	def checkVuln(self):
		response = {}
		try:
			if self.params.POST_Vuln:
				response = requests.post(self.params.urlVuln, data=self.params.requestDataVuln, cookies=self.params.cookies, proxies=self.params.proxy, verify=False)
			elif self.params.requestDataVuln:
				response = requests.get(self.params.urlVuln + '?' + self.__getRequestData(self.params.requestDataVuln), cookies=self.params.cookies, proxies=self.params.proxy, verify=False)
			else:
				response = requests.get(self.params.urlVuln, cookies=self.params.cookies, proxies=self.params.proxy, verify=False)
		except:
			self.checkVulnErrors += 1
		
		if hasattr(response, 'status_code') and response.status_code == 200 and self.__findPayload(response.text, self.params.requestData[self.params.injectParam]):
			self.findings.append({'Payload': self.params.requestData[self.params.injectParam]})
			if self.params.output: self.Utils.saveFindings(self.params)
			
	def sendPayload(self, payload):
		self.params.requestData[self.params.injectParam] = payload
		try:
			if self.params.POST_Payload:
				requests.post(self.params.urlPayload, data=self.params.requestData, cookies=self.params.cookies, proxies=self.params.proxy, verify=False)
			else:
				requests.get(self.params.urlPayload + '?' + self.__getRequestData(self.params.requestData), cookies = self.params.cookies, proxies=self.params.proxy, verify=False)
		except:
			self.sendPayloadErrors += 1
	
	def __getRequestData(self, requestData):
		textData = ''
		for param in requestData:
			textData += param + '=' + data[param] + '&'
		return textData[0:-1]
		
				
	def __initRequestData(self, requestData, url):
		data = {}
		if not requestData and '?' not in url: return {}
		for param in (requestData.split('&') if requestData else url[url.index('?')+1:].split('&')):
			data[param.split('=')[0]] = param.split('=')[1]
		return data
	
	def __initCookies(self):
		cookies = {}
		if self.params.cookies:
			for cookie in self.params.cookies.split('&'):
				cookies[cookie[0:cookie.index('=')]] = cookie[cookie.index('=')+1:]
		self.params.cookies = cookies
	
	def getErrors(self):
		return {"vulnErrors": self.checkVulnErrors, "payloadErrors": self.sendPayloadErrors}
	
	def printFindings(self):
		print('\n\nFindings: ' + str(len(self.findings)) + ' payload\n')
		for index, finding in enumerate(self.findings):
			print(str(index+1) + ') ' + finding['Payload'])
