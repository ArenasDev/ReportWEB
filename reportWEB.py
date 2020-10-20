import sys
import os
import datetime
import httpx
import httpcore
import requests
import random
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw
import urllib3
urllib3.disable_warnings()

class ReportSSL:
	def __init__(self):
		#SET NECESSARY HEADERS HERE LIKE {'X-Forwarded-For' : '127.0.0.1'}
		self.headers = {}
		#SET NECESSARY COOKIES HERE LIKE {'phpsessid' : '4yd10sm10qu3c4lv4r10'}
		self.cookies = {}
		#SET NECESSARY PROXIES HERE LIKE {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
		self.proxies = {}
		#SET WIDTH OF IMAGE HERE
		self.imageWidth = 60
		#SET NAME OF FOLDER IN WHICH IMAGES ARE SAVED HERE
		self.imageFolder  = 'images'
		userAgents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36','Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36','Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36','Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0','Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:78.0) Gecko/20100101 Firefox/78.0']
		self.headers.update({'User-Agent' : random.choice(userAgents)})
		self.data = ''
		self.parseArgsAndCheckConnectivity()
		self.data = self.generateData(False)
		self.securityHeaders = {("Cache-control", f"Cache-Control is -msg- (URL {self.url}):") : {"cache-control" : ["no-store", "must-revalidate"], "expires" : ["0", "-1"]}, ("HSTS", f"HSTS is -msg- (URL {self.url}):") : {"strict-transport-security" : ["max-age=31536000"]}, ("XSS Browser Filter", f"XSS protection filter is -msg- (URL {self.url}):") : {"x-xss-protection" : ["1; mode=block"]}, ("nosniff", f"X-Content-Type-Options: no-sniff -msg- (URL {self.url}):"): {"x-content-type-options" : ["nosniff"]}, ("Clickjacking", f"Clickjacking is not prevented via X-Frame-Options or CSP (URL {self.url}):"): {"x-frame-options" : ["deny", "sameorigin", "allow-from"], "content-security-policy" : ["child-src"]}}
		self.infoHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "x-powered-by-plesk", "x-powered-cms", "x-server-powered-by", "x-owa-version", "MicrosoftSharePointTeamServices", "x-cocoon-version"]
		
		self.checkDoubleHeadersAndCookies()
		self.checkSecurityHeaders()
		self.checkInfoHeaders()
		self.checkCookies()

	def parseArgsAndCheckConnectivity(self):
		if len(sys.argv) == 2 or len(sys.argv) == 3:
			if len(sys.argv) == 3:
				if sys.argv[1] == '--verbose':
					self.verbose = True
					self.url = sys.argv[2]
				else:
					self.printHelp()
			else:
				self.verbose = False
				self.url = sys.argv[1]
			try:
				print('Testing connectivity ...', end='', flush=True)
				with httpx.Client(proxies=self.proxies, verify=False, headers = self.headers, cookies = self.cookies, timeout=10.0) as client:
					self.req = client.get(self.url, allow_redirects=False)
					self.fixHeadersCapitalization()
					request = self.generateData(True)
					self.generateImageAndPrintInfo(f'RAW original request', request, f'ORIGINAL REQUEST')
				# self.req = httpx.get(self.url, verify=False, allow_redirects=False, headers = self.headers, cookies = self.cookies)
			except httpx._exceptions.InvalidURL as e:
				print(' missing schema (http:// or https://)')
				sys.exit()
			except httpcore._exceptions.ConnectError as e:
				print(e)
				print(' connection error, check URL and try again')
				sys.exit()
			
			print(" COMPLETED.")
		else:
			self.printHelp()

	def fixHeadersCapitalization(self):
		#This is a temporary fix (not perfect) while an official fix is launched
		newKeys = {}
		for key, item in self.req.headers.items():
			newKeys.update({'-'.join(c.capitalize() for c in key.split('-')) : item})
		self.req.headers = newKeys

		newKeys = {}
		for key, item in self.req.request.headers.items():
			newKeys.update({'-'.join(c.capitalize() for c in key.split('-')) : item})
		self.req.request.headers = newKeys

	def printHelp(self):
		print('Execute:\n\tpython reportSSL.py https://www.google.es/entrypoint\t\t(for silent mode)\n\tpython reportSSL.py --verbose https://www.google.es/entrypoint\t\t(for verbose mode)')
		sys.exit()

	def checkDoubleHeadersAndCookies(self):
		print(f'Checking duplicated headers and cookies ...', end='', flush=True)
		#Remove exact duplicates (header name and value)
		self.req.headers = httpx._models.Headers(list(set([i for i in self.req.headers.items()])))

		headers = {}
		for h, value in self.req.headers.items():
			if h.lower() != 'set-cookie':
				if h.lower() in headers.keys():
					#Exact duplicates are already out, so this has to be different value and has to be reported
					indexes = self.getIndexes([(h, value), (h, headers[h])])
					self.generateImageAndPrintInfo(f'Duplicate header {h} in response with different values', self.data, f'Duplicate header {h}', indexes)
				else:
					headers.update({h.lower() : value})

		cookies = {}
		for h, v in self.req.headers.items():
			if 'set-cookie' in h.lower():
				name = v.split("=")[0]
				value = v.split("=")[1:]
				if name in cookies.keys():
					if cookies[name][0] != value:
						indexes = self.getIndexes([(h, v), (h, cookies[name][1])])
						self.generateImageAndPrintInfo(f'Duplicate cookie {name} in response with different values', self.data, f'Duplicate cookie {name}', indexes)
				else:
					cookies.update({name : [value, v]})

		print(' DONE')

	def checkSecurityHeaders(self):
		headers = []
		for h1, v1 in self.securityHeaders.items():
			passed = False
			print(f'Checking {h1[0]} ...', end='', flush=True)
			msg = 'missing'

			for h, value in self.req.headers.items():
				if h.lower() in v1.keys():
					msg = 'not configured properly'
					check = False
					for elem in v1[h.lower()]:
						if elem in value.lower():
							check = True
							passed = True
							break

					if not check:
						headers.append((h.lower(), value))
					else:
						#If at least one of the values is correct, this header is correct
						headers = []
			
			#None of the values were found in the header, thus incorrect and reported
			#Dont report if one of the checks of this issue have passed (like clickjacking solved by x-frame-options and not in CSP)
			if not passed:
				indexes = self.getIndexes(headers)
				self.generateImageAndPrintInfo(h1[1].replace('-msg-', msg), self.data, h1[0], indexes)
				headers = []
				print(msg)
			else:
				print(' CORRECT')

	def checkInfoHeaders(self):
		print('Checking information disclosure headers ...', end='', flush=True)
		discardValue = ['', '.']

		for h, value in self.req.headers.items():
			if h.lower() in self.infoHeaders:
				if value not in discardValue:
					indexes = self.getIndexes([(h.lower(), value)])
					self.generateImageAndPrintInfo(f'Information disclosure in header {h}', self.data, f'Information disclosure in {h}', indexes)
				
		print(' Done')

	def checkCookies(self):
		print('Checking httpOnly and Secure flags in cookies ...', end='', flush=True)

		for h, value in self.req.headers.items():
			if 'set-cookie' in h.lower():
				if '; secure' not in value.lower():
					indexes = self.getIndexes([(h, value)])
					self.generateImageAndPrintInfo(f'Cookie {value.split("=")[0]} without secure flag', self.data, f'Secure Flag {value.split("=")[0]}', indexes)
				if '; httponly' not in value.lower():
					indexes = self.getIndexes([(h, value)])
					self.generateImageAndPrintInfo(f'Cookie {value.split("=")[0]} without httpOnly flag', self.data, f'httpOnly Flag {value.split("=")[0]}', indexes)

		print(' Done')

	def generateData(self, request):
		output = ''
		if request:
			path = str(self.req.request.url)[len(self.url):]
			if path == '':
				path = '/'
			output = f'\r\n{self.req.request.method} {path} HTTP/1.1\r\n'
			headers = self.req.request.headers.items()
		else:
			output = f'\r\n{self.req.http_version} {self.req.status_code} {self.req.reason_phrase}\r\n'
			headers = self.req.headers.items()

		for h, value in headers:
			aux = '{}: {}'.format(h, value)
			#The last '' is not empty, it has a zero width space used to mark lines not cropped or first lines of cropped lines
			position = 0
			output += aux[position:position + self.imageWidth] + '​' + '\r\n'
			position += self.imageWidth
			while position < len(aux):
				output += aux[position:position + self.imageWidth] + '\r\n'
				position += self.imageWidth

		return output[:-2]

	def getIndexes(self, elements):
		indexes = []
		for h,v in elements:
			counter = 0
			cropped = -1
			for line in self.data.split('\r\n'):
				#This '' is not empty, it has a zero-width space to check if line is first line or not cropped, meaning that the current range must end
				if cropped > 0 and line[-1] == '​':
					#If marked line is cropped, check next line until it is not cropped
					indexes.append((cropped, counter))
					cropped = -1

				aux = h + ': ' + v
				vAux = aux.lower()[0:self.imageWidth] if len(aux) >= self.imageWidth else aux.lower()
				if vAux in line.lower():
					cropped = counter + 1
				counter += 1

			if cropped > 0:
				indexes.append((cropped, counter))

		return indexes

	def generateImageAndPrintInfo(self, prev, pt, imageName, indexes = None):
		data = ''
		self.printt('')
		self.printt(prev)
		data += prev + '\r\n'
		if len(prev.split('\r\n')) > 1:
			self.printt('-' * len(prev.split('\r\n')[-1]))
			data += '-' * len(prev.split('\r\n')[-1]) + '\r\n'
		else:
			self.printt('-' * len(prev))
			data += '-' * len(prev) + '\r\n'
		
		self.printt(pt)
		data += pt
		self.text2png(data, self.imageFolder + '/' + imageName + '(' + self.url.split('://')[1].split('/')[0] + ')_'+datetime.datetime.now().strftime("%d_%m_%Y_%H_%M")+'.png', indexes = indexes)

	def printt(self, text):
		if self.verbose:
			print(text)

	def text2png(self, text, fullpath, color = "#000000", bgcolor = "#FFF", fontsize = 15, padding = 10, indexes = None):
		font = ImageFont.truetype("cour.ttf", fontsize)

		width = font.getsize(max(text.split('\r\n'), key = len))[0] + (padding * 2)
		# * 0.15 is the space between lines
		lineHeight = font.getsize(text)[1] + int(font.getsize(text)[1] * 0.15)
		imgHeight = lineHeight * (len(text.split('\r\n')) + 1) + padding
		img = Image.new("RGBA", (width, imgHeight), bgcolor)
		draw = ImageDraw.Draw(img)

		y = padding
		headerColor = "#000075"
		cookieNameColor = "#0000C0"
		cookieValueColor = "#A01010"

		#New code to print HTTP responses with a Burp Style syntax highlight
		index = 0
		step = 0
		extraPadding = 0
		cookie = False
		line = text.split('\r\n')[index]
		#print first 4 lines (Explanation, separator line, empty and http status code) all in black
		for line in text.split('\r\n')[:4]:
			draw.text((padding, y), line, color, font=font)
			index += 1
			y += lineHeight

		while index < len(text.split('\r\n')):
			line = text.split('\r\n')[index].replace('​', '')
			#Step 0: Print header name in blue
			if step == 0:
				cookie = line.lower().startswith('set-cookie') or line.lower().startswith('cookie')
				if ':' in line:
					#Delimiter of this step is in this line
					draw.text((padding + extraPadding, y), line.split(':')[0], headerColor, font=font)
					extraPadding += font.getsize(line.split(':')[0])[0]
					#Get new line
					step = 1
					line = ': ' + ':'.join(line.split(':')[1:])
				else:
					#Rest of line is in this step, but continues in the next line
					draw.text((padding + extraPadding, y), line, headerColor, font=font)
					extraPadding += font.getsize(line)[0]
					index += 1
					extraPadding = 0
					y += lineHeight
					# line = text.split('\r\n')[index]

			#Print in black the separator of header name and value
			if step == 1:
				#No need to check if delimiter is in line because it has been checked before
				draw.text((padding + extraPadding, y), ': ', color, font=font)
				extraPadding += font.getsize(': ')[0]
				step = 2
				line = line[2:]
				#Line is completed, get new line
				if line == '':
					index += 1
					extraPadding = 0
					y += lineHeight
					# line = text.split('\r\n')[index]

			#If current header is set-cookie, then print the cookie name in blue
			#Else, print line in black
			if step == 2:
				if cookie:
					if '=' in line:
						#Delimiter of this step is in this line
						draw.text((padding + extraPadding, y), line.split('=')[0], cookieNameColor, font=font)
						extraPadding += font.getsize(line.split('=')[0])[0]
						step = 3
						line = '=' + '='.join(line.split('=')[1:])
					else:
						#Rest of line is in this step, but continues in the next line
						draw.text((padding + extraPadding, y), line, cookieNameColor, font=font)
						extraPadding += font.getsize(line)[0]
						index += 1
						extraPadding = 0
						y += lineHeight
						# line = text.split('\r\n')[index]
				else:
					#Regular header, print in black and check if this is the last line of this header
					draw.text((padding + extraPadding, y), line, color, font=font)
					extraPadding += font.getsize(line)[0]
					#Check if this line is the last of this header
					index += 1
					extraPadding = 0
					y += lineHeight
					if index < len(text.split('\r\n')) and (text.split('\r\n')[index] == '' or text.split('\r\n')[index][-1] == '​'):
						step = 0
						cookie = False

			#Print separator of cookie name and cookie value in black
			if step == 3 and cookie:
				#No need to check if delimiter is in line because it has been checked before
				draw.text((padding + extraPadding, y), '=', color, font=font)
				extraPadding += font.getsize('=')[0]
				step = 4
				line = line[1:]
				#Line is completed, get new line
				if line == '':
					index += 1
					extraPadding = 0
					y += lineHeight

			#Print cookie value in red
			if step == 4 and cookie:
				if ';' in line:
					#Delimiter of this step is in this line
					draw.text((padding + extraPadding, y), line.split(';')[0], cookieValueColor, font=font)
					extraPadding += font.getsize(line.split(';')[0])[0]
					step = 5
					line = ';' + ';'.join(line.split(';')[1:])
				else:
					#Rest of line is in this step, but continues in the next line
					draw.text((padding + extraPadding, y), line, cookieValueColor, font=font)
					extraPadding += font.getsize(line)[0]
					index += 1
					extraPadding = 0
					y += lineHeight
					# line = text.split('\r\n')[index]

			#print rest of line in black
			if step == 5 and cookie:
				#Regular header, print in black and check if this is the last line of this header
				draw.text((padding + extraPadding, y), line, color, font=font)
				extraPadding += font.getsize(line)[0]
				#Check if this line is the last of this header
				index += 1
				extraPadding = 0
				y += lineHeight
				if index < len(text.split('\r\n')) and text.split('\r\n')[index][-1] == '​':
					step = 0
					cookie = False

		#Draw the highlight rectangle, have to use line instead of rectangle because it does not support line THICCness
		if indexes != None:
			for startLine, endLine in indexes:
				#Add 1 to index because of the heading line
				startLine += 1
				endLine += 2
				point1 = (3, (padding / 2) + 3 + lineHeight * startLine)
				point2 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, (padding / 2) + 3 + lineHeight * startLine)
				point3 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, padding + lineHeight * (startLine + (endLine - startLine)))
				point4 = (3, padding + lineHeight * (startLine + (endLine - startLine)))
				draw.line((point1, point2, point3, point4, point1), fill="red", width=2)

		if not os.path.exists(self.imageFolder):
			os.makedirs(self.imageFolder)

		#Resize to 30% and use antialiasing
		# w, h = img.size
		# img = img.resize((int(w/3), int(h/3)), Image.ANTIALIAS)

		img.save(fullpath, quality=100)

if __name__ == '__main__':
	ReportSSL()
