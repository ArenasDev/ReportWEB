import sys
import os
import datetime
import requests
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw
import urllib3
urllib3.disable_warnings()

class ReportSSL:
	def __init__(self):
		#SET NECESSARY HEADERS HERE LIKE {'phpsessid' : '4yd10sm10qu3c4lv4r10'}
		self.headers = {}
		self.imageFolder  = 'images'
		self.parseArgsAndCheckConnectivity()
		self.generateData()
		self.securityHeaders = {("Cache-control", f"Cache-Control is -msg- (URL {self.url}):") : {"cache-control" : ["no-store", "must-revalidate"], "expires" : ["0", "-1"]}, ("HSTS", f"HSTS is -msg- (URL {self.url}):") : {"strict-transport-security" : ["max-age=31536000"]}, ("XSS Browser Filter", f"XSS protection filter is -msg- (URL {self.url}):") : {"x-xss-protection" : ["1; mode=block"]}, ("nosniff", f"X-Content-Type-Options: no-sniff -msg- (URL {self.url}):" ): {"x-content-type-options" : ["nosniff"]}, ("Clickjacking", f"Clickjacking is not prevented via X-Frame-Options or CSP (URL {self.url}):" ): {"x-frame-options" : ["deny", "sameorigin", "allow-from"], "content-security-policy" : ["child-src"]}}
		self.infoheaders = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "x-powered-by-plesk", "x-powered-cms", "x-server-powered-by" ]
		
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
				self.req = requests.get(self.url, headers = self.headers)
			except requests.exceptions.MissingSchema as e:
				print(' missing schema (http:// or https://)')
				sys.exit()
			except requests.exceptions.ConnectionError as e:
				print(' connection error, check URL and try again')
				sys.exit()
			
			print(" COMPLETED.")
		else:
			self.printHelp()

	def printHelp(self):
		print('Execute:\n\tpython reportSSL.py https://www.google.es/entrypoint\t\t(for silent mode)\n\tpython reportSSL.py --verbose https://www.google.es/entrypoint\t\t(for verbose mode)')
		sys.exit()

	def checkSecurityHeaders(self):
		for h1, v1 in self.securityHeaders.items():
			print(f'Checking {h1[0]} ...', end='', flush=True)
			msg = 'missing'
			check = False

			for h, value in self.req.headers.items():
				if h.lower() in v1.keys():
					msg = 'not configured properly'
					for elem in v1[h.lower()]:
						if elem in value.lower():
							check = True
							break

			if not check:
				print(msg)
				indexes = self.getIndexes(v1.keys())
				self.generateImageAndPrintInfo(h1[1].replace('-msg-', msg), self.data, h1[0], indexes)
			else:
				print(' CORRECT')

	def checkInfoHeaders(self):
		print('Checking information disclosure headers ...', end='', flush=True)
		discardValue = ['', '.']

		for h, value in self.req.headers.items():
			if h.lower() in self.infoHeaders:
				if value not in discardValue:
					indexes = self.getIndexes(h.lower())
					self.generateImageAndPrintInfo(f'Information disclosure in header {h}', self.data, f'Information disclosure in {h}', indexes)
				
		print(' Done')

	def checkCookies(self):
		print('Checking httpOnly and Secure flags in cookies ...', end='', flush=True)

		for c in self.req.cookies:
			if not c.secure:
				indexes = self.getIndexes([c.name], cookies = True)
				self.generateImageAndPrintInfo(f'Cookie {c.name} without secure flag', self.data, f'Secure Flag {c.name}', indexes)
			if not c.has_nonstandard_attr("HttpOnly") and not c.has_nonstandard_attr("httpOnly") and not c.has_nonstandard_attr("Httponly") and not c.has_nonstandard_attr("httponly"):
				indexes = self.getIndexes([c.name], cookies = True)
				self.generateImageAndPrintInfo(f'Cookie {c.name} without httpOnly flag', self.data, f'httpOnly Flag {c.name}', indexes)

		print(' Done')

	def generateData(self):
		self.data = ''
		for h, value in self.req.headers.items():
			aux = '{}: {}'.format(h, value)
			mod = len(aux) % 80
			i = int(len(aux) / 80)
			if i > 0:
				for counter in range(i):
					self.data += '\r\n' + aux[80 * counter:80 * counter + 80]
				if mod > 0:
					self.data += '\r\n' + aux[80 * counter + 80:]
			else:
				self.data += '\r\n' + '{}: {}'.format(h, value)

	def getIndexes(self, headers, cookies = False):
		counter = 0
		indexes = []
		for line in self.data.split('\n'):
			if not cookies and ':' in line:
				if line.lower().split(":")[0] in headers:
					indexes.append(counter + 1)
			elif cookies:
				if headers[0] in line.lower():
					indexes.append(counter + 1)
			counter += 1

		return indexes

	def generateImageAndPrintInfo(self, prev, pt, imageName, indexes):
		data = ''
		self.printt('')
		self.printt(prev)
		data += prev + '\n'
		if len(prev.split('\n')) > 1:
			self.printt('-' * len(prev.split('\n')[-1]))
			data += '-' * len(prev.split('\n')[-1]) + '\n'
		else:
			self.printt('-' * len(prev))
			data += '-' * len(prev) + '\n'

		
		self.printt(pt)
		data += pt
		self.text2png(data, self.imageFolder + '/' + imageName + '(' + self.url.split('://')[1].split('/')[0] + ')_'+datetime.datetime.now().strftime("%d_%m_%Y_%H_%M")+'.png', indexes = indexes)

	def printt(self, text):
		if self.verbose:
			print(text)


	def text2png(self, text, fullpath, color = "#000", bgcolor = "#FFF", fontsize = 30, padding = 10, indexes = []):
		font = ImageFont.truetype("consola.ttf", fontsize)

		width = font.getsize(max(text.split('\n'), key = len))[0] + (padding * 2)
		lineHeight = font.getsize(text)[1]
		imgHeight = lineHeight * (len(text.split('\n')) + 1) + padding
		img = Image.new("RGBA", (width, imgHeight), bgcolor)
		draw = ImageDraw.Draw(img)

		y = padding
		#Draw the text
		for line in text.split('\n'):
			draw.text((padding, y), line, color, font=font)
			y += lineHeight

		#Draw the highlight rectangle, have to use line instead of rectangle because it does not support line THICCness
		for startLine in indexes:
			#Add 1 because otherwise it does not print the rectangle
			endLine = startLine + 1
			#Add 1 to index because of the heading line
			startLine += 1
			endLine += 1
			point1 = (3, (padding / 2) + 3 + lineHeight * startLine)
			point2 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, (padding / 2) + 3 + lineHeight * startLine)
			point3 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, padding + lineHeight * (startLine + (endLine - startLine)))
			point4 = (3, padding + lineHeight * (startLine + (endLine - startLine)))
			draw.line((point1, point2, point3, point4, point1), fill="red", width=5)

		if not os.path.exists(self.imageFolder):
			os.makedirs(self.imageFolder)

		img.save(fullpath, quality=100)

if __name__ == '__main__':
	ReportSSL()
