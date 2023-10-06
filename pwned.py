#! /home/dk/dev/pwned/bin/python3
import os, sys, requests, csv, time, re

api = open("apikey.txt").read().strip()

#set to false if using TXT file as uswername list
CSVinput = False

#set to false to remove breach blurb from report
briefReport = True

rawTxtOutput = False
CSVOutput = False
client = 'CLIENT NAME'

compiledData = {}
breachID = {}


def getUsernamesCSV():
	"""Transforms CSV from QRadar to list of usernames.	"""

	print('Reading list of usernames from users.CSV')
	os.system("chmod 400 users.csv")
	SourceCSV = open('users.csv')
	tempUsers = list(csv.reader(SourceCSV))
	SourceCSV.close()

	tempUsers = tempUsers[1::]
	users = []
	for user in tempUsers:
			users.append(user[0].upper())
	return users


def getUsernamesTXT():
	"""Transforms TXT file of usernames (1 username per line) to a list of usernames."""

	print('Reading list of usernames from users.TXT')
	SourceTXT = open('users.txt', 'r').read()
	users = SourceTXT.split("\n")

	return users



def check(username):
	"""Runs username against HIBP API, returns object {"username" : ["breachdata"]}"""

	header = {"hibp-api-key": api}
	
	print("Checking - {}".format(username))
	#rate limiting
	time.sleep(6)

	req = "https://haveibeenpwned.com/api/v3/breachedaccount/" + username
	data = requests.get(req, headers= header)

	if data.text == "":
		breachdata = 'None found'
	else:
		breachdata = data.text
	
	compiledData[username] = breachdata


def constructHTML(compiledData):
	"""Build HTML document"""

	fonts = "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin><link href='https://fonts.googleapis.com/css2?family=Cairo:wght@300&display=swap' rel='stylesheet'>"

	htmlTemplate = "<!doctype html>\n<html>\n<head>\n<title>Data Breach Report</title>\n<link rel='stylesheet' href='styles.css' type='text/css'/>\n <link rel='shortcut icon' type='image/x-icon' href='/images/favicon.png'/>\n{}\n</head>\n<body>\n".format(fonts)
	
	def buildHeader(client):
		header = '<header>\n<h1>Data Breach Report</h1>\n</header>'
		return header

	def buildTable(compiledData):

		mainTable = '<section class="tableSection"><table><tr><th>Email address</th><th>Breaches</th></tr>\n'

		for key, value in compiledData.items():
			breaches = re.findall("\"Name\":\"([^\"]+)", value)
			pwned = 'pwned'

			if breaches == []:
				breaches = ['None Found']
				pwned = 'notPwned'

			mainTable += str('<tr class="{}"><td><h4>{}</h4></td><td>'.format(pwned, key))

			for breach in breaches:

				mainTable += str(' {}, '.format(breach))

				#maintain dict to identify involved breaches and count of pwned for informative section in breachData()
				if breach == 'None Found':
					continue

				if (breach not in breachID):
					breachID[breach] = 1
				else:
					breachID[breach] += 1


			mainTable = mainTable[:-2] + '</td></tr>\n'
				
		mainTable += '</section></table>'

		return mainTable
	
	def bulidBreachData():

		breachData = '<section class="breachdata">\n'


		for i, j in enumerate(breachID):
			request = 'https://haveibeenpwned.com/api/v3/breach/{}'.format(j)

			JSON = requests.get(request).json()

			dataClasses = ', '.join(JSON["DataClasses"])

			impacted = breachID[j]

			if i % 2 == 0:
				bgColour = 'light'
			else:
				bgColour = 'dark'

			if briefReport:
				breachDescription = f'\n<blockquote>{JSON["Description"]}</blockquote>'
			else:
				breachDescription = ''

			breachData += '<section class="breachEntry {}"><img src="{}">\n<h1>{}</h1><h2 class="impacted">Impacted accounts: <span class="count"><strong>{} of {} assessed</strong></span></h2>\n<h2><strong><div class="changecol">Breach Date : </div>{}<br><div class="changecol">Data classes impacted : </div></strong>{}</h2>{}</section>'.format(bgColour, JSON["LogoPath"],  JSON["Title"], impacted, userCount, JSON["BreachDate"], dataClasses, breachDescription)

		breachData += '</section>'

		return breachData

	htmlout = htmlTemplate + buildHeader(client) + buildTable(compiledData) + bulidBreachData()

	return htmlout


#compile list of usernames into a list
if CSVinput:
	users = getUsernamesCSV()
else:
	users = getUsernamesTXT()


userCount = len(users)

for user in users:

	if user == 'N/A':
		continue
	
	check(user)


htmlout = constructHTML(compiledData)

text_file = open("index.html", "w")

htmlout += '<br><img src="images/footerlogo.png" class="footerlogo"></body>'

text_file.write(htmlout)
text_file.close()

