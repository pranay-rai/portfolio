from django.shortcuts import render

from django.http import HttpResponse

import urllib.request
import ssl, socket

import requests
import datetime
import subprocess


from jobs.models import URLForm


class Entity():
    def __init__(self, name, status, validity, expiry, expiryDays, protocols, cipherSuites):
        self.name = name
        self.status = status
        self.validity = validity
        self.expiry = expiry
        self.expiryDays = expiryDays
        self.protocols = protocols
        self.cipherSuites = cipherSuites


def home(request):
    form = URLForm()
    return render(request, 'jobs\home.html', {'form':form})

def results(request):

    if request.method == "POST":
        dataForm = URLForm(request.POST)

        if dataForm.is_valid():
            url = dataForm.cleaned_data['url']
        else:
            dataForm = URLForm()


    def checkStatus(url):
        status=''
        try:
            headers = {
                'User-Agent': 'Mozilla 5.0'
            }
            r = requests.get(url, headers=headers, allow_redirects=False)
            if(r.status_code==200):
                status = 'Live'
            if(r.status_code==301 or r.status_code==302):
                status = 'Redirected to <a href="' + r.headers['Location'] + "\">" + r.headers['Location'] + "</a>"
        except requests.exceptions.SSLError:
            status = 'Self-Signed Certificate'
        except requests.ConnectionError:
            status = 'Not Live'
        return status

    def check_ssl(url):
        validity = ''
        try:
            headers = {
                'User-Agent': 'Mozilla 5.0'
            }
            req = requests.get(url, headers=headers, verify=True, stream=False)
            validity = 'valid'
        except requests.exceptions.SSLError:
            validity = 'Self-Signed'
        except:
            validity = 'Invalid'
        return validity

    def expiryDate(url):
        date = ''
        hostname = url.replace("https://","")
        try:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            date=cert['notAfter']
            date = datetime.datetime.strptime(date,"%b %d %X %Y %Z").strftime("%b %d %Y")
        except:
            date = 'Could Not Retrieve'
        return date

    def expiryDays(url):
        days=''
        hostname = url.replace("https://", "")
        try:
            days = (datetime.datetime.strptime(expiryDate(url), "%b %d %Y")-datetime.datetime.now()).days
        except:
            days = "Could not retrieve"
        return days

    def findSupportedProtocols(url):
        protocols = []
        hostname = url.replace("https://", "")
        try:
            output = subprocess.getoutput('pysslscan scan --scan=server.preferred_ciphers --ssl2 --ssl3 --tls10 --tls11 --tls12 ' + hostname)
            for i in output.splitlines():
                if i.__contains__('SSLv3'):
                    if i.__contains__("Protocol"):
                        continue
                    else:
                        protocols.append('SSL3 ')
                if i.__contains__('TLSv10'):
                    if i.__contains__("Protocol"):
                        continue
                    else:
                        protocols.append('TLS1.0 ')
                if i.__contains__('TLSv11'):
                    if i.__contains__("Protocol"):
                        continue
                    else:
                        protocols.append('TLS1.1 ')
                if i.__contains__('TLSv12'):
                    if i.__contains__("Protocol"):
                        continue
                    else:
                        protocols.append('TLS1.2 ')
        except:
            protocols = 'Could Not Fetch'

        return ''.join(protocols)

    def findSupportedCipherSuites(url):
        hostname = url.replace("https://", "")
        result = []
        try:
            output = subprocess.getoutput('pysslscan scan --scan=server.ciphers --ssl2 --ssl3 --tls10 --tls11 --tls12 ' + hostname)
            for i in output.splitlines():
                if i.__contains__('Accepted'):
                    words = i.split()
                    word1 = words[1]
                    word2 = words[4]
                    word3 = words[6]
                    result.append(word1[word1.index('m')+1:word1.index('m')+7] + " -- " + word2 + " -- " +  word3[4:word3.rfind('\\')-3])
        except:
            result = 'Could not fetch'

        return result

    entity = Entity('', '', '', '', '', '', '')

    entity.name = url.replace("https://","")
    entity.status = checkStatus(url)
    entity.validity = check_ssl(url)
    entity.expiry = expiryDate(url)
    entity.expiryDays = expiryDays(url)
    entity.protocols = findSupportedProtocols(url)
    entity.cipherSuites = findSupportedCipherSuites(url)



    return render(request, 'jobs\\results.html', {'word':url, 'entity':entity})


