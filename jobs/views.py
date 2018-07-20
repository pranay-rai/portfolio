import time

import nmap as nmap
from django.shortcuts import render

from django.http import HttpResponse

import urllib.request
import ssl, socket

import requests
import datetime
import subprocess
import re
import tld
import nmap
import whois



from jobs.models import URLForm


class Entity():
    def __init__(self, name, status, validity, expiry, expiryDays, protocols, cipherSuites, reputation, TLDs, openPorts, IPaddr, owner, heartbeat):
        self.name = name
        self.status = status
        self.validity = validity
        self.expiry = expiry
        self.expiryDays = expiryDays
        self.protocols = protocols
        self.cipherSuites = cipherSuites
        self.reputation = reputation
        self.TLDs = TLDs
        self.openPorts = openPorts
        self.IPaddr = IPaddr
        self.owner = owner
        self.heartbeat = heartbeat


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

    start = time.time()
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
            if(r.status_code>=400):
                status = 'Timed Out Connection'
        except requests.exceptions.SSLError:
            status = 'Untrusted'
        except requests.exceptions.Timeout:
            status = 'Connection Timed out'
        except requests.ConnectionError:
            status = 'Not Live'
        except Exception as e:
            status = e.args
        return status

    def check_ssl(url):
        validity = ''
        try:
            headers = {
                'User-Agent': 'Mozilla 5.0'
            }
            req = requests.get(url, headers=headers, verify=True)
            validity = 'Valid'
        except requests.exceptions.SSLError:
            validity = 'Untrusted'
        except requests.exceptions.Timeout:
            status = 'Connection Timed out'
        except:
            validity = 'Invalid'
        return validity

    def expiryDate(url):
        date = ''
        try:
            hostname = url.replace("https://", "")
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            date=cert['notAfter']
            date = datetime.datetime.strptime(date,"%b %d %X %Y %Z").strftime("%b %d %Y")
        except socket.timeout:
            date = 'Could not retreive due to timeout error '
        except:
            date = 'Could Not Retrieve'
        return date

    def expiryDays(url):
        days=''
        try:
            hostname = url.replace("https://", "")
            days = (datetime.datetime.strptime(expiryDate(url), "%b %d %Y")-datetime.datetime.now()).days
        except:
            days = "Could not retrieve"
        return days

    def findSupportedProtocols(url):
        protocols = []
        try:
            hostname = url.replace("https://", "")
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

        result = []
        try:
            hostname = url.replace("https://", "")
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

    def checkReputation(url):
        reputation = ''
        try:
            res = tld.get_tld(url, as_object=True)
            hostname = res.domain

            website_list=[]
            with open('C:\\Users\\PRRAI\\PycharmProjects\\portfolio\\jobs\\names.csv', 'r') as f:
                website_list = f.readlines()
            r = re.compile('^.*' + hostname + '.*$')
            newList = list(filter(r.match, website_list))
            if len(newList) !=0:
                reputation = 'Malicious'
            else:
                reputation = 'Safe'
        except:
            reputation = 'Could not fetch'
        return reputation

    def findOtherTLDs(url):
        TLDs = ['ca', 'com', 'uk']
        websites = []
        try:
            res = tld.get_tld(url, as_object=True)
            hostname = res.domain
            for domain in TLDs:
                if domain!=res.tld:
                    try:
                        headers = {
                        'User-Agent': 'Mozilla 5.0'
                         }
                        link = 'http://' + res.domain + '.' + domain
                        r = requests.get(link, headers=headers, allow_redirects=False, timeout = 5)
                        if(r.status_code>=200 or r.status_code<=399):
                            websites.append(link.replace('http://', ''))
                        else:
                            continue
                    except:
                        continue
                else:
                    continue
        except:
            websites = []

        return websites

    def findOpenPorts(url):
        result = []
        try:
            res = tld.get_tld(url, as_object=True)
            domain = res.fld
            try:
                ip_addr = socket.gethostbyname(domain)
                nm = nmap.PortScanner()
                nm.scan(hosts=ip_addr, arguments='-F')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        for port in lport:
                            result.append('Port:<b> ' + str(port) + ' </b> State: <b>' + nm[host][proto][port]['state'] + '</b>' )
            except:
                print()
        except:
            print()

        return result

    def findIPaddr(url):
        result = ''
        try:
            res = tld.get_tld(url, as_object=True)
            domain = res.fld
            result= socket.gethostbyname(domain)
        except:
            result = 'Error retrieving'
        return result

    def findOwner(url):
        result = []
        try:
            res = tld.get_tld(url, as_object=True)
            domain = res.fld
            d= whois.whois(domain)
            if(d.registrant_name):
                result.append(d.registrant_name[1])
                result.append('Registrant name: <b>' + d.registrant_name[1] + '</b>')
                result.append('Webmaster: <b>' + d.registrant_name[2] + '</b>')
            if(d.emails):
                try:
                    if(isinstance(d.emails, list)):
                        result.append('Email: <b>' + ' '.join(str(e) for e in d.emails) + '</b>')
                    else:
                        result.append('Email: <b>' + d.emails + '</b>')
                except:
                    pass
            if(d.phone):
                if (isinstance(d.phone, list)):
                    result.append('Phone:<b> ' + ' '.join(str(e) for e in d.phone) + '</b>')
                else:
                    result.append('Phone:<b> ' + d.phone + '</b>')
            if(d.domain_status):
                result.append('Domain Status:<b> ' + d.domain_status+ '</b>')
            if (d.updated_date):
                result.append('Updated Date:<b>' + str(d.updated_date) + '</b>')
            if(d.creation_date):
                result.append('Creation Date:<b> ' + str(d.creation_date)+ '</b>')

            if(d.expiration_date):
                result.append('Expiration Date:<b> ' + str(d.expiration_date)+ '</b>')
        except:
            result = 'Could not fetch'

        return result

    def findHeartbeatVulnerability(url):

        result = ''
        try:
            hostname = url.replace("https://", "")
            output = subprocess.getoutput('pysslscan scan --scan=vuln.heartbleed --ssl2 --ssl3 --tls10 --tls11 --tls12 ' + hostname)
            presence = ''
            vulnerable = ''
            for i in output.splitlines():
                if i.__contains__('Heartbeat Extension present'):
                    words = i.split()
                    word = words[3]
                    presence = word[word.index('m') + 1:word.rfind('\\') - 3]
                if i.__contains__('Vulnerable'):
                    words = i.split()
                    word = words[1]
                    vulnerable = word[word.index('m') + 1:word.rfind('\\') - 3]

            result = "Heartbeat Extension Present : '" + presence + "' Vulnerable : '" + vulnerable + "'"
        except:
            result = 'Could not fetch'

        return result




    entity = Entity('', '', '', '', '', '', '', '', '', '', '', '', '')

    entity.name = url.replace("https://","")
    entity.status = checkStatus(url)
    entity.validity = check_ssl(url)
    entity.expiry = expiryDate(url)
    entity.expiryDays = expiryDays(url)
    entity.protocols = findSupportedProtocols(url)
    entity.cipherSuites = findSupportedCipherSuites(url)
    entity.reputation = checkReputation(url)
    entity.TLDs = findOtherTLDs(url)
    entity.openPorts = findOpenPorts(url)
    entity.IPaddr = findIPaddr(url)
    entity.owner = findOwner(url)
    entity.heartbeat = findHeartbeatVulnerability(url)

    end = time.time() - start
    end = round(end,1)


    return render(request, 'jobs\\results.html', {'word':url, 'entity':entity, 'time':end})


