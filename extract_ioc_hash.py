#!/usr/bin/python3
import requests
import sys
import signal
import re
import json
import urllib3

def def_handler(sig, frame):
    print("\n\nExit...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

regexIP = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

ips_total = []

def validateIP(strIP): 
    if(re.search(regexIP, strIP)):
        ips_total.append(strIP)

def hashes(url):
    i = 0
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    misp_headers = {
        "Authorization": "<paste API>",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    r = requests.get(url, headers=misp_headers, verify=False)

    info = re.findall(r'info.*', r.text)[0].split('"')[2]

    print("\n\ninfo = {}\n\n".format(info))

    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r.text)
    ips_len = len(ips)
    while i < ips_len:
        validateIP(ips[i])
        i = i + 1
    
    md5hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', r.text)
    sha1hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', r.text)
    sha256hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', r.text)

    print("IPS = {}\n".format(json.dumps(ips_total)))
    print("MD5Hash = {}\n".format(json.dumps(md5hash)))
    print("SHA1Hash = {}\n".format(json.dumps(sha1hash)))
    print("SHA256Hash = {}\n".format(json.dumps(sha256hash)))

if  __name__ == "__main__":

    while True:
        url = input("\n[*] Please provide an url MISP : ")
        hashes(url.strip('\n'))
