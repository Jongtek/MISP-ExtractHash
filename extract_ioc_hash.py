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

def hashes(url):
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    misp_headers = {
        "Authorization": "<paste API>",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    r = requests.get(url, headers=misp_headers, verify=False)

    info = re.findall(r'info.*', r.text)[0].split('"')[2]

    print("\n\ninfo = {}\n\n".format(info))

    md5hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', r.text)
    sha1hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', r.text)
    sha256hash = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', r.text)

    print("MD5Hash = {}\n".format(json.dumps(md5hash)))
    print("SHA1Hash = {}\n".format(json.dumps(sha1hash)))
    print("SHA256Hash = {}\n".format(json.dumps(sha256hash)))

if  __name__ == "__main__":

    while True:
        url = input("\n[*] Please provide an url MISP : ")
        hashes(url.strip('\n'))
