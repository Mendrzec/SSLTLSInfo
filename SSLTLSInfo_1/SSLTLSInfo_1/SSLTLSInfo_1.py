import ssl
import socket
import OpenSSL
import datetime
import os
import pyping
import sys
import json
import time

websites_file = open("websites_short.txt", "r")
websites_list = websites_file.readlines()
websites_file.close()

json_raport = {}
json_raport["CERTS"] = []

for website in websites_list:
#if 1:

    #HOST = 'github.com'
    HOST = website.translate(None, ' \n\t\r')
    PORT = 443
    cert = None
    cert_json_obj = {}
    print('Pinging ' + HOST + '...')
    response = os.system("ping -n 1 -w 1000 " + HOST)
    if response == 0:  
        #TRY TO GET SSL BANNER

        sock = socket.socket()
        sock.settimeout(2)
        try:
            sock.connect((HOST,PORT))
            ssl_sock = ssl.wrap_socket(sock)
            cert_der = ssl_sock.getpeercert(True)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
        except socket.timeout:
            print('Connection to ' + HOST + ':' + str(PORT) + 'timed out.')
        except socket.error:
            print('Connection to ' + HOST + ':' + str(PORT) + ' impossible.')

        if cert != None :
            
            cert_json_obj["!Host"] = HOST
            cert_json_obj["Subject"] = dict(cert.get_subject().get_components())
            cert_json_obj["Issuer"] = dict(cert.get_issuer().get_components())
            cert_json_obj["HashAlgorithm"] = cert.get_signature_algorithm()
            cert_json_obj["ValidSince"] = time.strftime('%d-%m-%Y', time.strptime(cert.get_notBefore(), '%Y%m%d%H%M%SZ'))
            cert_json_obj["ValidTo"] = time.strftime('%d-%m-%Y', time.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ'))
            cert_json_obj["Version"] = cert.get_version()
            cert_json_obj["Serial"] = cert.get_serial_number()
            cert_json_obj["PKeyBits"] = cert.get_pubkey().bits()

            json_raport["CERTS"].append(cert_json_obj)

    else:
        continue

    #print json.dumps(json_raport, sort_keys=True, indent = 2)

raport_file = open('raport.json', 'w')
raport_file.write(json.dumps(json_raport, sort_keys=True, indent = 2))
raport_file.close()
