import ssl
import socket
import OpenSSL
import datetime

HOST = 'www.github.com'
PORT = 443
cert = None


sock = socket.socket()
sock.settimeout(2)
try:
    sock.connect((HOST,PORT))
    ssl_sock = ssl.wrap_socket(sock)
    cert_der = ssl_sock.getpeercert(True)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
except socket.timeout:
    print('Connection timed out')

if cert != None :
    cert_hash_alg = cert.get_signature_algorithm()
    cert_valid_since = cert.get_notBefore()  #formatted as ASN.1 GENERALIZEDTIME
    cert_valid_to = cert.get_notAfter()
    cert_issuer = cert.get_issuer() #returns X509Name obj
    cert_pkey = cert.get_pubkey()   #return PKey obj
    cert_subject = cert.get_subject() #X509Name obj
    cert_version = cert.get_version()
    cert_serial = cert.get_serial_number()

    list = cert_issuer.get_components()
    print('Wystawiony przez: ')
    print(list)

    print('Wystawiony dla: ')
    list = cert_subject.get_components()
    print(list)

    print('Algorytm hashujacy: ')
    print(cert_hash_alg)

    print('Numer seryjny: ')
    print(cert_serial)

    print('Ważny od: ')
    datetime.datetime.strptime(cert_valid_since.encode('UTF-8'), "%Y%m%d%H%M%S%Z")
    print('Ważny do: ')
    datetime.datetime.strptime(cert_valid_to, "%Y%m%d%H%M%SZ")

