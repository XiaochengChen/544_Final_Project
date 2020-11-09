import socket
import json
import time
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

import Cryptodome
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Hash import SHA1


HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port

def startServer():
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        allMsgsHash = SHA1.new()
        with conn:
            while True:                         
                flag, cipherSuit, tempMsg = recvClientHello(conn)    # 1. Handle Client_Hello
                allMsgsHash.update(tempMsg)                  # Updates hash with each received message
                if flag is None:
                    print("Got error receiving Client hello")
                    break
                allMsgsHash.update(sendServerHello(conn))               # 5. Send Server_Hello
                # time.sleep(2)
                sendCertificate(conn, publickey)    # 6. Send Public key
                # time.sleep(2)
                sendServerDone(conn)                # 7. Send Server_hello_done
                

def recvClientHello(conn):
    data = conn.recv(1024)
    if data is None:
        print("Did not get any data")
        return None, None, None
    cipherSuit = json.loads(data) # Contains a dictionary with the cyphersuit
    return 1, cipherSuit, data

def sendServerHello(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello')
    
def sendServerDone(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello_Done')

#Private key and public key 1024 bits
def rsakeys():
    length=1024
    privatekey = RSA.generate(length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey
 
def sendCertificate(s, publickey):
    certificate = makeCertificate(b'Download Server', publickey)
    print("Size of certificate = " ,len(certificate))
    s.sendall(certificate)
    # json.dumps(certificate)
    return certificate
"""
def sendCertificateDS(s):
    h = SHA1.new()
    h.update(certificate)
    DSThirdPartyHash = h.digest()   #Hash certificate in bytes


    # Generate RSA Keys for third party
    length=1024
    DSThirdPartyPrivateKey = RSA.generate(length, Random.new().read)
    DSThirdPartyPublicKey = DSThirdPartyPrivateKey.publickey()
    DSThirdParty = encrypt(DSThirdPartyPrivateKey, DSThirdPartyHash) # Third Party Digital Signature
    secondHalfCertificate = b'''{"Digital Signature of the third party": "%b",
    "Public Key of the third party":"%b"}''' % (DSThirdParty, DSThirdPartyPublicKey.export_key('PEM'))
    
    finalCertificate = b'''
    {"Certificate": %b, "Information":%b}
    ''' % (firstHalfCertificate, secondHalfCertificate)

    print(json.dumps(finalCertificate)["Certificate"])
    s.sendall(finalCertificate)
    return finalCertificate
"""
def sendPublicKey(s, publickey):
    s.sendall(publickey.export_key('PEM'))

def makeCertificate(name, publickey):
    return b'''{ "Name": "%b", 
    "Serial Number":"12345678", 
    "Expiration Date":"12/12/2020"}''' % name

# Encryption with RSA Public Key from Server to Client
def encrypt(key, plain_text):
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(plain_text)
    # print('     Plain text to encrypt: ', plain_text )
    # print('     Cipher text to send to client: ', cipher_text)
    return cipher_text

print('Server listening on: ', PORT)
startServer()
    