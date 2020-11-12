import socket
import json
import os
import time
import hashlib

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
            flag, cipherSuit, tempMsg = recvClientHello(conn)   # 1. Handle Client_Hello
            allMsgsHash.update(tempMsg)                         # Updates hash with each received message
            if flag is None:
                print("Got error receiving Client hello")
                return
            allMsgsHash.update(sendServerHello(conn))           # 3. Send Server_Hello
            allMsgsHash.update(sendCertificate(conn))           # 5. Send Certificate and Public key
            sendPublicKey(conn, publickey)
            allMsgsHash.update(encrypt(conn, publickey, b'here is software'))   # 8. Send encypted message to client
            allMsgsHash.update(sendServerDone(conn))                            # 10. Send Server_hello_done

# 1. Handle Client_Hello
def recvClientHello(conn):
    data = conn.recv(1024)
    if data is None:
        print("Did not get any data")
        return None, None, None
    cipherSuit = json.loads(data) # Contains a dictionary with the cyphersuit
    return 1, cipherSuit, data

# 3. Send Server_Hello
def sendServerHello(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello')
    return b'Server_Hello'

 # 5. Send Certificate and Public key
def sendCertificate(s):
    certificate = makeCertificate(b'Download Server')
    print("Server received: Size of certificate = " ,len(certificate))
    s.sendall(certificate)
    # json.dumps(certificate)
    return certificate

def makeCertificate(name):
    return b'''{ "Name": "%b",
    "Serial Number":"12345678",
    "Expiration Date":"12/12/2020"}''' % name

def sendPublicKey(s, publickey):
    #s.send(publickey.exportKey(format='PEM', passphrase=None, pkcs=1))
    s.sendall(publickey.export_key('PEM'))
    return publickey

#Private key and public key 1024 bits
def rsakeys():
     length=1024
     privatekey = RSA.generate(length, Random.new().read)
     publickey = privatekey.publickey()

     # Save private key as a file to be used for decryption
     f = open('keyfile.pem', 'wb')
     f.write(privatekey.exportKey('PEM'))
     f.close()

     return privatekey, publickey


# 8. Send encypted message to client
# Encryption with RSA Public Key
def encrypt(s, publickey, plain_text):
    cipher = PKCS1_OAEP.new(publickey)
    cipher_text = cipher.encrypt(plain_text)
    print('     Plain text to encrypt: ', plain_text )
    print('     Cipher text to send to client: ', cipher_text)
    s.sendall(cipher_text)
    return cipher_text

# Assume server's private key is a saved file
def decryption(cipher_text):
    key = RSA.importKey(open('keyfile.pem').read())
    cipher = PKCS1_OAEP.new(key)
    plain_text = cipher.decrypt(cipher_text)
    print('     Decrypted Message: ', repr(plain_text))
    return plain_text

 # 10. Send Server_hello_done
def sendServerDone(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello_Done')
    return b'Server_Hello_Done'

print('Server listening on: ', PORT)
startServer()
