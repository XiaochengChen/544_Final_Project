import socket
import certificate
import random
import json

import Cryptodome
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Hash import SHA1

# Documentation for cryptography library https://cryptography.io/en/latest/
HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Same port as server

def startClient():
    allMsgsHash = SHA1.new()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        allMsgsHash.update(sendClientHello(s))  # 2. Send Client_Hello
        # Note: Maybe these receive from server functions can be
        #   separated based on what we want to do with the content
        #   being received
        allMsgsHash.update(recvServerHello(s))      # 4. Receive Server_Hello 
        allMsgsHash.update(recvCertiFromServer(s))   # 7. Receive Certificate from server and generate pre-master key
        allMsgsHash.update(recvServerHelloDone(s)) 
        # recvFromServer(s)   # 9. Receive Encrypted Message
        # 10. Get Private Key given RSA Public Key
        # 11. Decrypt the received message
        # decrypt(publickey, cipher_text)

def sendClientHello(s):
    cypherSuit = b'{ "Cipher": "DES", "MAC":"SHA-1", "CipherType":"Block", "HashSize":"20"}'
    s.sendall(cypherSuit)
    return cypherSuit

def recvServerHello(s):
    serverMessage = s.recv(1024) # Wait for message from Server
    print('Client received (Server Hello), ', repr(serverMessage))
    return serverMessage

def recvServerHelloDone(s):
    data = s.recv(1024)
    print("Client received (Server_Hello_Done) ", data.decode("utf-8"))
    return data 
    
    
def recvCertiFromServer(s):
    certificate = s.recv(98)
    print('Client received certificate', certificate.decode("utf-8"))
    return certificate
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

#To fix: Decryption for client
def decrypt(publickey, cipher_text):
    getPrivateKey = RSA.importKey(open('private.pem').read())
    privatekey = PKCS1_OAEP.new(getPrivateKey)
    plain_text = cipher.decrypt(privatekey)
    print('Client Received, ', repr(serverMessage))




startClient()
