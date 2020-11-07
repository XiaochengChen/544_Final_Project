import socket
import certificate
import random
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# Documentation for cryptography library https://cryptography.io/en/latest/
HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Same port as server

def startClient():
    allMsgs = ''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        tmpMsg = s.connect((HOST, PORT))
        allMsgs += tmpMsg
        sendClientHello(s)  # 2. Send Client_Hello

        # Note: Maybe these receive from server functions can be
        #   separated based on what we want to do with the content
        #   being received
        recvServerHello(s)      # 4. Receive Server_Hello
        recvServerHelloDone(s)  
        recvCertiFromServer(s)   # 7. Receive Certificate from server and generate pre-master key
        # recvFromServer(s)   # 9. Receive Encrypted Message
        # 10. Get Private Key given RSA Public Key
        # 11. Decrypt the received message
        # decrypt(publickey, cipher_text)

def sendClientHello(s):
    cypherSuit = b'{ "Cipher": "DES", "MAC":"SHA-1", "CipherType":"Block", "HashSize":"20"}'
    s.sendall(cypherSuit)
    return cypherSuit.decode("utf-8")

def recvServerHello(s):
    serverMessage = s.recv(1024) # Wait for message from Server
    print('Client Received, ', repr(serverMessage))
    # Do something with the message

def recvServerHelloDone(s):
    pass
    
def recvCertiFromServer(s):
    s. recv(1024)
    print('Client received certificate')
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

#To fix: Decryption for client
def decrypt(publickey, cipher_text):
    getPrivateKey = RSA.importKey(open('private.pem').read())
    privatekey = PKCS1_OAEP.new(getPrivateKey)
    plain_text = cipher.decrypt(privatekey)
    print('Client Received, ', repr(serverMessage))




startClient()
