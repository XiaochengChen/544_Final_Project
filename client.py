import socket
import certificate
import random
import json
import os

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
        allMsgsHash.update(sendClientHello(s))          # 2. Send Client_Hello
        allMsgsHash.update(recvServerHello(s))          # 4. Receive Server_Hello
        allMsgsHash.update(recvCertiFromServer(s))      # 6. Receive Certificate from server and generate pre-master key
        allMsgsHash.update(recvPublicKeyFromServer(s))  # 7. Receive Public Key from server
        allMsgsHash.update(recvCipherTextFromServer(s)) # 9. Receive CipherText
        allMsgsHash.update(recvServerHelloDone(s))      # 11. Receive Server_hello_done

# 2. Send Client_Hello
def sendClientHello(s):
    cypherSuit = b'{ "Cipher": "DES", "MAC":"SHA-1", "CipherType":"Block", "HashSize":"20"}'
    s.sendall(cypherSuit)
    return cypherSuit

# 4. Receive Server_Hello
def recvServerHello(s):
    serverHello = s.recv(1024) # Wait for message from Server
    print('Client received (Server Hello), ', repr(serverHello))
    return serverHello

# 6. Receive Certificate from server and generate pre-master key
def recvCertiFromServer(s):
    certificate = s.recv(96)
    print('Client received certificate', certificate)
    return certificate
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

def preMasterKey():
    # The client generates a 48-byte pre-master secret
    # and encrypts with the public key from the server’s
    # certificate or temporary RSA key from a
    # server_key_exchange message. Its use to compute a
    # master secret.
    os.urandom(48)
    return os.urandom(48)
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

# 7. Receive Public Key from server
def recvPublicKeyFromServer(s):
    publickey = s.recv(1024)
    print('Client received public key with certificate', publickey.decode("utf-8"))
    return publickey

# 9. Receive CipherText
def recvCipherTextFromServer(s):
    ciphertext = s.recv(1024)
    print('Client received ciphertext', ciphertext)
    return ciphertext

def encrypt(s, publickey, plain_text):
    cipher = PKCS1_OAEP.new(publickey)
    cipher_text = cipher.encrypt(plain_text)
    print('     Plain text to encrypt: ', plain_text )
    print('     Cipher text to send to client: ', cipher_text)
    return cipher_text

# Assume client's private key is a saved file
def decryption(cipher_text):
    key = RSA.importKey(open('keyfile.pem').read())
    cipher = PKCS1_OAEP.new(key)
    plain_text = cipher.decrypt(cipher_text)
    print('     Decrypted Message: ', repr(plain_text))
    return plain_text

# 11. Receive Server_hello_done
def recvServerHelloDone(s):
    serverDone = s.recv(96)
    print("Client received (Server_Hello_Done) ", repr(serverDone))
    return serverDone

startClient()
