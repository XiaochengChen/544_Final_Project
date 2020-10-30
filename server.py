import socket
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port

def startServer():
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        with conn:
            while True:                         # 1. Wait for client_hello

                data = conn.recv(1024)          # check for client's message
                if not data:
                    break

                recvFromClient(data)            # 3. Received Client_Hello
                serverHello(conn)               # 5. Send Server_Hello
                sendPublicKey(conn,publickey)   # 6. Send Public key
                encrypt(conn, publickey, b'here is software') # 8. Send encypted message to client

def recvFromClient(data):
    print('Server Received, ', repr(data))

def serverHello(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello')

#Private key and public key 1024 bits
def rsakeys():
     length=1024
     privatekey = RSA.generate(length, Random.new().read)
     publickey = privatekey.publickey()
     return privatekey, publickey

def sendPublicKey(s, publickey):
    s.send(publickey.exportKey(format='PEM', passphrase=None, pkcs=1))

# Encryption with RSA Public Key from Server to Client
def encrypt(s, publickey, plain_text):
    cipher = PKCS1_OAEP.new(publickey)
    cipher_text = cipher.encrypt(plain_text)
    print('     Plain text to encrypt: ', plain_text )
    print('     Cipher text to send to client: ', cipher_text)
    s.sendall(cipher_text)


print('Server listening on: ', PORT)
startServer()
