import socket
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import base64

HOST = '127.0.0.1'  # Localhost
PORT = 3030       # Listening port

def startServer():
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        with conn:
            while True: #Wait for client_hello
                data = recvClientHello(conn) #Received Client_Hello
                if not data:
                    break
                serverHello(conn) # Send Server_Hello

                cipher_text = encrypt(publickey, b'here is software')
                conn.sendall(cipher_text)


def recvClientHello(s):
    clientHello = s.recv(1024) # Wait for client_hello message
    print('Server Received, ', repr(clientHello))
    return clientHello

def serverHello(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello')

#Private key and public key 1024 bits
def rsakeys():
     length=1024
     privatekey = RSA.generate(length, Random.new().read)
     publickey = privatekey.publickey()
     return privatekey, publickey

#encryption for server
def encrypt(publickey, plain_text):
    cipher = PKCS1_OAEP.new(publickey)
    cipher_text = cipher.encrypt(plain_text)
    print('Plain text: ', plain_text )
    print('Cipher text: ', cipher_text)
    return cipher_text


print('Server listening on: ', PORT)
startServer()
