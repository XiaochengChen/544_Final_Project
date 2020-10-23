import socket
import certificate
import random 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# Documentation for cryptography library https://cryptography.io/en/latest/
HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Same port as server

def startClient():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        sendClientHello(s)
        recvServerHello(s)

def sendClientHello(s): # s is used to send the hello client message
    s.sendall(b'Client_Hello')

def recvServerHello(s):
    serverHello = s.recv(1024) # Wait for serverHello message
    print('Received, ', repr(serverHello))
    # Do something with the message

startClient()
