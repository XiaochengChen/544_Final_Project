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
        sendClientHello(s)  # 2. Send Client_Hello

        # Note: Maybe these receive from server functions can be
        #   separated based on what we want to do with the content
        #   being received
        recvFromServer(s)   # 4. Receive Server_Hello
        recvFromServer(s)   # 7. Receive Public Key
        recvFromServer(s)   # 9. Receive Encrypted Message
        # 10. Get Private Key given RSA Public Key
        # 11. Decrypt the received message
        # decrypt(publickey, cipher_text)

def sendClientHello(s):
    # s is used to send the hello client message
    # Send clientHello message with right contents
    s.sendall(b'Client_Hello')

def recvFromServer(s):
    serverMessage = s.recv(1024) # Wait for message from Server
    print('Client Received, ', repr(serverMessage))
    # Do something with the message

#To fix: Decryption for client
def decrypt(publickey, cipher_text):
    getPrivateKey = RSA.importKey(open('private.pem').read())
    privatekey = PKCS1_OAEP.new(getPrivateKey)
    plain_text = cipher.decrypt(privatekey)
    print('Client Received, ', repr(serverMessage))




startClient()
