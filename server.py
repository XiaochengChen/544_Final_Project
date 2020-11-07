import socket
import json
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# import Crypto
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.PublicKey import RSA
# from Crypto import Random

HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port

def startServer():
    # privatekey, publickey = rsakeys()
    # print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        allMsgs = ''
        with conn:
            while True:                         
                flag, cipherSuit, tempMsg = recvClientHello(conn)    # 1. Handle Client_Hello
                allMsgs += tempMsg                  # Concatenates the received message to allMsgs string
                if flag is None:
                    print("Got error receiving Client hello")
                    break
                sendServerHello(conn)               # 5. Send Server_Hello
                # sendPublicKey(conn,publickey)       # 6. Send Public key
                # encrypt(conn, publickey, b'here is software') # 8. Send encypted message to client

def recvClientHello(conn):
    data = conn.recv(1024)
    if not data:
        return None
    cipherSuit = json.loads(data) # Contains a dictionary with the cyphersuit
    print(cipherSuit["Cipher"])
    return 1, cipherSuit, data

def sendServerHello(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello')

#Private key and public key 1024 bits
# def rsakeys():
#      length=1024
#      privatekey = RSA.generate(length, Random.new().read)
#      publickey = privatekey.publickey()
#      return privatekey, publickey

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
    