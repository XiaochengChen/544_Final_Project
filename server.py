import socket
import json
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

import Cryptodome
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome import Random


HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port

def startServer():
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
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
                sendCertificate(conn,publickey)     # 6. Send Public key
                sendServerDone(conn)                # 7. Send Server_hello_done
                
                # encrypt(conn, publickey, b'here is software') # 8. Send encypted message to client

def recvClientHello(conn):
    data = conn.recv(1024)
    if not data:
        return None, None, None
    cipherSuit = json.loads(data) # Contains a dictionary with the cyphersuit
    return 1, cipherSuit, data.decode("utf-8")

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
    certificate_1 = b'{ "Name": "I am server hahahahahahaha", "Serial Number":"12345678", "Expire Date":"12/12/2020", "Public Key of the server":"%s"}' % publickey
    DS_thirdparty = SHA1(certificate_1)
    length=192
    DS_thirdparty_privatekey = RSA.generate(length, Random.new().read)
    DS_thirdparty_publickey = DS_thirdparty_privatekey.publickey()
    Enc_DS_thirdparty_privatekey = TripleDES(DS_thirdparty_privatekey)
    certificate_2 = certificate_1 + b'{"Digital Signature of the third party": "%s", "Public Key of the third party":"%s"}' % (Enc_DS_thirdparty_privatekey, DS_thirdparty_publickey)
    s.sendall(certificate_2)
    return certificate_2.decode("utf-8")

# Encryption with RSA Public Key from Server to Client
def encrypt(s, publickey, plain_text):
    cipher = PKCS1_OAEP.new(publickey)
    cipher_text = cipher.encrypt(plain_text)
    print('     Plain text to encrypt: ', plain_text )
    print('     Cipher text to send to client: ', cipher_text)
    s.sendall(cipher_text)


print('Server listening on: ', PORT)
startServer()
    