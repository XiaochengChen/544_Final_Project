import socket
import json
import os
import time
import hashlib
import RSA
import random
import des

from Cryptodome.Hash import SHA1

HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port
thirdPartyPrivateKey, thirdPartyPublicKey  = RSA.generate_keypair(1297279, 1297657)

def startServer():
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        allMsgsHash = SHA1.new()
        with conn:
            flag, cipherSuit, tempMsg = recvClientHello(conn)       # 1. Recv Client_Hello
            allMsgsHash.update(tempMsg)                             # Updates hash with each received message
            if flag is None:
                print("Got error receiving Client hello")
                return
            allMsgsHash.update(sendServerHello(conn))               # 2. Send Server_Hello
            allMsgsHash.update(sendCertificate(conn, publickey))    # 3. Send Certificate and Public key
            preMasterSecret = recvPreMasterSecret(conn, privatekey) # 3.5 Recv Premaster Key
            allMsgsHash.update(sendServerDone(conn))                # 4. Send Server_hello_done
            print(allMsgsHash.hexdigest())

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

def sendCertificate(s, pk):
    certificate = makeServerCertificate('Download Server', pk)
    
    certSignature = makeCertificateSignature(certificate.encode("utf-8"))
    completeCertificate = '''\
        {"certificate": %s, \
        "signature": "%s"}''' % (certificate, certSignature)
    print("Server sent certificate, Size of certificate = ", len(completeCertificate))
    s.sendall(completeCertificate.encode("utf-8"))
    
    return completeCertificate.encode("utf-8")

def makeServerCertificate(name, pk):
    cert = '''{ "Name": "%s",\
    "Serial Number":"12345678", \
    "Expiration Date":"12/12/2020", \
    "d": "%d", "n": "%d"}''' % (name, pk[0], pk[1])
    return cert.replace(" ", "")

def makeCertificateSignature(certificate):
    certificateHash = SHA1.new()
    certificateHash.update(certificate)
    print("Certificate: ", certificate)
    print("Cert Hash: ", certificateHash.hexdigest())
    encryptedHash = encrypt(thirdPartyPrivateKey,certificateHash.digest())
    strListEncryptedHash = [str(i) for i in encryptedHash]
    return ' '.join(strListEncryptedHash)

def recvPreMasterSecret(s, pk):
    encryptedPreMasterSecret = s.recv(1024) 
    intArrOfPreMasterSecret = [int(n) for n in encryptedPreMasterSecret.decode("utf-8").split()]
    preMasterSecret = decrypt(pk, intArrOfPreMasterSecret)
    print("preMasterSecret : ", preMasterSecret)
    return preMasterSecret

#Private key and public key
def rsakeys():
    primeNumbersFile = open("primeNumbers.txt", "r")
    lines = primeNumbersFile.readlines()
    randomLine = random.randint(0, len(lines)-1)
    splitLine = lines[randomLine].split()
    p = int(splitLine[0])  
    q = int(splitLine[1])
    return RSA.generate_keypair(p, q)

# Encryption with RSA Public Key, returns an array of integers
def encrypt(pk, plaintext):
    ciphertext =  [RSA.encrypt(pk, b) for b in plaintext]
    return ciphertext

def decrypt(pk, ciphertext):
    plaintext = b''.join([RSA.decrypt(pk, c) for c in ciphertext])
    return plaintext

# 10. Send Server_hello_done
def sendServerDone(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello_Done')
    return b'Server_Hello_Done'

print('Server listening on: ', PORT)
startServer()
