import socket
import json
import os
import time
import hashlib
import RSA
import random
import des

from Cryptodome.Hash import SHA1
from Cryptodome.Hash import MD5

HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port
thirdPartyPrivateKey, thirdPartyPublicKey  = RSA.generate_keypair(1297279, 1297657)

def startServer(flag=False):
    privatekey, publickey = rsakeys()
    print(privatekey, publickey) #Private and public keys
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        allMsgsHash = SHA1.new()
        with conn:
            cipherSuitBytes, cipherSuitjson = recvClientHello(conn)  # 1. Recv Client_Hello
            allMsgsHash.update(cipherSuitBytes)                      # Updates hash with each received message

            clientHelloBytes, hellojson = sendServerHello(conn)      # 2. Send Server_Hello
            allMsgsHash.update(clientHelloBytes)
                           
            allMsgsHash.update(sendCertificate(conn, publickey))    # 3. Send Certificate and Public key
            

            allMsgsHash.update(sendServerDone(conn))                # 4. Send Server_hello_done

            preMasterSecretBytes = recvPreMasterSecret(conn, privatekey) # 5. Recv Premaster Key
            allMsgsHash.update(preMasterSecretBytes)

            print(allMsgsHash.hexdigest())

            masterSecret = createMasterSecret(preMasterSecretBytes, \
                cipherSuitjson["randomNonce"].encode("utf-8"), hellojson["randomNonce"].encode("utf-8"))
            
            fileName = recvSoftwareRequest(conn)                 # 6. Recv software request from clients

            sendSoftware(conn, fileName, masterSecret, privatekey, flag)

def recvClientHello(conn):
    cipherSuitBytes = conn.recv(1024)
    cipherSuitjson = json.loads(cipherSuitBytes) # Contains a dictionary with the cyphersuit
    print("\n1. Client Hello: \n\t>>>", cipherSuitjson)
    return cipherSuitBytes, cipherSuitjson

def sendServerHello(s):
    n = 10
    helloRandom = random.randint(pow(10, n), pow(10, n+1) -1) # Creates a random number of n digits
    helloBytes = ('{"Message": "Server Hello", "randomNonce": "%s"}' % str(helloRandom)).replace(" ","").encode("utf-8") 
    s.sendall(helloBytes)
    hellojson = json.loads(helloBytes)
    print("\n2. Server Hello: \n\t>>>", hellojson)
    return helloBytes, hellojson

 # 5. Send Certificate and Public key

def sendCertificate(s, pk):
    certificate = makeServerCertificate('Download Server', pk)
    
    certSignature = makeCertificateSignature(certificate.encode("utf-8"))
    completeCertificate = '''\
        {"certificate": %s, \
        "signature": "%s"}''' % (certificate, certSignature)
    print("\n3. Send server Certificate: \n\t>>>", json.loads(completeCertificate))
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
    encryptedHash = encrypt(thirdPartyPrivateKey,certificateHash.digest())
    strListEncryptedHash = [str(i) for i in encryptedHash]
    return ' '.join(strListEncryptedHash)

def recvPreMasterSecret(s, pk):
    encryptedPreMasterSecret = s.recv(1024) 
    intArrOfPreMasterSecret = [int(n) for n in encryptedPreMasterSecret.decode("utf-8").split()]
    preMasterSecret = decrypt(pk, intArrOfPreMasterSecret)
    print("\n3.5 Receive premasterSecret (encrypted):\n\t>>>", preMasterSecret)
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

def sendServerDone(s):
    # Send serverHello message with right contents
    s.sendall(b'Server_Hello_Done')
    return b'Server_Hello_Done'

def createMasterSecret(preMasterSecretBytes, clientRandom, serverRandom):
    partOne = md5Helper([preMasterSecretBytes, shaHelper([b'A', preMasterSecretBytes,\
        clientRandom, serverRandom])])
    partTwo = md5Helper([preMasterSecretBytes, shaHelper([b'BB', preMasterSecretBytes,\
        clientRandom, serverRandom])])
    partThree = md5Helper([preMasterSecretBytes, shaHelper([b'CCC', preMasterSecretBytes,\
        clientRandom, serverRandom])])
    masterSecret = b''.join([partOne, partTwo, partThree])

    print("\n MasterSecret = \n\t>>>", masterSecret)
    return masterSecret

def shaHelper(byteArr):
    mySHA = SHA1.new()
    mySHA.update(b''.join(byteArr))
    return mySHA.digest()

def md5Helper(byteArr):
    myMD5 = MD5.new()
    myMD5.update(b''.join(byteArr))
    return myMD5.digest()

def recvSoftwareRequest(s):
    softwareRequest = s.recv(30)
    print("\n5. Server receives software request:\n\t>>>", softwareRequest)
    return json.loads(softwareRequest)["File Name"]

def sendSoftware(s, fileName, desKey, privateRSAKey, flag=False):
    with open(fileName, "rb") as rawFile:
        softwareFile = rawFile.read()
        #Splits the software file into a sublist of length n.
        n = 124 
        splitFile = [softwareFile[k:k+n] for k in range(0, len(softwareFile), n)]
        sendInfoAboutPackets(s, fileName, len(splitFile))
        for packetN in range(len(splitFile)):
            if packetN % 50 == 0:
                print(f"Sending packet #{packetN}...")
            packetToSend = createPacket(splitFile[packetN], desKey, privateRSAKey, packetN)
            if flag:
                s.sendall(maliciousPacket(packetToSend))
            else: 
                s.sendall(packetToSend)
            
            if not getPacketConfirmation(s, packetN):
                print("Got wrong confirmation packet, cancelling...")
                return
            if packetN % 50 == 0:
                print(f"Waiting for ACK on packet {packetN}...")

def sendInfoAboutPackets(s, fileName, m):
    info = b'{"File Name": "%b", "Number of packets": "%d"}' % (fileName.encode("utf-8"), m)
    s.sendall(info)

def createPacket(data, desKey, privateRSAKey,n):
    encryptedData = encryptDEShelper(data, desKey)
    rawPacket = '{"Data":"%s","Packet Number":"%s"}' % (encryptedData, str(n))
    signature = getPacketSignature(rawPacket.replace(" ","").encode("utf-8"), privateRSAKey)
    finalPacket = ('{"Payload" : %s, "Signature": "%s"}' % (rawPacket, signature)).encode("utf-8")
    return finalPacket

def getPacketSignature(content, pk):
    certificateHash = SHA1.new()
    certificateHash.update(content)
    encryptedHash = encrypt(pk,certificateHash.digest())
    strListEncryptedHash = [str(i) for i in encryptedHash]
    return ' '.join(strListEncryptedHash)

# This returns a string of numbers that need to be converted to bytearray to decrypt
def encryptDEShelper(data, key):
    coder = des.des()
    rawCipher = coder.encrypt(key, data, padding=True)
    rByte = bytearray()
    [rByte.append(ord(ch)) for ch in rawCipher]
    temp = [str(i) for i in rByte]
    return ' '.join(temp)

def maliciousPacket(originalPacket):
    ogPacket = json.loads(originalPacket)
    ogPacket["Payload"]["Data"] = 'Modified data'
    return json.dumps(ogPacket).encode("utf-8")


def getPacketConfirmation(s, n):
    ACKn = json.loads(s.recv(100))
    if ACKn["Packet Number"] != str(n):
        print(f"Did not get ACK for packet #{n}\nGot:")
        print("\t",ACKn)
        return False
    return True

print('Server listening on: ', PORT)
startServer(True) # Add parameter 'True' if needed to show protection to attack
