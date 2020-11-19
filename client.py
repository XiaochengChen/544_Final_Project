import socket
import certificate
import random
import json
import os
import RSA
import des

from Cryptodome.Hash import SHA1
from Cryptodome.Hash import MD5
# Documentation for cryptography library https://cryptography.io/en/latest/
HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Same port as server
thirdPartyPrivateKey, thirdPartyPublicKey  = RSA.generate_keypair(1297279, 1297657)

def startClient():
    allMsgsHash = SHA1.new()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        cipherSuitBytes, cipherSuitjson = sendClientHello(s) # 1. Send Client_Hello
        allMsgsHash.update(cipherSuitBytes)  

        serverHelloBytes, serverHellojson = recvServerHello(s) # 2. Receive Server_Hello
        allMsgsHash.update(serverHelloBytes)

        # 3. Receive Certificate from server and generate pre-master key
        serverPublicKey, serverCertificateBytes = recvCertiFromServer(s)
        allMsgsHash.update(serverCertificateBytes)
        
        allMsgsHash.update(recvServerHelloDone(s))      # 4. Receive Server_hello_done
        
        
        preMasterSecretBytes = sendPreMasterSecret(s, serverPublicKey) # 5. Send Premaster key
        allMsgsHash.update(preMasterSecretBytes)

        

        masterSecret = createMasterSecret(preMasterSecretBytes,\
             cipherSuitjson["randomNonce"].encode("utf-8"), serverHellojson["randomNonce"].encode("utf-8"))
    
        sendSoftwareRequest(s)

        recvSoftware(s, masterSecret, serverPublicKey)
        
        return


def sendClientHello(s):
    n = 10
    helloRandom = random.randint(pow(10, n), pow(10, n+1) -1) # Creates a random number of n digits
    cipherSuitBytes = ('{ "Cipher": "DES", "MAC":"SHA-1",\
        "CipherType":"Block", "HashSize":"20", "randomNonce":"%s"}' % str(helloRandom)).replace(" ","").encode("utf-8")
    s.sendall(cipherSuitBytes)
    cipherSuitjson = json.loads(cipherSuitBytes)
    print("\n1. Client Hello: \n\t>>>", cipherSuitjson)
    return cipherSuitBytes , cipherSuitjson

def recvServerHello(s):
    serverHelloBytes = s.recv(1024) # Wait for message from Server
    serverHellojson = json.loads(serverHelloBytes)
    print('\n2. Server Hello: \n\t>>>', serverHellojson)
    return serverHelloBytes, serverHellojson

def recvCertiFromServer(s):
    serverCertificateBytes = s.recv(500)
    jsonCert = json.loads(serverCertificateBytes)
    print('\n3. Receive server certificate:\n\t>>>', jsonCert)
    certificate = jsonCert["certificate"]
    signature = jsonCert["signature"]
    serverPublicKey = (int(certificate["d"]), int(certificate["n"]))
    verifySignature(json.dumps(certificate).replace(" ", ""), signature, thirdPartyPublicKey)

    return serverPublicKey, serverCertificateBytes

def sendPreMasterSecret(s, pk):
    preMasterSecret = generatePreMasterSecret()
    print("\n3.5 Send premasterSecret (encrypted):\n\t>>>", preMasterSecret)
    temp = encrypt(pk, preMasterSecret)
    encryptedPreMasterSecret = ' '.join([str(n) for n in temp])
    s.sendall(encryptedPreMasterSecret.encode("utf-8"))
    return preMasterSecret

def verifySignature(contents, signature, pk):
    certHash = SHA1.new()
    certHash.update(contents.encode("utf-8"))
    intArrOfSignature = [int(n) for n in signature.split()]
    decryptedHash = decrypt(pk, intArrOfSignature)
    if decryptedHash != certHash.digest():
        raise TypeError("Signature didn't match")

def generatePreMasterSecret():
    # The client generates a 48-byte pre-master secret
    # and encrypts with the public key from the server’s
    # certificate or temporary RSA key from a
    # server_key_exchange message. Its use to compute a
    # master secret.
    os.urandom(48)
    return os.urandom(48)
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

def encrypt(pk, plaintext):
    ciphertext =  [RSA.encrypt(pk, b) for b in plaintext]
    return ciphertext

def decrypt(pk, ciphertext):
    plaintext = b''.join([RSA.decrypt(pk, c) for c in ciphertext])
    return plaintext

def recvServerHelloDone(s):
    serverHelloDoneBytes = s.recv(96)
    print("\n4. Receive server Hello done: \n\t>>>",serverHelloDoneBytes)
    return serverHelloDoneBytes

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

def sendSoftwareRequest(s):
    request = b'{"File Name" : "penguin.png"}'
    s.sendall(request)
    print("\n5. Client send software request:\n\t", request)

def recvSoftware(s, desKey, serverPublicKey):
    infoAboutPackets = json.loads(s.recv(100))
    with open("newPenguin.png", 'wb') as newFile:
        for packetN in range(int(infoAboutPackets["Number of packets"])):
            if packetN % 50 == 0:
                print(f"Receiving packet #{packetN}...")
            rcvdPacket = json.loads(s.recv(1024))
            actualPacketN = rcvdPacket["Payload"]["Packet Number"]
            verifySignature(json.dumps(rcvdPacket["Payload"]).replace(" ", ""),\
                rcvdPacket["Signature"], serverPublicKey)
            newFile.write(decryptDEShelper(rcvdPacket["Payload"]["Data"], desKey))
            if packetN % 50 == 0:
                print(f"Received packet #{actualPacketN}")
            sendPacketConfirmation(s, packetN)

def sendPacketConfirmation(s, n):
    s.sendall(b'{"Packet Number": "%d"}' % n)

def decryptDEShelper(ciphertext, key):
    coder = des.des()
    cipherRbyte = bytearray()
    [cipherRbyte.append(int(ch)) for ch in ciphertext.split()]
    rawPlaintext = coder.decrypt(key, cipherRbyte, padding=True)
    rByte = bytearray()
    [rByte.append(ord(ch)) for ch in rawPlaintext]
    return rByte

startClient()
