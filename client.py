import socket
import certificate
import random
import json
import os
import RSA


from Cryptodome.Hash import SHA1

# Documentation for cryptography library https://cryptography.io/en/latest/
HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Same port as server
thirdPartyPrivateKey, thirdPartyPublicKey  = RSA.generate_keypair(1297279, 1297657)

def startClient():
    allMsgsHash = SHA1.new()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        allMsgsHash.update(sendClientHello(s))          # 1. Send Client_Hello
        allMsgsHash.update(recvServerHello(s))          # 2. Receive Server_Hello
        serverPublicKey, serverCertificate = recvCertiFromServer(s)
        allMsgsHash.update(serverCertificate)      # 6. Receive Certificate from server and generate pre-master key
        preMasterSecret = sendPreMasterSecret(s, serverPublicKey) 
        allMsgsHash.update(recvServerHelloDone(s))      # 11. Receive Server_hello_done
        return

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

# 6. Receive Certificate from server
def recvCertiFromServer(s):
    rawCertificate = s.recv(500)
    jsonCert = json.loads(rawCertificate)
    print('Client received certificate', jsonCert)
    certificate = jsonCert["certificate"]
    signature = jsonCert["signature"]
    serverPublicKey = (int(certificate["d"]), int(certificate["n"]))
    verifySignature(certificate, signature)

    return serverPublicKey, rawCertificate
    #TODO: generate pre-master key(48 byte encrypted with server's RSA public key)

def sendPreMasterSecret(s, pk):
    preMasterSecret = generatePreMasterSecret()
    print("preMasterSecret : ", preMasterSecret)
    temp = encrypt(pk, preMasterSecret)
    encryptedPreMasterSecret = ' '.join([str(n) for n in temp])
    s.sendall(encryptedPreMasterSecret.encode("utf-8"))
    return preMasterSecret

def verifySignature(contents, signature):
    certHash = SHA1.new()
    certHash.update(json.dumps(contents).replace(" ","").encode("utf-8"))
    intArrOfSignature = [int(n) for n in signature.split()]
    decryptedHash = decrypt(thirdPartyPublicKey, intArrOfSignature)
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

# 11. Receive Server_hello_done
def recvServerHelloDone(s):
    serverDone = s.recv(96)
    print("Client received (Server_Hello_Done) ", repr(serverDone))
    return serverDone

startClient()
