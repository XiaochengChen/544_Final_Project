import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


HOST = '127.0.0.1'  # Localhost
PORT = 3030         # Listening port

def startServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()     # Blocking call
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)  # for now this is just an echo server

def serverHello():
    # Send serverHello message with right contents 
    pass

print('Server listening on: ', PORT)
startServer()
    