import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
from base64 import b64decode
import json
import hashlib

def client():
    host = input("Host: ")
    port = int(input("Port: "))
    m = hashlib.sha256()
    password = input("Encryption Password:")
    m.update(password.encode())
    key = bytes.fromhex(m.hexdigest())

    client_socket = socket.socket()
    client_socket.connect((host, port))

    def decrypt(ct):
          b64 = json.loads(ct)
          iv = b64decode(b64['iv'])
          ct = b64decode(b64['ciphertext'])
          cipher = AES.new(key, AES.MODE_CBC, iv)
          pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
          return pt

    def receive(client_socket):
      while True:
        data = client_socket.recv(1024).decode()  # receive response
        pt = decrypt(data)
        print("\n" + host + ": " + pt + "\n-> ", end="")  # show in terminal
    
    def encrypt(pt):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(pt.encode(), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        return result

    def send(client_socket):
      while True:
        message = input("-> ")  # again take input
        result = encrypt(message)
        client_socket.send(result.encode())  # send message

    x = threading.Thread(target=receive, args=(client_socket,))
    x.start()

    y = threading.Thread(target=send, args=(client_socket,))
    y.start()

client()
