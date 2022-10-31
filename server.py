import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
from base64 import b64decode
import json
import hashlib

def server():
    host = input("Host: ")
    port = int(input("Port: "))
    m = hashlib.sha256()
    password = input("Encryption Password:")
    m.update(password.encode())
    key = bytes.fromhex(m.hexdigest())

    server_socket = socket.socket()
    server_socket.bind((host, port)) 
    server_socket.listen(2)
    conn, address = server_socket.accept() 
    print("Connection from: " + str(address))

    def encrypt(pt):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(pt.encode(), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        return result
    
    def decrypt(ct):
          b64 = json.loads(ct)
          iv = b64decode(b64['iv'])
          ct = b64decode(b64['ciphertext'])
          cipher = AES.new(key, AES.MODE_CBC, iv)
          pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
          return pt
    
    def receive(conn):
      while True:          
          data = conn.recv(1024).decode()
          pt = decrypt(data)

          if not data:
            print("User disconnected.")

          print("\n" + str(address[0]) + ": " + pt + "\n-> ", end="")  # show in terminal
         
    def send(conn):
        while True:
          data = input('-> ')
          ct = encrypt(data)
          conn.send(ct.encode())  # send data to the client

    x = threading.Thread(target=receive, args=(conn,))
    x.start()

    y = threading.Thread(target=send, args=(conn,))
    y.start()

server()
