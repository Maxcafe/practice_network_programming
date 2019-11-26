# !/usr/bin/python
# -*- coding:utf-8 -*-

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = '192.168.14.36'
port = 50000

sock.bind((host, port))
sock.listen(1)

print('Waiting connection...')

# コネクションとクラインとの情報が返ってくる
connection, addr = sock.accept()
print('Connection from' + str(addr))

while True:
  # クライアントからデータを受信
  data = connection.recv(1024)

  # クライアントからexitと言うデータが送られてきたら終了
  if data == b'exit':
    break

  print('Received a message: ' + str(data))

  # クライアントにデータを送信
  connection.send(data)
  print('Sent a message: ' + str(data))

# connectionとsocketをクローズ
connection.close()
sock.close()
