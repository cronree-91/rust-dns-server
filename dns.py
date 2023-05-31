import socket

M_SIZE = 1024

serv_address = ('127.0.0.1', 8001)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(serv_address)

while True:
    rx_message, addr = sock.recvfrom(M_SIZE)

    print(f"[Server]: address: {addr} data: {rx_message}")