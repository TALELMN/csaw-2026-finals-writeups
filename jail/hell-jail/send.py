# send.py — ship the ELF to the jail service and read the flag back.
import socket
s = socket.create_connection(("10.0.219.67", 1337), timeout=10)
s.sendall(open("open_flag", "rb").read())
s.shutdown(socket.SHUT_WR)
out = b""
while (d := s.recv(4096)):
    out += d
print(out.decode())
