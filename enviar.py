import socket
import sys
from ip_packet import create_packet

IP_router_final = sys.argv[1]
puerto_router_final = int(sys.argv[2])
ttl = int(sys.argv[3])
ID = int(sys.argv[4])
mensaje = sys.argv[5].encode()
IP_envio = sys.argv[6]
puerto_envio = int(sys.argv[7])

IP_packet = create_packet((IP_router_final, puerto_router_final, ttl, ID, 0, len(mensaje), 0, mensaje))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(IP_packet, (IP_envio, puerto_envio))
sock.close()