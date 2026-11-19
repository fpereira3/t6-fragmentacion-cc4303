import socket
import sys
from ip_packet import parse_packet, create_packet, check_routes, fragment_IP_packet, reassemble_IP_packet

router_IP = sys.argv[1]
router_puerto = int(sys.argv[2])
router_rutas = sys.argv[3]

router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
router_socket.bind((router_IP, router_puerto))

buff_size = 1024

fragmentos = {}

while True:
    IP_packet, _ = router_socket.recvfrom(buff_size)
    ip, puerto, ttl, ID, offset, tamano, flag, mensaje = parse_packet(IP_packet)
    destination_address = (ip, puerto)

    if ttl <= 0:
        print(f"Se recibió paquete {IP_packet} con TTL 0")
    elif destination_address == (router_IP, router_puerto):
        if ID not in fragmentos:
            fragmentos[ID] = []
        fragmentos[ID].append(IP_packet)
        paquete = reassemble_IP_packet(fragmentos[ID])
        if paquete is not None:
            print(parse_packet(paquete)[7].decode())
            del fragmentos[ID]
    else:
        ruta = check_routes(router_rutas, destination_address)
        if ruta is None:
            print(f"No hay rutas hacia {destination_address} para paquete {IP_packet}")
        else:
            next_hop, mtu = ruta
            new_packet = create_packet((ip, puerto, ttl - 1, ID, offset, tamano, flag, mensaje))
            for fragmento in fragment_IP_packet(new_packet, mtu):
                print(f"redirigiendo paquete {fragmento} con destino final {destination_address} "
                      f"desde {(router_IP, router_puerto)} hacia {next_hop}")
                router_socket.sendto(fragmento, next_hop)