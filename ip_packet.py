import ipaddress

rutas_visitadas = {}

def parse_packet(IP_packet):
    ip = ".".join(str(b) for b in IP_packet[0:4])
    puerto = int.from_bytes(IP_packet[4:6], "big")
    ttl = IP_packet[6]
    ID = int.from_bytes(IP_packet[7:11], "big")
    offset = int.from_bytes(IP_packet[11:15], "big")
    tamano = int.from_bytes(IP_packet[15:19], "big")
    flag = IP_packet[19]
    mensaje = IP_packet[20:]
    return (ip, puerto, ttl, ID, offset, tamano, flag, mensaje)


def create_packet(parsed_IP_packet):
    ip, puerto, ttl, ID, offset, tamano, flag, mensaje = parsed_IP_packet
    ip_bytes = bytes([int(x) for x in ip.split(".")])
    return (ip_bytes
            + puerto.to_bytes(2, "big")
            + ttl.to_bytes(1, "big")
            + ID.to_bytes(4, "big")
            + offset.to_bytes(4, "big")
            + tamano.to_bytes(4, "big")
            + flag.to_bytes(1, "big")
            + mensaje)

def check_routes(routes_file_name, destination_address):
    dest_IP, dest_puerto = destination_address
    area = None
    rutas = []
    with open(routes_file_name) as f:
        for linea in f:
            partes = linea.split()
            if len(partes) < 6:
                continue
            red, puerto_ini, puerto_fin, next_hop_IP, next_hop_puerto, mtu = partes[:6]
            if ipaddress.ip_address(dest_IP) in ipaddress.ip_network(red, strict=False) \
                    and int(puerto_ini) <= dest_puerto <= int(puerto_fin):
                if area is None:
                    area = (red, puerto_ini, puerto_fin)
                if area == (red, puerto_ini, puerto_fin):
                    rutas.append(((next_hop_IP, int(next_hop_puerto)), int(mtu)))
    if area is None:
        return None
    i = (rutas_visitadas.get(area, -1) + 1) % len(rutas)
    rutas_visitadas[area] = i
    return rutas[i]

def fragment_IP_packet(IP_packet, MTU):
    if len(IP_packet) <= MTU:
        return [IP_packet]
    ip, puerto, ttl, ID, offset, tamano, flag, mensaje = parse_packet(IP_packet)
    largo = MTU - 20
    fragmentos = []
    for i in range(0, len(mensaje), largo):
        trozo = mensaje[i:i + largo]
        if i + largo >= len(mensaje):
            flag_trozo = flag
        else:
            flag_trozo = 1
        fragmentos.append(create_packet((ip, puerto, ttl, ID, offset + i, len(trozo), flag_trozo, trozo)))
    return fragmentos

def reassemble_IP_packet(fragment_list):
    fragmentos = sorted([parse_packet(f) for f in fragment_list], key=lambda f: f[4])
    ip, puerto, ttl, ID, offset, tamano, flag, mensaje = fragmentos[0]
    if offset != 0:
        return None
    mensaje_completo = b""
    for ip, puerto, ttl, ID, offset, tamano, flag, mensaje in fragmentos:
        if offset != len(mensaje_completo):
            return None
        mensaje_completo += mensaje
    if flag != 0:
        return None
    ip, puerto, ttl, ID = fragmentos[0][0:4]
    return create_packet((ip, puerto, ttl, ID, 0, len(mensaje_completo), 0, mensaje_completo))