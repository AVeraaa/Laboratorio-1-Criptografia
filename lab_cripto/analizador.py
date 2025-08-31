from scapy.all import rdpcap, ICMP, Raw
import os

# Lista de palabras comunes en español para calcular la probabilidad del texto.
PALABRAS_COMUNES = [
    "de", "la", "en", "el", "y", "seguridad", "criptografia",
    "redes", "que", "con", "los", "un", "una", "del"
]


def descifrado_cesar(texto_cifrado, corrimiento):
    """
    Descifra un texto que fue cifrado con el algoritmo César.
    """
    texto_plano = ""
    for caracter in texto_cifrado:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            codigo_original = (ord(caracter) - base -
                               corrimiento + 26) % 26 + base
            texto_plano += chr(codigo_original)
        else:
            texto_plano += caracter
    return texto_plano


def calcular_probabilidad(texto):
    """
    Calcula un puntaje de "probabilidad" para un texto basado en la
    frecuencia de palabras comunes en español.
    """
    puntaje = 0
    texto_minusculas = texto.lower()
    for palabra in PALABRAS_COMUNES:
        puntaje += texto_minusculas.count(palabra)
    return puntaje


def analizar_captura(archivo_pcap):
    """
    Función principal que lee una captura, extrae el mensaje y lo descifra.
    """
    print(f"\n[+] Analizando el archivo: {archivo_pcap}")

    mensaje_cifrado = ""

    try:
        paquetes = rdpcap(archivo_pcap)
    except FileNotFoundError:
        print(f"[!] Error: El archivo '{archivo_pcap}' no fue encontrado.")
        return

    for paquete in paquetes:
        if paquete.haslayer(ICMP) and paquete[ICMP].type == 8 and paquete.haslayer(Raw):
            payload = paquete[Raw].load
            if len(payload) >= 9:
                caracter_secreto = chr(payload[8])
                mensaje_cifrado += caracter_secreto

    if not mensaje_cifrado:
        print("[!] No se encontró ningún mensaje oculto en la captura.")
        return

    print(f"\n[+] Mensaje cifrado reconstruido: {mensaje_cifrado}")
    print("-" * 40)
    print("[*] Realizando ataque de fuerza bruta...")

    # --- AJUSTE EMPIEZA AQUÍ ---

    # 1. FASE DE ANÁLISIS: Guardamos todos los resultados y encontramos el mejor.
    posibles_textos = []
    max_probabilidad = -1
    mejor_corrimiento = 0

    for corrimiento in range(26):
        texto_descifrado = descifrado_cesar(mensaje_cifrado, corrimiento)
        posibles_textos.append(texto_descifrado)

        probabilidad_actual = calcular_probabilidad(texto_descifrado)
        if probabilidad_actual > max_probabilidad:
            max_probabilidad = probabilidad_actual
            mejor_corrimiento = corrimiento

    # 2. FASE DE PRESENTACIÓN: Imprimimos la lista, coloreando la mejor opción.
    for i, texto in enumerate(posibles_textos):
        if i == mejor_corrimiento:
            # Imprimimos la línea más probable en verde.
            print(f"\033[92m    Corrimiento {i:2d}: {texto}\033[0m")
        else:
            print(f"    Corrimiento {i:2d}: {texto}")

    print("-" * 40)

    # Mantenemos el resumen final para claridad.
    print("[+] Opción más probable encontrada:")
    print(f"    Corrimiento: {mejor_corrimiento}")
    print(f"    Texto: {posibles_textos[mejor_corrimiento]}")


# --- Bloque principal de ejecución ---
if __name__ == "__main__":
    ruta_archivo = input("Ingrese la ruta al archivo de captura (.pcapng): ")

    if os.path.exists(ruta_archivo):
        analizar_captura(ruta_archivo)
    else:
        print(
            f"[!] Error: La ruta '{ruta_archivo}' no es válida o el archivo no existe.")
