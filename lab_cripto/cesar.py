def cifrado_cesar(texto, corrimiento):
    """
    Cifra un texto utilizando el algoritmo de cifrado César.

    Args:
        texto (str): El texto plano que se va a cifrar.
        corrimiento (int): El número de posiciones a desplazar en el alfabeto.

    Returns:
        str: El texto cifrado resultante.
    """
    resultado = ""

    # Iteramos sobre cada caracter del texto de entrada
    for caracter in texto:
        # Verificamos si el caracter es una letra del alfabeto
        if caracter.isalpha():
            # Determinamos si la letra es mayúscula o minúscula para
            # establecer el punto de partida (ASCII de 'A' o 'a').
            base = ord('A') if caracter.isupper() else ord('a')

            # Aplicamos la fórmula del cifrado César:
            # 1. Convertimos el caracter a su posición en el alfabeto (0-25)
            #    restando el valor ASCII base.
            # 2. Sumamos el corrimiento.
            # 3. Usamos el operador módulo 26 para asegurar que el resultado
            #    se mantenga dentro del rango del alfabeto (ej: 'Z' + 2 = 'B').
            # 4. Sumamos nuevamente el valor ASCII base para obtener el
            #    código del nuevo caracter cifrado.
            nuevo_codigo = (ord(caracter) - base + corrimiento) % 26 + base

            # Convertimos el código ASCII de vuelta a un caracter y lo añadimos al resultado.
            resultado += chr(nuevo_codigo)
        else:
            # Si el caracter no es una letra (es un número, espacio, etc.),
            # lo añadimos al resultado sin modificarlo.
            resultado += caracter

    return resultado


# --- Bloque principal de ejecución ---
if __name__ == "__main__":
    # 1. Solicitamos al usuario el texto a cifrar.
    texto_original = input("Ingrese el texto a cifrar: ")

    # 4. Usamos un bloque try-except para manejar errores si la entrada no es un número.
    try:
        # 1. Solicitamos el número de corrimiento.
        corrimiento_num = int(input("Ingrese el corrimiento (ej: 3): "))

        # Llamamos a la función de cifrado con las entradas del usuario.
        texto_cifrado = cifrado_cesar(texto_original, corrimiento_num)

        # 6. Imprimimos el resultado final.
        print(f"\nTexto cifrado: {texto_cifrado}")

    except ValueError:
        # Si int() falla, se captura la excepción y se muestra un mensaje de error.
        print("\nError: El valor del corrimiento debe ser un número entero.")
