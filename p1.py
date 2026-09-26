import base64
import os
import re
import threading
import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Evento para asegurar que la conexión MQTT se complete antes de pedir entradas por consola
evento_conectado = threading.Event()

def cargar_clave_privada(ruta_fichero):
    # Lectura del fichero en modo binario
    with open(ruta_fichero, "rb") as key_file:
        datos = key_file.read()
        # Deserializa la clave generada con ssh-keygen
        return serialization.load_ssh_private_key(
            datos,
            password=None,
            backend=default_backend()
        )


def cargar_clave_publica(ruta_fichero):
    with open(ruta_fichero, "rb") as key_file:
        contenido = key_file.read()
        try:
            # Intenta cargar la clave en formato ssh-rsa de OpenSSH
            return serialization.load_ssh_public_key(contenido, backend=default_backend())
        except Exception:
            # Si no es OpenSSH, lo interpreta como formato tradicional PEM/PKCS#8
            return serialization.load_pem_public_key(contenido, backend=default_backend())


def rsa_encrypt(public_key, message):
    # Cifra con la clave pública del destinatario usando OAEP y SHA256 como hash
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, encrypted):
    # Descifra con la clave privada usando OAEP y SHA256 como hash
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def aes_encrypt(key, data):
    # Cifrador AES-GCM con la clave simétrica generada de 128 bits
    aesgcm = AESGCM(key)
    nonce = key
    return aesgcm.encrypt(nonce, data, None)


def aes_decrypt(key, ciphertext):
    # Descifra el texto con la clave simétrica recuperada
    aesgcm = AESGCM(key)
    nonce = key
    return aesgcm.decrypt(nonce, ciphertext, None)


def cargar_diccionario_pubkeys(ruta_archivo):
    # Si el fichero no existe en el directorio local, retorna un diccionario vacío
    if not os.path.exists(ruta_archivo):
        return {}

    # Apertura y lectura del fichero
    with open(ruta_archivo, "r", encoding="utf-8") as f:
        contenido = f.read()

    # Regex para extraer pares 'id' : 'clave'
    patron = r'["\']([a-zA-Z0-9_-]+)["\']\s*:\s*["\']([^"\']+)["\']'
    coincidencias = re.findall(patron, contenido)

    claves_cargadas = {}

    # Itera sobre cada id y su clave extraída
    for user_id, raw_key in coincidencias:
        raw_key = raw_key.strip()
        pub_key_obj = None

        # Intenta deserializar en formato OpenSSH
        try:
            linea_ssh = f"ssh-rsa {raw_key}".encode('utf-8')
            pub_key_obj = serialization.load_ssh_public_key(
                linea_ssh, backend=default_backend())
        except Exception:
            # Intenta deserializar en formato DER con Base 64
            if pub_key_obj is None:
                try:
                    der_bytes = base64.b64decode(raw_key)
                    pub_key_obj = serialization.load_der_public_key(
                        der_bytes, backend=default_backend())
                except Exception:
                    pass

        # Devuelve las claves RSA válidas
        if pub_key_obj is not None:
            claves_cargadas[user_id] = pub_key_obj

    return claves_cargadas


def cifrar_salto(public_key, datos_bytes):
    # Genera la clave simétrica de 128 bits
    key = AESGCM.generate_key(bit_length=128)
    # Cifra el mensaje con AES-GCM empleando la clave
    c2 = aes_encrypt(key, datos_bytes)
    # Cifra la clave simétrica con la clave pública RSA del salto
    c1 = rsa_encrypt(public_key, key)
    # Devuelve la clave cifrada mediante la clave pública RSA y el mensaje cifrado por la clave simétrica
    return c1 + c2


def descifrar_salto(private_key, mensaje_cifrado):
    # Calcula la longitud en bytes del que separa la clave simétrica cifrada del mensaje cifrado y los segmenta
    len_c1 = (private_key.key_size + 7) // 8
    c1 = mensaje_cifrado[:len_c1]
    c2 = mensaje_cifrado[len_c1:]

    # Recupera la clave simétrica usando la clave privada RSA
    key = rsa_decrypt(private_key, c1)
    # Descifra el contenido y valida la autenticidad con AES-GCM
    return aes_decrypt(key, c2)


def formatear_id(id_str):
    # Formatea el id para que tenga un tamaño exigido de 5 bytes
    return id_str.ljust(5).encode('utf-8')


def construir_onion(ruta_ids, ruta_public_keys, mi_id, mensaje_texto, anonimo=False):
    # Si se activa el flag anónimo, se oculta la identidad sustituyendo el remitente por 'none'
    remitente = "none" if anonimo else mi_id
    # Prepara el paquete a enviar indicando identidad de origen, texto y identificador de nodo destino final
    m = formatear_id(remitente) + mensaje_texto.encode('utf-8')
    m_prime = formatear_id("end") + m

    # Cifra la primera capa usando la clave pública del destino final
    c = cifrar_salto(ruta_public_keys[-1], m_prime)

    # Itera desde el penúltimo nodo hasta el primero de la secuencia de saltos
    for i in range(len(ruta_ids) - 2, -1, -1):
        # Indica al nodo actual a quién debe reenviarle el paquete
        siguiente_salto = formatear_id(ruta_ids[i + 1])
        # Añade la siguiente cabecera al payload y cifra para el nodo i
        c = cifrar_salto(ruta_public_keys[i], siguiente_salto + c)

    return c


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[MQTT] Conectado con éxito. Escuchando en el canal: '{MI_ID}'")
        # Se suscribe al tópico con el user-id para recibir paquetes
        client.subscribe(MI_ID)
        # Desbloquea el hilo de la consola principal una vez conectado
        evento_conectado.set()
    else:
        print(f"\n[MQTT] Error de conexión, código: {rc}")


def on_message(client, userdata, msg):
    print("\n[*] Paquete recibido en el canal local. Procesando...")
    try:
        # Descifra la capa exterior con la clave privada local
        datos = descifrar_salto(mi_clave_privada, msg.payload)
        # Lee los primeros 5 bytes para obtener el siguiente salto o la marca 'end'
        siguiente_salto = datos[:5].decode('utf-8').strip()
        c_siguiente = datos[5:]

        # Si no es 'end', actúa como nodo intermediario
        if siguiente_salto != "end":
            print(
                f"[+] Reenviando paquete al siguiente nodo: '{siguiente_salto}'")
            # Publica el payload restante en el canal del siguiente nodo
            client.publish(siguiente_salto, c_siguiente)
        else:
            # Si es el destinatario final extrae el ID del emisor y el mensaje
            emisor = c_siguiente[:5].decode('utf-8').strip()
            mensaje = c_siguiente[5:].decode('utf-8', errors='replace')
            print("\n==========================================")
            print(f"[*] MENSAJE DESTINADO A MÍ")
            print(f"    Emisor:  {emisor}")
            print(f"    Mensaje: {mensaje}")
            print("==========================================\n> ", end="")
    except Exception as e:
        # Maneja posibles fallos de autenticación o datos corruptos
        print(
            f"[!] No se pudo descifrar/procesar el paquete entrante: {e}\n> ", end="")


# Credenciales y datos del broker
BROKER_IP = "51.94.164.150"
PUERTO = 1883
USUARIO_MQTT = "sinf"
PASS_MQTT = "sinf2026"

MI_ID = "ffr"

# Inicializa claves cargando el par privado/público y las claves públicas de los nodos
mi_clave_privada = cargar_clave_privada("id_rsa")
claves_publicas_red = cargar_diccionario_pubkeys("pubkeys.py")
claves_publicas_red[MI_ID] = cargar_clave_publica("id_rsa.pub")

if __name__ == "__main__":
    try:
        cliente = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    except AttributeError:
        cliente = mqtt.Client()

    # Configuración de credenciales de autenticación de MQTT y decisiones ante la llegada de conexiones y recepción de mensajes
    cliente.username_pw_set(USUARIO_MQTT, PASS_MQTT)
    cliente.on_connect = on_connect
    cliente.on_message = on_message

    # Conexión al broker
    cliente.connect(BROKER_IP, PUERTO, 60)
    cliente.loop_start()

    # Pausa hasta recibir confirmación de conexión desde on_connect
    evento_conectado.wait()

    print("\n--- Cliente Onion Routing Iniciado ---")

    # Bucle para envío de mensajes desde terminal
    try:
        while True:
            # Lectura del texto del mensaje
            texto = input("\n> Escribe el mensaje a enviar (o 'salir'): ")
            if texto.lower() == 'salir':
                break
            if not texto.strip():
                continue

            # Lectura de la ruta ingresada separada por comas
            ruta_str = input(
                "> Introduce la ruta separada por comas (ej. ogc,mzp,hex): ")
            ruta = [nodo.strip()
                    for nodo in ruta_str.split(",") if nodo.strip()]

            if not ruta:
                continue

            # Comprueba que se disponga de las claves públicas de todos los nodos
            claves_faltantes = [
                nodo for nodo in ruta if nodo not in claves_publicas_red]
            if claves_faltantes:
                print(
                    f"[!] Error: Faltan las claves públicas de: {claves_faltantes}")
                continue

            # Validación de entrada obligatoria 's' o 'n' para remitente anónimo
            while True:
                opcion_anonimo = input(
                    "> ¿Enviar como anónimo ('none')? (s/n): ").strip().lower()
                if opcion_anonimo in ('s', 'n'):
                    es_anonimo = (opcion_anonimo == 's')
                    break
                print("[!] Entrada no válida, escribe 's' o 'n'.")

            # Recupera las claves públicas de la ruta y construye el paquete
            llaves_ruta = [claves_publicas_red[nodo] for nodo in ruta]
            onion = construir_onion(
                ruta, llaves_ruta, MI_ID, texto, anonimo=es_anonimo)

            # Envía el paquete al canal del primer nodo intermedio
            primer_salto = ruta[0]
            cliente.publish(primer_salto, onion)
            print(
                f"[+] Paquete publicado en el tópico: '{primer_salto}' (Anónimo: {es_anonimo})")

    except KeyboardInterrupt:
        pass
    finally:
        # Detiene la ejecución y cierra la sesión con el broker
        cliente.loop_stop()
        cliente.disconnect()
        print("\nDesconectado.")
