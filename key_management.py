from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import random
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuración
PRIME = 2**127 - 1  # Un número primo grande para el campo finito
VAULT_URL = "https://LlavesLideres3.vault.azure.net"

# Conectar a Azure Key Vault
credential = DefaultAzureCredential()
client = SecretClient(vault_url=VAULT_URL, credential=credential)
print("Conexión exitosa al Key Vault.")

# Función para generar coeficientes del polinomio
def generar_coefs(secret, degree):
    coefs = [secret] + [random.randint(1, PRIME - 1) for _ in range(degree - 1)]
    return coefs

# Evaluar el polinomio en un punto
def evaluar_pol(coefs, x):
    y = sum(c * pow(x, i, PRIME) for i, c in enumerate(coefs)) % PRIME
    return y

# Ajustar nombres de los secretos para cumplir con las restricciones de Azure Key Vault
def ajustar_nombre_secretos(correo):
    return correo.replace('@', '-').replace('.', '-')

# Cifrado AES-GCM
def cifrar_aes_gcm(clave, datos):
    iv = random.getrandbits(96).to_bytes(12, byteorder='big')  # IV de 12 bytes para GCM
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(datos) + encryptor.finalize()
    return iv + encryptor.tag + cifrado  # Incluir IV y etiqueta de autenticación

# Descifrado AES-GCM
def descifrar_aes_gcm(clave, datos_cifrados):
    iv = datos_cifrados[:12]  # Extraer IV de 12 bytes
    tag = datos_cifrados[12:28]  # Extraer etiqueta de autenticación de 16 bytes
    cifrado = datos_cifrados[28:]  # Resto son los datos cifrados
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cifrado) + decryptor.finalize()

# Generar siempre una nueva clave maestra
secret_name = "mi-clave-maestra"
clave_maestra = random.getrandbits(128).to_bytes(16, byteorder='big')  # Generar clave de 16 bytes
client.set_secret(secret_name, base64.b64encode(clave_maestra).decode('utf-8'))
print("Nueva clave maestra generada y actualizada en el Key Vault.")

# Convertir la clave maestra a entero
clave_entera = int.from_bytes(clave_maestra, byteorder='big') % PRIME

# Dividir la clave maestra en fragmentos
num_fragmentos = 3  # Número total de fragmentos
umbral = 2  # Umbral mínimo para reconstruir
coefs = generar_coefs(clave_entera, umbral)
fragmentos = [(x, evaluar_pol(coefs, x)) for x in range(1, num_fragmentos + 1)]

# Lista de correos de los destinatarios
correos = [
    "asalazarp1700@alumno.ipn.mx",
    "asalinasm2000@alumno.ipn.mx",
    "ogutierreza1700@alumno.ipn.mx"
]

# Generar claves de cifrado únicas para cada fragmento y almacenarlos en Key Vault
for i, (correo, (x, y)) in enumerate(zip(correos, fragmentos), start=1):
    clave_cifrado = random.getrandbits(128).to_bytes(16, byteorder='big')  # Generar clave de 16 bytes
    fragmento_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
    fragmento_cifrado = cifrar_aes_gcm(clave_cifrado, fragmento_bytes)

    nombre_secreto = ajustar_nombre_secretos(correo)
    fragment_name = f"fragmento-{nombre_secreto}"
    clave_name = f"clave-{nombre_secreto}"

    # Guardar el fragmento cifrado en Key Vault
    client.set_secret(fragment_name, base64.b64encode(fragmento_cifrado).decode('utf-8'))
    client.set_secret(clave_name, base64.b64encode(clave_cifrado).decode('utf-8'))
    print(f"Fragmento {i} asociado a {correo} almacenado en Key Vault.")

# Recuperar un fragmento y descifrarlo
def recuperar_fragmento(correo):
    try:
        nombre_secreto = ajustar_nombre_secretos(correo)
        fragment_name = f"fragmento-{nombre_secreto}"
        clave_name = f"clave-{nombre_secreto}"

        fragmento_cifrado = base64.b64decode(client.get_secret(fragment_name).value)
        clave_cifrada = base64.b64decode(client.get_secret(clave_name).value)

        fragmento_bytes = descifrar_aes_gcm(clave_cifrada, fragmento_cifrado)
        fragmento = int.from_bytes(fragmento_bytes, byteorder='big')
        return fragmento
    except Exception as e:
        print(f"Error al recuperar el fragmento: {e}")
        return None

