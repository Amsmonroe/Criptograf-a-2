import subprocess
import json
import os
import base64
from azure.identity import AzureCliCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuración
PRIME = 2**127 - 1  # Un número primo grande para el campo finito
VAULT_URL = "https://LlavesLideres3.vault.azure.net"

# Conectar a Azure Key Vault utilizando las credenciales de Azure CLI
try:
    credential = AzureCliCredential()
    client = SecretClient(vault_url=VAULT_URL, credential=credential)
    print("Conexión exitosa al Key Vault utilizando Azure CLI.")
except Exception as e:
    print("Error al conectar al Key Vault. Asegúrate de haber iniciado sesión con 'az login'.")
    print(e)
    exit(1)

# Ajustar nombres de los secretos para cumplir con las restricciones de Azure Key Vault
def ajustar_nombre_secretos(correo):
    return correo.replace('@', '-').replace('.', '-')

# Descifrar AES-GCM con clave de 16 bytes
def descifrar_aes_gcm(clave, datos_cifrados):
    iv = datos_cifrados[:12]  # IV de 12 bytes
    tag = datos_cifrados[12:28]  # Etiqueta de autenticación de 16 bytes
    cifrado = datos_cifrados[28:]  # Datos cifrados
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cifrado) + decryptor.finalize()

# Recuperar un fragmento, descifrarlo y guardar automáticamente en Base64
def recuperar_y_guardar_fragmento(correo):
    try:
        # Usar nombres válidos para Azure Key Vault
        nombre_secreto = ajustar_nombre_secretos(correo)
        fragment_name = f"fragmento-{nombre_secreto}"
        clave_name = f"clave-{nombre_secreto}"

        # Recuperar el fragmento cifrado y la clave desde Key Vault
        fragmento_cifrado_base64 = client.get_secret(fragment_name).value
        clave_base64 = client.get_secret(clave_name).value

        if not fragmento_cifrado_base64 or not clave_base64:
            print(f"No se pudo recuperar el secreto '{fragment_name}' o '{clave_name}'.")
            return None

        print(f"Fragmento cifrado (Base64): {fragmento_cifrado_base64}")
        print(f"Clave (Base64): {clave_base64}")

        # Decodificar valores de Base64
        fragmento_cifrado = base64.b64decode(fragmento_cifrado_base64)
        clave = base64.b64decode(clave_base64)

        # Validar la longitud de la clave decodificada
        if len(clave) != 16:
            print(f"La clave no tiene 16 bytes. Longitud obtenida: {len(clave)}")
            return None

        # Descifrar el fragmento
        fragmento_bytes = descifrar_aes_gcm(clave, fragmento_cifrado)

        # Convertir el fragmento descifrado a Base64
        fragmento_base64 = base64.b64encode(fragmento_bytes).decode('utf-8')

        # Obtener la carpeta Descargas del sistema
        carpeta_descargas = os.path.join(os.path.expanduser("~"), "Descargas")
        if not os.path.exists(carpeta_descargas):
            os.makedirs(carpeta_descargas)

        # Guardar el fragmento en un archivo en la carpeta Descargas
        archivo_nombre = os.path.join(carpeta_descargas, f"fragmento_{correo}.txt")
        with open(archivo_nombre, 'w') as archivo:
            archivo.write(fragmento_base64)
        print(f"Fragmento guardado exitosamente en formato Base64 en {archivo_nombre}")
        return archivo_nombre

    except Exception as e:
        print("Error al recuperar el fragmento:")
        print(e)
        return None

# Obtener el correo electrónico del usuario autenticado con Azure CLI
def obtener_correo_desde_azure_cli():
    try:
        # Usa la ruta correcta al ejecutable `az.cmd`
        resultado = subprocess.run(
            ['C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd', 'account', 'show'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if resultado.returncode != 0:
            print("Error al ejecutar 'az account show'. Asegúrate de estar autenticado con 'az login'.")
            print(resultado.stderr)
            exit(1)
        
        # Parsear la salida JSON
        datos_cuenta = json.loads(resultado.stdout)
        correo = datos_cuenta.get('user', {}).get('name')
        if not correo:
            print("No se pudo obtener el correo electrónico del usuario autenticado.")
            exit(1)
        return correo
    except FileNotFoundError as fnfe:
        print("No se encontró el comando 'az'. Asegúrate de que Azure CLI esté instalado y en el PATH.")
        print(fnfe)
        exit(1)
    except Exception as e:
        print("Error al obtener información de Azure CLI:")
        print(e)
        exit(1)

# Flujo principal
correo_usuario = obtener_correo_desde_azure_cli()
archivo_fragmento = recuperar_y_guardar_fragmento(correo_usuario)
if archivo_fragmento:
    print(f"El fragmento ha sido guardado exitosamente en {archivo_fragmento}.")
else:
    print(f"No se pudo recuperar y guardar el fragmento para {correo_usuario}.")
