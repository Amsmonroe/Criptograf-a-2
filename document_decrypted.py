import base64
import os
import time
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.communication.email import EmailClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Configuración
WEBHOOK_URL = "https://amstar08.pythonanywhere.com/aprobaciones"
ADMINS_EMAILS = ["asalazarp1700@alumno.ipn.mx", "asalinasm2000@alumno.ipn.mx"]
MAX_WAIT_TIME = 300  # Tiempo máximo de espera en segundos (5 minutos)
POLL_INTERVAL = 15  # Intervalo entre cada consulta al webhook en segundos
PRIME = 2**127 - 1  # Número primo grande para el campo finito
VAULT_URL = "https://llaveslideres3.vault.azure.net"

# Funciones auxiliares
def mod_inv(a, p):
    """Calcula el inverso modular."""
    return pow(a, p - 2, p)

def ajustar_nombre_secretos(correo):
    """Ajusta el nombre del secreto para cumplir con las restricciones de Azure Key Vault."""
    return correo.replace('@', '-').replace('.', '-')

def descifrar_aes_gcm(clave, datos_cifrados):
    """Descifra datos cifrados con AES-GCM."""
    iv = datos_cifrados[:12]  # IV de 12 bytes
    tag = datos_cifrados[12:28]  # Etiqueta de autenticación de 16 bytes
    cifrado = datos_cifrados[28:]  # Datos cifrados
    cipher = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cifrado) + decryptor.finalize()

def recuperar_fragmento(correo):
    """Recupera y descifra un fragmento desde Key Vault."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=VAULT_URL, credential=credential)

    nombre_secreto = ajustar_nombre_secretos(correo)
    fragment_name = f"fragmento-{nombre_secreto}"
    clave_name = f"clave-{nombre_secreto}"

    fragmento_cifrado_base64 = client.get_secret(fragment_name).value
    clave_base64 = client.get_secret(clave_name).value

    fragmento_cifrado = base64.b64decode(fragmento_cifrado_base64)
    clave = base64.b64decode(clave_base64)

    fragmento_bytes = descifrar_aes_gcm(clave, fragmento_cifrado)
    fragmento = int.from_bytes(fragmento_bytes, byteorder='big')
    return fragmento

def lagrange_interpolation(fragmentos, p):
    """Reconstrucción de la clave usando interpolación de Lagrange."""
    suma = 0
    for j, (xj, yj) in enumerate(fragmentos):
        prod = yj
        for m, (xm, _) in enumerate(fragmentos):
            if m != j:
                prod = (prod * xm * mod_inv(xm - xj, p)) % p
        suma = (suma + prod) % p
    return suma

def wait_for_approvals():
    start_time = time.time()
    print("Esperando aprobaciones de los administradores...")

    while time.time() - start_time < MAX_WAIT_TIME:
        try:
            response = requests.get(WEBHOOK_URL)
            if response.status_code == 200:
                aprobaciones = response.json().get("aprobaciones", {})
                if all(aprobaciones.get(email, False) for email in ADMINS_EMAILS):
                    print("¡Todas las aprobaciones fueron recibidas!")
                    return True
                else:
                    print(f"Aprobaciones actuales: {aprobaciones}")
            else:
                print(f"Error al obtener aprobaciones: {response.text}")
        except Exception as e:
            print(f"Error al consultar el webhook: {e}")

        time.sleep(POLL_INTERVAL)

    print("Tiempo de espera agotado. No se recibieron todas las aprobaciones.")
    return False

def check_email_responses():
    responses = {}
    while True:
        for email in ADMINS_EMAILS:
            response = input(f"¿Recibiste un 'sí' de {email}? (sí/no): ").strip().lower()
            responses[email] = response == "sí"

        print(f"Aprobaciones actuales: {responses}")
        if all(responses.values()):
            return True
        time.sleep(5)

def send_email(acs_connection_string, sender_email, recipients, subject, body):
    email_client = EmailClient.from_connection_string(acs_connection_string)
    message = {
        "senderAddress": sender_email,
        "recipients": {
            "to": [{"address": recipient} for recipient in recipients],
        },
        "content": {
            "subject": subject,
            "plainText": body,
            "html": f"<html><body><p>{body}</p></body></html>",
        },
    }
    poller = email_client.begin_send(message)
    result = poller.result()

    if "messageId" in result:
        print(f"Correo enviado exitosamente. Message ID: {result['messageId']}")
    else:
        print("El correo fue enviado, pero no se pudo obtener el Message ID.")

def list_and_decrypt_files(container_name, connection_string, clave_reconstruida):
    """Lista los archivos en el blob, permite seleccionar uno, descifra y guarda localmente."""
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(container_name)

    print("Archivos disponibles en el contenedor:")
    blobs = list(container_client.list_blobs())
    for idx, blob in enumerate(blobs):
        print(f"{idx + 1}. {blob.name}")

    file_choice = int(input("Seleccione el número del archivo a descifrar: ")) - 1
    selected_blob = blobs[file_choice].name

    print(f"Descargando y descifrando el archivo: {selected_blob}")
    blob_client = container_client.get_blob_client(selected_blob)
    encrypted_data = blob_client.download_blob().readall()

    try:
        if len(encrypted_data) < 28:
            raise ValueError("El archivo cifrado no tiene suficiente longitud para contener IV, TAG y datos cifrados.")
        
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        cipher_data = encrypted_data[28:]

        print(f"IV: {iv.hex()}")
        print(f"TAG: {tag.hex()}")
        print(f"Datos cifrados: {cipher_data[:16].hex()}... (truncado)")

        decrypted_data = descifrar_aes_gcm(clave_reconstruida, encrypted_data)
        output_file = f"descifrado_{os.path.basename(selected_blob)}"
        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"Archivo descifrado y guardado como: {output_file}")

    except InvalidTag:
        print("Error: La etiqueta de autenticación no coincide. Verifica que la clave reconstruida sea correcta.")
    except Exception as e:
        print(f"Error al descifrar el archivo: {e}")

def borrar_aprobaciones():
    """Reinicia las aprobaciones utilizando el endpoint dedicado."""
    try:
        response = requests.post("http://127.0.0.1:5000/reset_aprobaciones")
        if response.status_code == 200:
            print("Aprobaciones reiniciadas exitosamente.")
        else:
            print(f"Error al reiniciar aprobaciones: {response.text}")
    except Exception as e:
        print(f"Error al intentar reiniciar aprobaciones: {e}")

# Función principal
def main():
    correos = [
        "asalazarp1700@alumno.ipn.mx",
        "asalinasm2000@alumno.ipn.mx",
        "ogutierreza1700@alumno.ipn.mx"
    ]

    # Borrar aprobaciones previas
    print("Borrando aprobaciones previas...")
    borrar_aprobaciones()

    # 1. Enviar correos a los administradores
    acs_connection_string = "endpoint=https://comunication-service-mails.unitedstates.communication.azure.com/;accesskey=F2cPabq4davyNvD8TvCQYpIut1ulMRWbRnFYaLPnOfQ1YATx2yknJQQJ99BAACULyCph3jNvAAAAAZCS2eW7"
    sender_email = "DoNotReply@6270a2d3-8067-4522-93ee-f3aa5cd9825a.azurecomm.net"

    print("Enviando correos a los administradores...")
    recipients = ADMINS_EMAILS
    subject = "Solicitud de aprobación para usar fragmentos"
    body = (
        "Se solicita su aprobación para usar los fragmentos de clave. "
        "Responda 'sí' o 'no' usando el enlace: "
        "https://amstar08.pythonanywhere.com/webhook"
    )
    send_email(acs_connection_string, sender_email, recipients, subject, body)

    # 2. Esperar aprobaciones de los administradores
    if not wait_for_approvals():
        print("Esperando respuestas manualmente por correo...")
        if not check_email_responses():
            print("Permiso denegado. No se procederá.")
            return

    # 3. Recuperar todos los fragmentos
    print("Recuperando fragmentos aprobados desde Key Vault...")
    fragmentos = [(i + 1, recuperar_fragmento(correo)) for i, correo in enumerate(correos)]

    # 4. Reconstruir la clave maestra
    clave_reconstruida = lagrange_interpolation(fragmentos, PRIME)
    clave_reconstruida_bytes = clave_reconstruida.to_bytes((clave_reconstruida.bit_length() + 7) // 8, "big")
    print(f"Clave reconstruida: {base64.b64encode(clave_reconstruida_bytes).decode('utf-8')}")

    # 5. Listar archivos en el blob y descifrar uno
    blob_connection_string = "DefaultEndpointsProtocol=https;AccountName=documentoscifrados;AccountKey=x0iks7+Sm8cRCZMIJx0YlAoNwauAwqxHkcu1WIpnjZ35o7tHfgjimggAMeucWI0V6jyNUEo/qZYD+AStZezZew==;EndpointSuffix=core.windows.net"
    container_name = "cifrados"
    list_and_decrypt_files(container_name, blob_connection_string, clave_reconstruida_bytes)

if __name__ == "__main__":
    main()
