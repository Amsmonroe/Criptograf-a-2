import os
import base64
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, filedialog
import ecdsa
import xml.etree.ElementTree as ET

# Función para cargar un secreto de Azure Key Vault
def load_secret_from_key_vault(vault_url, secret_name):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    try:
        secret = client.get_secret(secret_name)
        return base64.b64decode(secret.value)  # Decodifica el secreto Base64
    except Exception as e:
        print(f"Error al cargar el secreto '{secret_name}': {e}")
        return None

# Función para cifrar un documento con AES-GCM
def encrypt_document(document, master_key):
    iv = os.urandom(12)  # Genera un IV aleatorio de 12 bytes
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_document = encryptor.update(document) + encryptor.finalize()
    return iv + encryptor.tag + encrypted_document  # Devuelve IV + Tag + datos cifrados

# Guardar el documento cifrado en Azure Blob Storage
def save_encrypted_document_to_blob(encrypted_data, blob_service_client, container_name, blob_name):
    try:
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        blob_client.upload_blob(encrypted_data, overwrite=True)
        print(f"Documento cifrado guardado en Azure Blob Storage como {blob_name}")
    except Exception as e:
        print(f"Error al guardar el documento en Blob Storage: {e}")

# Guardar el archivo XML en Azure Blob Storage
def save_xml_to_blob(xml_file_path, blob_service_client, container_name, blob_name):
    try:
        with open(xml_file_path, 'rb') as file:
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            blob_client.upload_blob(file, overwrite=True)
            print(f"Archivo XML guardado en Azure Blob Storage como {blob_name}")
    except Exception as e:
        print(f"Error al guardar el archivo XML en Blob Storage: {e}")

# Función para generar un nombre único para archivos

def generate_unique_filename(base_name, extension):
    counter = 1
    while os.path.exists(f"{base_name}_{counter}.{extension}"):
        counter += 1
    return f"{base_name}_{counter}.{extension}"

# Función para firmar el documento y generar archivo XML
def sign_document_and_generate_xml(data, file_name):
    try:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)  # Generar clave privada
        
        # Generar nombres únicos para las claves
        private_key_filename = generate_unique_filename("private_key", "pem")
        public_key_filename = generate_unique_filename("public_key", "pem")

        signature = private_key.sign(data)  # Firmar los datos

        # Guardar claves localmente
        with open(private_key_filename, "wb") as key_file:
            key_file.write(private_key.to_pem())
        with open(public_key_filename, "wb") as pub_file:
            pub_file.write(private_key.verifying_key.to_pem())

        print(f"Claves generadas y guardadas localmente: {private_key_filename}, {public_key_filename}")

        # Crear XML
        root = ET.Element("FirmaDigital")
        clave_publica = ET.SubElement(root, "ClavePublica")
        clave_publica.text = base64.b64encode(private_key.verifying_key.to_pem()).decode()

        mensaje = ET.SubElement(root, "Mensaje")
        mensaje.set("Archivo", file_name)
        mensaje.text = base64.b64encode(data).decode()

        firma = ET.SubElement(root, "Firma")
        firma.text = base64.b64encode(signature).decode()

        # Guardar XML
        xml_file = file_name + ".xml"
        tree = ET.ElementTree(root)  # Corregir definición de tree
        tree.write(xml_file, encoding="utf-8", xml_declaration=True)

        print(f"Archivo XML generado y guardado como {xml_file}")
        return xml_file, public_key_filename
    except Exception as e:
        print(f"Error al firmar el documento y generar XML: {e}")
        return None, None

# Crear carpeta para almacenar el archivo cifrado, el XML y la clave pública
def create_folder_for_files(base_name):
    folder_name = os.path.splitext(base_name)[0]
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name

# Función principal
def main():
    # Ventana de selección de archivo
    root = Tk()
    root.withdraw()  # Ocultar la ventana principal de Tkinter
    input_file = filedialog.askopenfilename(title="Selecciona el documento a cifrar")

    if not input_file:
        print("No se seleccionó ningún archivo.")
        return

    # Leer el contenido del archivo
    try:
        with open(input_file, 'rb') as file:
            document = file.read()
    except Exception as e:
        print(f"Error al leer el archivo seleccionado: {e}")
        return

    # Configuración de Azure Key Vault y Blob Storage
    vault_url = "https://llaveslideres3.vault.azure.net/"  # URL del Key Vault
    master_key_name = "mi-clave-maestra"  # Nombre de la clave maestra

    # Cargar la clave maestra
    master_key = load_secret_from_key_vault(vault_url, master_key_name)
    if not master_key:
        print("No se pudo cargar la clave maestra. Abortando...")
        return

    # Cifrar el documento
    encrypted_data = encrypt_document(document, master_key)

    # Firmar el documento y generar archivo XML
    xml_file, public_key_file = sign_document_and_generate_xml(encrypted_data, os.path.basename(input_file))
    if not xml_file or not public_key_file:
        print("No se pudo generar el archivo XML o la clave pública. Abortando...")
        return

    # Crear carpeta para almacenar los archivos
    folder_name = create_folder_for_files(os.path.basename(input_file))
    encrypted_file_path = os.path.join(folder_name, os.path.basename(input_file) + ".enc")
    xml_file_path = os.path.join(folder_name, xml_file)
    public_key_path = os.path.join(folder_name, os.path.basename(public_key_file))

    # Guardar el archivo cifrado localmente
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Mover el archivo XML y la clave pública a la carpeta
    os.rename(xml_file, xml_file_path)
    os.rename(public_key_file, public_key_path)

    # Configurar Azure Blob Storage
    blob_service_client = BlobServiceClient(account_url="https://documentoscifrados.blob.core.windows.net/cifrados/", credential=DefaultAzureCredential())
    container_name = "cifrados"

    # Guardar los archivos en Azure Blob Storage
    save_encrypted_document_to_blob(encrypted_data, blob_service_client, container_name, os.path.join(folder_name, os.path.basename(encrypted_file_path)))
    save_xml_to_blob(xml_file_path, blob_service_client, container_name, os.path.join(folder_name, os.path.basename(xml_file_path)))

if __name__ == "__main__":
    main()


