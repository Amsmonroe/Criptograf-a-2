import getpass
import subprocess
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Función para validar la contraseña
def validar_contraseña():
    print("Solicitando contraseña...")  # Línea de depuración
    password = getpass.getpass("Introduce tu contraseña: ")
    print("Contraseña ingresada.")  # Línea de depuración
    
    # Configurar las credenciales y el cliente de Azure Key Vault
    credential = DefaultAzureCredential()
    key_vault_name = "accesoserver2"
    key_vault_uri = f"https://accesoserver2.vault.azure.net/"
    client = SecretClient(vault_url=key_vault_uri, credential=credential)
    
    # Obtener la contraseña almacenada en Key Vault
    secret_name = "server-password"
    stored_password = client.get_secret(secret_name).value
    
    # Validar la contraseña ingresada
    if password == stored_password:
        print("Acceso concedido")
        return True
    else:
        print("Acceso denegado")
        return False

# Función para iniciar el App Service
def iniciar_app_service():
    # Configuración del App Service en Azure
    resource_group = "Proyecto-cripto"
    app_service_name = "ProyectoCripto"
    
    comando = [
        "az", "webapp", "start",
        "--resource-group", resource_group,
        "--name", app_service_name
    ]
    
    print(f"Ejecutando comando: {' '.join(comando)}")  # Línea de depuración

    try:
        subprocess.run(' '.join(comando), shell=True, check=True)
        print("El App Service se ha iniciado correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"Error al iniciar el App Service: {e}")
    except FileNotFoundError as e:
        print("Error: Asegúrate de que Azure CLI está instalado y configurado.")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Flujo principal
if validar_contraseña():
    iniciar_app_service()
else:
    print("No se pudo iniciar el App Service debido a una contraseña incorrecta.")