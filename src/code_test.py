# Para que este código funcione, necesitarás instalar las bibliotecas 'requests' y 'mysql-connector-python'.
# Puedes hacerlo con pip:
# pip install requests mysql-connector-python

import requests
import mysql.connector
from mysql.connector import Error

def conectar_api_con_token(url="https://api.github.com/user"):
    """
    Se conecta a una API que requiere autenticación por token.
    """
    
    token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # Ejemplo de token de GitHub

    # test_secrets.py

    # CASO 1: DETECCIÓN POSITIVA (Debe ser bloqueado)
    # Tiene alta entropía y el nombre de variable indica que es una llave privada.
    stripe_api_key = "sk_live_51Mz9VzIqX8kL2pW9vR4tN7mJ1bH3gF5dC0xZ"

    # CASO 2: DETECCIÓN POSITIVA (AWS Style)
    # Formato clásico de AWS, alta entropía.
    #aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # CASO 3: FALSO POSITIVO (Debe ser ignorado por el SLM)
    # Tiene alta entropía (parece random), pero el nombre de la variable sugiere
    # que es un hash o un ID, no un secreto. Aquí es donde el SLM brilla.
    #image_checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    #user_session_uuid = "550e8400-e29b-41d4-a716-446655440000"


    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        print("--- Conectando a la API con token ---")
        response = requests.get(url, headers=headers)
        # Lanza una excepción si la solicitud no fue exitosa (código de estado != 200)
        response.raise_for_status()

        print("Conexión exitosa a la API.")
        print("Datos recibidos:")
        print(response.json())

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print("Error de autenticación (401). Verifica que el token sea correcto y tenga los permisos necesarios.")
        else:
            print(f"Error HTTP al conectar con la API: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión con la API: {e}")


def conectar_base_de_datos_mysql():
    """
    Establece una conexión con una base de datos MySQL.
    """
    # **IMPORTANTE**: Reemplaza estos valores con tus propias credenciales de MySQL.
    host_db = "localhost"
    usuario_db = "db_username"
    contraseña_db = "dbPassword2026$#"
    nombre_db = "clientes"
    
    conexion = None
    try:
        print("\n--- Conectando a la base de datos MySQL ---")
        conexion = mysql.connector.connect(
            host=host_db,
            user=usuario_db,
            password=contraseña_db,
            database=nombre_db
        )
        
        if conexion.is_connected():
            print("Conexión exitosa a la base de datos MySQL.")
            db_info = conexion.get_server_info()
            print("Versión del servidor MySQL:", db_info)
            
    except Error as e:
        print(f"Error al conectar a MySQL: {e}")
    finally:
        # Asegúrate de cerrar la conexión si se estableció
        if conexion and conexion.is_connected():
            conexion.close()
            print("Conexión a MySQL cerrada.")

def main():
    """
    Función principal que ejecuta las conexiones.
    """
    print("Iniciando ejecución del script...")
    conectar_api_con_token()
    conectar_base_de_datos_mysql()
    print("\nScript finalizado.")

if __name__ == "__main__":
    main()