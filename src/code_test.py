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
    # **IMPORTANTE**: Reemplaza "TU_TOKEN_DE_ACCESO_PERSONAL" con tu token real.
    # Por ejemplo, un token de acceso personal (PAT) de GitHub.
    # NUNCA expongas tus tokens directamente en el código en un entorno de producción.
    # Utiliza variables de entorno u otros métodos seguros para manejar secretos.
    token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # Ejemplo de token de GitHub

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
    usuario_db = "tu_usuario"
    contraseña_db = "tu_contraseña"
    nombre_db = "tu_base_de_datos"
    
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