# test_secrets.py

# CASO 1: DETECCIÓN POSITIVA (Debe ser bloqueado)
# Tiene alta entropía y el nombre de variable indica que es una llave privada.


# CASO 2: DETECCIÓN POSITIVA (AWS Style)
# Formato clásico de AWS, alta entropía.


# CASO 3: FALSO POSITIVO (Debe ser ignorado por el SLM)
# Tiene alta entropía (parece random), pero el nombre de la variable sugiere
# que es un hash o un ID, no un secreto. Aquí es donde el SLM brilla.
image_checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e"


# CASO DE PRUEBA: FALSOS POSITIVOS
# Tienen alta entropía, pero son seguros. El SLM debería dejarlos pasar.
user_uuid = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
file_checksum = "d41d8cd98f00b204e9800998ecf8427e"
dummy_token = "00000000000000000000000000000000" # Entropía muy baja, ni siquiera debería preguntar al SLM