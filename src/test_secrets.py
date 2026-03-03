# test_secrets.py

# CASO 1: DETECCIÓN POSITIVA (Debe ser bloqueado)
# Tiene alta entropía y el nombre de variable indica que es una llave privada.
stripe_api_key = "sk_test_123"

# CASO 2: DETECCIÓN POSITIVA (AWS Style)
# Formato clásico de AWS, alta entropía.
aws_secret_access_key = "AWS_SECRET_TEST"


# CASO 3: FALSO POSITIVO (Debe ser ignorado por el SLM)
# Tiene alta entropía (parece random), pero el nombre de la variable sugiere
# que es un hash o un ID, no un secreto. Aquí es donde el SLM hace su magia.
image_checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e"

user_session_uuid = "550e8400-e29b-41d4-a716-446655440000"

