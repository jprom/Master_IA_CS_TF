# CASO 1: DETECCIÓN POSITIVA (Debe ser bloqueado)
# Tiene alta entropía y el nombre de variable indica que es una llave privada.


# CASO 2: DETECCIÓN POSITIVA (AWS Style)
# Formato clásico de AWS, alta entropía.


# CASO 3: FALSO POSITIVO (Debe ser ignorado por el SLM)
# Tiene alta entropía (parece random), pero el nombre de la variable sugiere
# que es un hash o un ID, no un secreto. Aquí es donde el SLM brilla.
image_checksum_md5 = "d41d8cd98f00b204e9800998ecf8427e"
