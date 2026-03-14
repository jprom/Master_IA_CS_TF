import matplotlib.pyplot as plt
import numpy as np

# Datos simulados basados en pruebas reales
categorias = ['Texto Normal', 'Variables', 'UUIDs', 'MD5 Hash', 'API Keys (Base64)']
entropia_promedio = [2.5, 3.2, 3.8, 4.2, 5.8]
desviacion = [0.3, 0.4, 0.2, 0.3, 0.4]  # Variabilidad de los datos

fig, ax = plt.subplots(figsize=(10, 6))

# Colores para distinguir zonas de seguridad
colores = ['#a5d6a7', '#a5d6a7', '#fff59d', '#fff59d', '#ef9a9a']

barras = ax.bar(categorias, entropia_promedio, yerr=desviacion, capsize=5, color=colores, alpha=0.9, edgecolor='black')

# Línea de umbral anterior (3.5)
ax.axhline(y=3.5, color='gray', linestyle='--', linewidth=2, label='Umbral Inicial (3.5)')
# Línea de umbral final (4.5)
ax.axhline(y=4.5, color='red', linestyle='-', linewidth=2, label='Umbral Optimizado (4.5)')

# Añadir etiquetas y título
ax.set_ylabel('Entropía de Shannon (bits)')
ax.set_title('Justificación del Ajuste de Umbral de Entropía')
ax.legend()
ax.grid(axis='y', linestyle='--', alpha=0.7)

# Anotaciones
ax.text(4, 4.6, 'Zona de Detección Activa (SLM)', color='red', fontsize=10, ha='center')
ax.text(1, 2.0, 'Zona Segura (Ignorado)', color='green', fontsize=10, ha='center')

plt.tight_layout()
plt.show()