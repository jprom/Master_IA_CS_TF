#!/usr/bin/env python3
import sys
import requests
import os
import math
import re
from pathlib import Path

# --- CONFIGURACIÓN ---
ADK_WEBHOOK_URL = os.getenv("ADK_SECURITY_AGENT_URL", "https://tu-n8n.com/webhook/analisis-profundo")

# Umbral de Entropía (4.5 es un buen punto medio para detectar claves base64/hex)
ENTROPY_THRESHOLD = 4.5 

# Extensiones ignoradas
IGNORED_EXTENSIONS = {'.png', '.jpg', '.lock', '.pyc', '.git', '.css', '.html', '.md', '.txt'}

# --- REGEX PATTERNS (Detección Local) ---
# Patrones conocidos de alto riesgo
PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
    (r"xox[baprs]-([0-9a-zA-Z]{10,48})?", "Slack Token"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "Private Key Header"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
]

# Regex para capturar strings entre comillas (simples o dobles) para medir su entropía
STRING_LITERAL_REGEX = re.compile(r"(['\"])(.*?)\1")

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def shannon_entropy(data):
    """Calcula la entropía de una cadena.
    Una cadena como 'aaaaa' tiene entropía 0.
    Una cadena como 'wJalrXUtnFEMI/K7MDENG' tiene entropía alta (>4.5).
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def local_quick_scan(content):
    """
    Analiza el contenido localmente buscando:
    1. Patrones Regex conocidos (AWS, Stripe, etc.)
    2. Strings con alta entropía (parecen contraseñas o keys aleatorias)
    
    Retorna: True si encuentra ALGO sospechoso.
    """
    
    # 1. Chequeo de Regex Específicos
    for pattern, name in PATTERNS:
        if re.search(pattern, content):
            print(f"   {Colors.WARNING}⚠️  Patrón detectado localmente: {name}{Colors.ENDC}")
            return True

    # 2. Chequeo de Entropía en Strings
    # Buscamos todo lo que esté entre comillas
    strings_found = STRING_LITERAL_REGEX.findall(content)
    
    for quote_type, string_val in strings_found:
        # Ignoramos strings muy cortos o muy largos (falsos positivos comunes)
        if len(string_val) < 12 or len(string_val) > 120:
            continue
        
        # Ignoramos si tiene espacios (las claves usualmente no tienen espacios)
        if ' ' in string_val:
            continue

        entropy = shannon_entropy(string_val)
        if entropy > ENTROPY_THRESHOLD:
            print(f"   {Colors.WARNING}⚠️  Alta entropía detectada ({entropy:.2f}): '{string_val[:10]}...'{Colors.ENDC}")
            return True
            
    return False

def analyze_file_with_agent(filepath, content):
    """Envía el archivo a N8N para confirmación inteligente."""
    print(f"   {Colors.OKBLUE}📡 Enviando a IA para confirmación...{Colors.ENDC}")

    payload = {
        "filename": str(filepath),
        "code": content,
        "user": os.getenv("USER", "unknown_dev")
    }

    try:
        response = requests.post(ADK_WEBHOOK_URL, json=payload, timeout=20)
        if response.status_code == 200:
            return response.json() # Esperamos { "findings": [...] }
        else:
            print(f"   ❌ Error del Agente Remoto (Status {response.status_code})")
            return {"findings": []}
    except Exception as e:
        print(f"   ❌ Error de conexión: {e}")
        return {"findings": []}

def scan_file(filepath):
    path = Path(filepath)
    if path.suffix in IGNORED_EXTENSIONS or not path.exists() or path.is_dir():
        return []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return []

    print(f"🔍 Escaneando: {filepath}")

    # PASO 1: FILTRO LOCAL (Rápido)
    is_suspicious = local_quick_scan(content)

    if is_suspicious:
        # PASO 2: ANÁLISIS PROFUNDO (Remoto)
        # Solo gastamos tokens y tiempo si el local sospecha algo
        result = analyze_file_with_agent(filepath, content)
        return result.get("findings", [])
    
    return []

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames: return

    all_issues = []
    print(f"{Colors.HEADER}🛡️  Security Pre-Commit Hook (Hybrid Mode){Colors.ENDC}")

    for filename in args.filenames:
        issues = scan_file(filename)
        if issues:
            for issue in issues:
                issue['file'] = filename
                all_issues.append(issue)

    if all_issues:
        print(f"\n{Colors.FAIL}🚨 BLOQUEO: La IA confirmó secretos en tu código:{Colors.ENDC}")
        for issue in all_issues:
            print(f"📂 {issue.get('file')}")
            print(f"   ❌ {issue.get('message')}")
            print(f"   💡 {issue.get('suggestion')}")
            print("-" * 40)
        sys.exit(1)
    else:
        print(f"\n{Colors.OKBLUE}✅ Todo limpio.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
