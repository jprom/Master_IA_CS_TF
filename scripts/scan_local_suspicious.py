#!/usr/bin/env python3
import sys
import requests
import os
from pathlib import Path

# --- CONFIGURACIÓN ---
ADK_WEBHOOK_URL = os.getenv("ADK_SECURITY_AGENT_URL", "http://localhost:5678/webhook-test/analyze-files-security")
# Archivos que ignoramos (imágenes, lockfiles, etc.)
IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.exe', '.bin', '.lock', '.svg', '.pyc', '.git', '.css', '.html'}
# Palabras que activan la alerta para enviar a analizar
TRIGGER_KEYWORDS = ['secret', 'password', 'api_key', 'access_key', 'token', 'auth', 'credential', 'private_key', 'bearer']

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def analyze_file_with_agent(filepath, content):
    """Envía el CÓDIGO COMPLETO a N8N para un análisis profundo."""
    print(f"   {Colors.WARNING}📡 Enviando archivo completo a IA de Seguridad: {filepath}...{Colors.ENDC}")

    payload = {
        "filename": str(filepath),
        "code": content,  # <--- AQUÍ ESTÁ EL CAMBIO: Enviamos todo el código
        "user": os.getenv("USER", "unknown_dev")
    }

    try:
        response = requests.post(ADK_WEBHOOK_URL, json=payload, timeout=15) # Más tiempo para que la IA lea
        if response.status_code == 200:
            return response.json() # Esperamos una lista de hallazgos
        else:
            print(f"   ⚠️ Error del Agente (Status {response.status_code})")
            return {"findings": []}
    except Exception as e:
        print(f"   ⚠️ Error de conexión: {e}")
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

    # 1. FILTRO RÁPIDO LOCAL
    # Si el archivo no tiene palabras clave peligrosas, ni nos molestamos en gastar tokens de IA.
    content_lower = content.lower()
    has_trigger = any(keyword in content_lower for keyword in TRIGGER_KEYWORDS)
    
    # Opcional: También podrías mantener el chequeo de entropía aquí si quieres ser más estricto.

    if has_trigger:
        # 2. ANÁLISIS PROFUNDO REMOTO
        result = analyze_file_with_agent(filepath, content)
        return result.get("findings", [])
    
    return []

def main():
    # (Igual que antes, procesa argumentos)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames: return

    all_issues = []
    print(f"{Colors.HEADER}🛡️  Iniciando Deep Security Scan...{Colors.ENDC}")

    for filename in args.filenames:
        issues = scan_file(filename)
        if issues:
            for issue in issues:
                # Agregamos el nombre del archivo al issue para el reporte
                issue['file'] = filename
                all_issues.append(issue)

    if all_issues:
        print(f"\n{Colors.FAIL}🚨 BLOQUEO DE SEGURIDAD - SECRETOS ENCONTRADOS:{Colors.ENDC}")
        for issue in all_issues:
            print(f"📂 {issue.get('file')} (Línea {issue.get('line', '?')})")
            print(f"   ❌ {issue.get('message')}")
            print(f"   💡 Sugerencia: {issue.get('suggestion')}")
            print("-" * 40)
        sys.exit(1)
    else:
        print(f"{Colors.OKBLUE}✅ Análisis completado. Sin hallazgos críticos.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
