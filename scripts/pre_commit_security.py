#!/usr/bin/env python3
import sys
import math
import json
import re
import argparse
import requests
import os
from collections import Counter
from pathlib import Path

# --- CONFIGURACIÓN ---
# El script buscará la URL en tus variables de entorno por seguridad.
# Si no existe, usa un valor por defecto (o lanza error).
ADK_WEBHOOK_URL = os.getenv("ADK_SECURITY_AGENT_URL", "https://tu-n8n-instance.com/webhook/analisis-seguridad")

# Mantenemos el filtro de entropía local para no saturar tu servidor N8N con basura
ENTROPY_THRESHOLD = 3.6 
IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.exe', '.bin', '.lock', '.svg', '.pyc', '.git'}

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# --- 1. CÁLCULO DE ENTROPÍA (Filtro Local) ---
def shannon_entropy(data):
    """Calcula la entropía para filtrar cadenas aburridas localmente."""
    if not data: return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

# --- 2. COMUNICACIÓN CON EL AGENTE (N8N) ---
def consult_adk_agent(filepath, line_number, variable_name, suspicious_value):
    """
    Empaqueta el hallazgo y lo envía al Agente Remoto (N8N).
    El Agente decide si es secreto y notifica al equipo si es necesario.
    """
    print(f"   {Colors.WARNING}📡 Consultando Agente de Seguridad para: {variable_name}...{Colors.ENDC}")

    payload = {
        "filename": str(filepath),
        "line": line_number,
        "variable": variable_name,
        "value": suspicious_value,
        "user": os.getenv("USER", "unknown_dev"), # Útil para notificar al manager correcto
        "context": "pre-commit-scan"
    }

    try:
        # Timeout de 5s. Si N8N está caído, decidimos si fallar o dejar pasar.
        response = requests.post(ADK_WEBHOOK_URL, json=payload, timeout=8)
        
        if response.status_code == 200:
            data = response.json()
            # Esperamos que N8N responda: { "is_secret": true, "reason": "..." }
            return data.get("is_secret", False), data.get("reason", "Flagged by Security Agent")
        else:
            print(f"   ⚠️ Error del Agente Remoto (Status {response.status_code})")
            # FAIL OPEN: Si el servidor de seguridad falla, ¿bloqueamos el trabajo?
            # False = Dejar pasar (mejor experiencia dev). True = Bloquear (máxima seguridad).
            return False, "Error de conexión con Agente"

    except Exception as e:
        print(f"   ⚠️ No se pudo conectar con el Agente: {e}")
        return False, "Error de red"

# --- 3. LÓGICA DE ESCANEO LOCAL ---
def scan_file(filepath):
    issues = []
    path = Path(filepath)
    
    # Evitar escanearse a sí mismo
    if path.resolve() == Path(__file__).resolve():
        return issues

    if path.suffix in IGNORED_EXTENSIONS or not path.exists() or path.is_dir():
        return issues

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return issues

    # Regex para capturar asignaciones
    assignment_pattern = re.compile(r'([a-zA-Z0-9_.-]+)\s*[:=]\s*["\']([^"\']+)["\']')

    for i, line in enumerate(lines):
        if len(line) > 500: continue 

        matches = assignment_pattern.findall(line)
        
        for var_name, value in matches:
            if len(value) < 8: continue 
            if value.startswith("http") or " " in value: continue # Ignorar URLs y frases con espacios
            
            entropy = shannon_entropy(value)
            
            # Solo enviamos al Agente si pasa el umbral de sospecha local
            if entropy > ENTROPY_THRESHOLD:
                print(f"{Colors.OKBLUE}[INFO] Sospechoso en {filepath}:{i+1} (Entropía: {entropy:.2f}){Colors.ENDC}")
                
                # Llamada al Agente Remoto
                is_secret, reason = consult_adk_agent(filepath, i+1, var_name, value)
                
                if is_secret:
                    issues.append({
                        "file": filepath,
                        "line": i + 1,
                        "variable": var_name,
                        "reason": reason
                    })
    return issues

# --- 4. MAIN ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames:
        # Si se ejecuta sin argumentos, no hacemos nada (para no romper hooks)
        return

    all_issues = []
    print(f"{Colors.HEADER}🛡️  Iniciando Agente de Seguridad Local...{Colors.ENDC}")

    for filename in args.filenames:
        found_issues = scan_file(filename)
        all_issues.extend(found_issues)

    if all_issues:
        print(f"\n{Colors.FAIL}🚨 BLOQUEO DE SEGURIDAD - SECRETOS DETECTADOS:{Colors.ENDC}")
        for issue in all_issues:
            print(f"📂 {issue['file']}:{issue['line']} -> {issue['variable']}")
            print(f"   📝 Razón del Agente: {issue['reason']}")
        
        print(f"\n{Colors.WARNING}⚠️  Se ha enviado una notificación automática al equipo de seguridad.{Colors.ENDC}")
        sys.exit(1) # Bloquea el commit
    else:
        print(f"{Colors.OKGREEN}✅ Código limpio. Aprobado por Agente.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()