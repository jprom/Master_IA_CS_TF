#!/usr/bin/env python3
import sys
import math
import json
import re
import argparse
import requests
from collections import Counter
from pathlib import Path

# --- CONFIGURACIÓN ---
ENTROPY_THRESHOLD = 4.6 
OLLAMA_MODEL = "qwen2.5-coder:1.5b"
OLLAMA_URL = "http://localhost:11434/api/generate"
IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.exe', '.bin', '.lock', '.svg', '.pyc'}

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# --- 1. CÁLCULO DE ENTROPÍA ---
def shannon_entropy(data):
    """Calcula la entropía de Shannon."""
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

# --- 2. ANÁLISIS SLM (OLLAMA) ---
def analyze_with_slm(context_line, variable_name, suspicious_value):
    """Consulta al modelo local."""
    prompt = f"""
    You are a security auditor. Analyze this code snippet.
    Variable Name: "{variable_name}"
    Value: "{suspicious_value}"
    Full Line: "{context_line.strip()}"
    
    Task: Determine if this is a SENSITIVE SECRET (Password, API Key) or SAFE (UUID, Hash, Public Key).
    Respond ONLY in JSON format: {{"is_secret": boolean, "reason": "short explanation"}}
    """

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1}
        }, timeout=10) # Timeout aumentado a 10s por si carga el modelo
        
        if response.status_code == 200:
            result = json.loads(response.json()['response'])
            return result.get('is_secret', False), result.get('reason', 'Unknown')
    except Exception as e:
        # Si falla la conexión, asumimos que es secreto por precaución
        return True, f"SLM Error: {str(e)}"
    
    return False, "SLM Analysis Failed"

# --- 3. LÓGICA DE ESCANEO ---
def scan_file(filepath):
    issues = []
    path = Path(filepath)
    
    # Ignorar tipos de archivo y verificar existencia
    if path.suffix in IGNORED_EXTENSIONS or not path.exists() or path.is_dir():
        return issues

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return issues

    # Regex: Busca asignaciones tipo variable = "valor"
    assignment_pattern = re.compile(r'([a-zA-Z0-9_.-]+)\s*[:=]\s*["\']([^"\']+)["\']')

    for i, line in enumerate(lines):
        if len(line) > 500: continue # Ignorar líneas minificadas

        matches = assignment_pattern.findall(line)
        
        for var_name, value in matches:
            if len(value) < 8: continue 

            # AQUI es donde se llama a la función de entropía definida arriba
            entropy = shannon_entropy(value)
            
            if entropy > ENTROPY_THRESHOLD:
                print(f"{Colors.OKBLUE}[INFO] Analizando candidato en {filepath}:{i+1} (Entropía: {entropy:.2f})...{Colors.ENDC}")
                
                is_secret, reason = analyze_with_slm(line, var_name, value)
                
                if is_secret:
                    issues.append({
                        "file": filepath,
                        "line": i + 1,
                        "variable": var_name,
                        "entropy": entropy,
                        "reason": reason
                    })
    return issues

# --- 4. FUNCIÓN PRINCIPAL ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames:
        return

    all_issues = []
    print(f"{Colors.HEADER}🔍 Iniciando escaneo de seguridad...{Colors.ENDC}")

    for filename in args.filenames:
        # Llamamos a scan_file, NO a buscar_alta_entropia directamente
        found_issues = scan_file(filename)
        all_issues.extend(found_issues)

    if all_issues:
        print(f"\n{Colors.FAIL}🚨 ¡ALERTA! SECRETOS DETECTADOS:{Colors.ENDC}")
        for issue in all_issues:
            print(f"📂 {issue['file']}:{issue['line']} -> {issue['variable']} (Entropía: {issue['entropy']:.2f})")
            print(f"   Razón: {issue['reason']}")
        sys.exit(1) # Bloquea el commit
    else:
        print(f"{Colors.OKGREEN}✅ Escaneo limpio.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
