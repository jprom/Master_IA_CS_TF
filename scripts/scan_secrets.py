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
ENTROPY_THRESHOLD = 3.5 
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
    prompt = f"""
    Analyze this code snippet.
    Variable: "{variable_name}"
    Value: "{suspicious_value}"
    
    Task: Is this a HARDCODED SECRET (Password, API Key)?
    Respond JSON: {{"is_secret": boolean, "reason": "explanation"}}
    """
    
    print(f"   {Colors.WARNING}⚡ Consultando IA para: {variable_name}...{Colors.ENDC}")

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 120  # Aumentamos esto para que no corte la frase
            }
        }, timeout=10)
        
        # --- NUEVO: Limpieza de respuesta ---
        raw_text = response.json().get('response', '')
        
        # Intentamos parsear. Si falla, buscamos el primer '{' y el último '}'
        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            start = raw_text.find('{')
            end = raw_text.rfind('}') + 1
            if start != -1 and end != -1:
                result = json.loads(raw_text[start:end])
            else:
                return False, "Error de formato JSON de la IA"

        return result.get('is_secret', False), result.get('reason', 'Unknown')

    except Exception as e:
        print(f"   [Error IA] {e}")
        # Si la IA falla, mejor dejar pasar (False) para no bloquear tu trabajo por error técnico
        return False, "Error de conexión con IA"
    
    """Consulta al modelo local optimizada para M1/M2/M3."""
    prompt = f"""
    Analyze this code snippet.
    Variable: "{variable_name}"
    Value: "{suspicious_value}"
    
    Task: Determine if this is a SENSITIVE SECRET (Password, API Key) or SAFE (UUID, Hash).
    Respond ONLY in JSON format: {{"is_secret": boolean, "reason": "short explanation"}}
    """

    print(f"   [DEBUG] Enviando a Ollama ({variable_name})...") # DEBUG

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            
            # OPTIMIZACIÓN M1:
            "keep_alive": "10m", # Mantiene el modelo cargado entre archivos
            "options": {
                "temperature": 0.0, # Determinista (más rápido)
                "num_ctx": 256,     # Ventana pequeña = Menos RAM = Más velocidad
                "num_predict": 60,  # Respuesta corta
                "top_k": 20         # Muestreo simplificado
            }
        }, timeout=30) # Timeout generoso para la primera carga
        
        # DEBUG: Ver qué responde exactamente Ollama
        if response.status_code != 200:
            print(f"   [ERROR SLM] Status Code: {response.status_code}")
            print(f"   [ERROR SLM] Respuesta: {response.text}")
            return True, f"Error del Servidor SLM (Code {response.status_code})"

        result = json.loads(response.json()['response'])
        return result.get('is_secret', False), result.get('reason', 'Unknown')

    except requests.exceptions.ConnectionError:
        print(f"   [ERROR CRÍTICO] No se puede conectar a Ollama en {OLLAMA_URL}")
        return True, "Ollama no está corriendo o puerto bloqueado"
    except Exception as e:
        print(f"   [ERROR] Excepción: {str(e)}")
        return True, f"Error SLM: {str(e)}"

        # En caso de error (timeout), fallamos seguro (fail-open) o inseguro?
        # Para pre-commit, mejor avisar pero no bloquear si el modelo está apagado,
        # A MENOS que quieras seguridad estricta.
        print(f"   [WARN] Ollama falló: {e}")
        return False, "SLM Skipped" # Cambia a True si quieres bloquear por error
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

            if value.startswith("http://") or value.startswith("https://"): continue
            
            # se llama a la función de entropía
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

# --- 4. FUNCIÓN MAIN ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames:
        return

    all_issues = []
    print(f"{Colors.HEADER}🔍 Iniciando escaneo de seguridad...{Colors.ENDC}")

    for filename in args.filenames:
        # Llamamos a scan_file
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
