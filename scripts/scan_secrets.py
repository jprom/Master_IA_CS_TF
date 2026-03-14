#!/usr/bin/env python3
import sys
import math
import json
import re
import argparse
import requests
import getpass 
import os
from collections import Counter
from pathlib import Path

# --- CONFIGURACIÓN ---

N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/notification"

ENTROPY_THRESHOLD = 4.5 
OLLAMA_MODEL = "qwen2.5-coder:1.5b" 
OLLAMA_URL = "http://localhost:11434/api/generate"
IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.exe', '.bin', '.lock', '.svg', '.pyc', '.git', '.css', '.scss'}

# Configuración de contexto
CONTEXT_WINDOW_SIZE = 100 

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

# --- 2. EXTRACCIÓN DE CONTEXTO ---
def get_context_window(lines, target_index, window=CONTEXT_WINDOW_SIZE):
    """
    Extrae un bloque de código alrededor de la línea objetivo.
    Devuelve el código con números de línea para ayudar al LLM.
    """
    start = max(0, target_index - window)
    end = min(len(lines), target_index + window + 1)
    
    context_str = ""
    for i in range(start, end):
        prefix = ">> " if i == target_index else "   "
        context_str += f"{prefix}Line {i+1}: {lines[i]}"
    
    return context_str

# --- 3. ANÁLISIS SLM (OLLAMA LOCAL) ---
def analyze_with_slm(full_context, variable_name, suspicious_value, filename):
    """
    Consulta al modelo local Ollama enviando el contexto del código.
    """
    prompt = f"""
    You are a Senior Security Engineer reviewing code.
    
    I found a high-entropy string in file: '{filename}'.
    
    Variable Name: "{variable_name}"
    Suspicious Value: "{suspicious_value}"
    
    Below is the CODE CONTEXT (surrounding lines). Analyze how this variable is USED.
    
    --- BEGIN CODE CONTEXT ---
    {full_context}
    --- END CODE CONTEXT ---
    
    Analysis Rules:
    1. If the variable is used for Authentication (API Key, Password, Secret, Bearer Token), return "is_secret": true.
    2. If the variable is a UUID, Checksum, Hash, Public ID, CSS Class, or Random Seed, return "is_secret": false.
    3. Look at the variable name semantics (e.g., 'api_key' is suspicious, 'image_id' is safe).
    
    Respond ONLY in JSON format: {{"is_secret": boolean, "reason": "short explanation based on context"}}
    """

    print(f"   {Colors.WARNING}⚡ Analizando contexto con IA Local ({variable_name})...{Colors.ENDC}")

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1, # Baja temperatura para ser más analítico
                "num_ctx": 4096     # Aumentamos ventana de contexto del modelo
            }
        }, timeout=30) # Aumentamos timeout porque procesar contexto toma más tiempo
        
        if response.status_code != 200:
            return False, f"Error Ollama: {response.status_code}"

        # Limpieza y parseo de la respuesta
        raw_text = response.json().get('response', '')
        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            # Intento de recuperación si el JSON viene sucio
            start = raw_text.find('{')
            end = raw_text.rfind('}') + 1
            if start != -1 and end != -1:
                result = json.loads(raw_text[start:end])
            else:
                return False, "Error formato JSON IA"

        return result.get('is_secret', False), result.get('reason', 'Unknown')

    except Exception as e:
        print(f"   [Error IA] {e}")
        return False, "Error conexión IA"

# --- 4. REPORTE A N8N ---
def send_alert_to_n8n(issues):
    """Envía el reporte de secretos encontrados a n8n."""
    print(f"   {Colors.FAIL}📡 Enviando alerta a n8n (Slack)...{Colors.ENDC}")
    
    payload = {
        "user": getpass.getuser(),
        "project": os.path.basename(os.getcwd()),
        "secrets_found": len(issues),
        "details": issues
    }

    try:
        requests.post(N8N_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"   ⚠️ No se pudo enviar la alerta a n8n: {e}")

# --- 5. LÓGICA DE ESCANEO ---
def scan_file(filepath):
    issues = []
    path = Path(filepath)
    
    if path.suffix in IGNORED_EXTENSIONS or not path.exists() or path.is_dir():
        return issues

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return issues

    # Regex: Variable = "Valor"
    assignment_pattern = re.compile(r'([a-zA-Z0-9_.-]+)\s*[:=]\s*["\']([^"\']+)["\']')

    for i, line in enumerate(lines):
        if len(line) > 500: continue 

        matches = assignment_pattern.findall(line)
        
        for var_name, value in matches:
            if len(value) < 8: continue 
            if value.startswith("http://") or value.startswith("https://"): continue
            
            # 1. Filtro de Entropía
            entropy = shannon_entropy(value)
            
            if entropy > ENTROPY_THRESHOLD:
                print(f"{Colors.OKBLUE}[INFO] Candidato en {filepath}:{i+1} (Entropía: {entropy:.2f}){Colors.ENDC}")
                
                # PREPARAR CONTEXTO
                # Obtenemos 100 líneas antes y después para que la IA entienda la lógica
                code_context = get_context_window(lines, i)
                
                # 2. Confirmación con IA Local + Contexto
                is_secret, reason = analyze_with_slm(code_context, var_name, value, filepath)
                
                if is_secret:
                    issues.append({
                        "file": filepath,
                        "line": i + 1,
                        "variable": var_name,
                        "entropy": round(entropy, 2),
                        "reason": reason,
                        "snippet": line.strip() # Enviamos solo la línea del secreto para evitar exponer el valor real
                    })
    return issues

# --- 6. FUNCIÓN MAIN ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*')
    args = parser.parse_args()

    if not args.filenames:
        return

    all_issues = []
    print(f"{Colors.HEADER}🔍 Iniciando escaneo local de seguridad con Contexto IA...{Colors.ENDC}")

    for filename in args.filenames:
        found_issues = scan_file(filename)
        all_issues.extend(found_issues)

    if all_issues:
        # SI SE ENCUENTRAN SECRETOS:
        print(f"\n{Colors.FAIL}🚨 ¡ALERTA! SECRETOS CONFIRMADOS POR IA LOCAL:{Colors.ENDC}")
        
        for issue in all_issues:
            print(f"📂 {issue['file']}:{issue['line']} -> {issue['variable']}")
            print(f"   Razón: {issue['reason']}")
        
        # Ejecucion N8N
        send_alert_to_n8n(all_issues)
        
        sys.exit(1) # Bloquea el commit
    else:
        print(f"{Colors.OKGREEN}✅ Escaneo limpio.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
