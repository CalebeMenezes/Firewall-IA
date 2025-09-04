import json
from datetime import datetime
import os

AUDIT_FILE = "data/audit_log.json"

def load_audit_log():
    """Carrega o log de auditoria, retorna lista vazia se não existir ou corrompido."""
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_audit_log(logs):
    """Salva a lista de logs em JSON, criando pasta se necessário."""
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    with open(AUDIT_FILE, "w") as f:
        json.dump(logs, f, indent=4)

def log_action(user, role, action, ip):
    """Adiciona uma ação ao log."""
    logs = load_audit_log()
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "role": role,
        "action": action,
        "target": ip   # renomeei de 'ip' para 'target' se quiser algo mais genérico
    })
    save_audit_log(logs)
