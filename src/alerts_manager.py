import json
import os
from datetime import datetime

ALERTS_FILE = "alerts.json"

# -------------------- Funções de alerta --------------------

def load_alerts():
    """
    Carrega os alertas do arquivo JSON.
    Retorna um dicionário: {ip: {"first_seen": str, "ocorrencias": int}}
    """
    if not os.path.exists(ALERTS_FILE):
        return {}
    try:
        with open(ALERTS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_alerts(alerts):
    """
    Salva os alertas no arquivo JSON.
    """
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

def add_alert(ip):
    """
    Adiciona um alerta para um IP. Se já existir, incrementa ocorrencias.
    """
    alerts = load_alerts()
    if ip in alerts:
        alerts[ip]["ocorrencias"] += 1
    else:
        alerts[ip] = {
            "first_seen": datetime.now().isoformat(),
            "ocorrencias": 1
        }
    save_alerts(alerts)

def remove_alert(ip):
    """
    Remove um alerta de um IP.
    """
    alerts = load_alerts()
    if ip in alerts:
        del alerts[ip]
        save_alerts(alerts)
