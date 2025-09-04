import json
import os

RULES_FILE = "rules.json"

def load_rules():
    """Carrega as regras do arquivo JSON, criando-o se não existir."""
    if not os.path.exists(RULES_FILE):
        os.makedirs(os.path.dirname(RULES_FILE) or ".", exist_ok=True)
        rules = {"blocked": [], "allowed": []}
        save_rules(rules)  # cria o arquivo no disco
        return rules
    with open(RULES_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # Caso o arquivo esteja corrompido, reseta para padrão
            rules = {"blocked": [], "allowed": []}
            save_rules(rules)
            return rules

def save_rules(rules):
    """Salva as regras no arquivo JSON."""
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

def add_rule(ip, rule_type="blocked"):
    """Adiciona um IP à lista de regras."""
    rules = load_rules()
    if ip not in rules.get(rule_type, []):
        rules[rule_type].append(ip)
        save_rules(rules)
        return True
    return False

def remove_rule(ip, rule_type="blocked"):
    """Remove um IP da lista de regras."""
    rules = load_rules()
    if ip in rules.get(rule_type, []):
        rules[rule_type].remove(ip)
        save_rules(rules)
        return True
    return False
