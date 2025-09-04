from scapy.all import sniff, IP
import pandas as pd
from datetime import datetime
import os
import shutil
import threading
import keyboard
from ai_model import load_model, classify_packets, train_model, model_statistics
from master_control import master_control
import subprocess
import time
import sys
from rules_manager import load_rules
from alerts_manager import add_alert

# ------------------- Configurações -------------------
CAPTURE_INTERVAL = 30  # segundos por ciclo de captura
RETRAIN_INTERVAL = 10   # ciclos antes de re-treinar
HISTORY_PATH = "data/history_features.csv"

os.makedirs("data/logs", exist_ok=True)
captured_packets = []

# Flags de controle compartilhadas com o modo mestre
control_flags = {"paused": False, "stop": False}

# ------------------- Gestão de Regras -------------------

def firewall_decision(packet):
    """
    Decide com base nas regras manuais (rules.json).
    Retorna:
      - blocked_rule -> bloqueado manualmente
      - allowed_rule -> permitido manualmente
      - no_rule -> sem regra, IA decide
    """
    rules = load_rules()
    src_ip = packet["src_ip"]

    if src_ip in rules["blocked"]:
        return "blocked_rule"
    if src_ip in rules["allowed"]:
        return "allowed_rule"

    return "no_rule"

def block_ip_windows(ip_address):
    rule_name = f"BloqueioIA_{ip_address}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"
    ])
    print(f"✅ IP {ip_address} bloqueado no firewall do Windows")

def unblock_ip_windows(ip_address):
    rule_name = f"BloqueioIA_{ip_address}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ])
    print(f"⚠️ IP {ip_address} desbloqueado no firewall do Windows")

def notify_and_ask(ip_address):
    while True:
        resp = input(f"⚠️ Alerta Amarelo: {ip_address} pode ser suspeito. Bloquear? [s/n]: ").lower()
        if resp == "s":
            block_ip_windows(ip_address)
            break
        elif resp == "n":
            print(f"❌ IP {ip_address} não bloqueado.")
            break
        else:
            print("Digite 's' para sim ou 'n' para não.")

# ------------------- Captura e classificação -------------------

def packet_handler(packet):
    if IP in packet:
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "len": len(packet)
        }
        captured_packets.append(data)

def process_and_classify(model):
    if not captured_packets:
        print("Nenhum pacote capturado")
        return None

    df = pd.DataFrame(captured_packets)
    df['minute'] = pd.to_datetime(df['time']).dt.floor('min')
    grouped = df.groupby(['src', 'minute']).agg(
        pkt_count=('len', 'count'),
        avg_pkt_len=('len', 'mean'),
        bytes_sum=('len', 'sum'),
        dst_ports_count=('dst', 'nunique')
    ).reset_index()

    grouped = grouped.dropna()
    grouped = grouped.replace([float("inf"), float("-inf")], None).dropna()
    grouped = grouped.drop_duplicates()

    if grouped.empty:
        print("⚠️ Nenhum dado válido após limpeza, ciclo descartado.")
        return None

    classified_df = classify_packets(grouped, model)

    if os.path.exists(HISTORY_PATH):
        classified_df.to_csv(HISTORY_PATH, mode="a", header=False, index=False)
    else:
        classified_df.to_csv(HISTORY_PATH, index=False)

    for idx, row in classified_df.iterrows():
        src_ip = row['src']

        # Verifica se o IP está em regras manuais
        decision = firewall_decision({"src_ip": src_ip})

        log_line = f"{row['minute']} | {src_ip} | IA level: {row['level']} | decision: {decision} | pkt_count: {row['pkt_count']} \n"
        with open("data/logs/firewall_log.txt", "a") as f:
            f.write(log_line)

        # Se a decisão foi manual, respeita a regra
        if decision == "blocked_rule":
            block_ip_windows(src_ip)
            continue
        elif decision == "allowed_rule":
            print(f"✅ IP {src_ip} permitido manualmente, ignorando decisão da IA.")
            continue

        # Caso contrário, segue pela IA
        if row['level'] == "Amarelo":
            add_alert(src_ip)
        elif row['level'] == "Vermelho":
            block_ip_windows(src_ip)

    return classified_df

# ------------------- Re-treinamento -------------------

def retrain_model(cycle_count, old_model):
    if not os.path.exists(HISTORY_PATH):
        print("⚠️ Nenhum histórico disponível para re-treinamento.")
        return None

    df = pd.read_csv(HISTORY_PATH)
    if df.empty:
        print("⚠️ Histórico vazio, não é possível re-treinar.")
        return None

    df = df.tail(5000)

    if os.path.exists("data/models/ia_model.pkl"):
        os.makedirs("data/models", exist_ok=True)
        shutil.copy("data/models/ia_model.pkl", "data/models/ia_model_prev.pkl")

    print("🔄 Re-treinando IA com últimos 5000 registros...")
    new_model = train_model(df, model_path="data/models/ia_model.pkl")

    stats_old = model_statistics(df, old_model)
    stats_new = model_statistics(df, new_model)

    csv_path = "data/logs/retrain_log.csv"
    df_csv = pd.DataFrame([{
        "timestamp": datetime.now(),
        "old_score": stats_old["mean_score"],
        "new_score": stats_new["mean_score"]
    }])

    if os.path.exists(csv_path):
        df_csv.to_csv(csv_path, mode='a', header=False, index=False)
    else:
        df_csv.to_csv(csv_path, index=False)

    log_line = f"""
=== Re-treino ciclo {cycle_count} ===
ANTIGO -> média: {stats_old['mean_score']:.4f}, std: {stats_old['std_score']:.4f}, V:{stats_old['count_verde']} A:{stats_old['count_amarelo']} R:{stats_old['count_vermelho']}
NOVO   -> média: {stats_new['mean_score']:.4f}, std: {stats_new['std_score']:.4f}, V:{stats_new['count_verde']} A:{stats_new['count_amarelo']} R:{stats_new['count_vermelho']}
--------------------------------------------
"""
    with open("data/logs/retrain_log.txt", "a") as f:
        f.write(log_line)
    print(log_line)

    return new_model

# ------------------- Firewall automático -------------------

def run_firewall():
    print("🚀 Firewall IA iniciado (modo automático)")
    print("Dica: pressione 'm' a qualquer momento para entrar no modo mestre.")

    model = load_model("data/models/ia_model.pkl")
    cycle_count = 0

    # Thread que escuta o atalho para entrar no modo mestre
    def listen_for_master():
        while True:
            keyboard.wait("|")
            print("\n Atalho detectado -> entrando no Modo Mestre... \n")
            key_input = input("Digite a chave mestra: ")
            result = master_control(key_input, control_flags)
            if result:
                nonlocal model
                model = result
            print("\nRetornando ao Firewall automático...\n")

    threading.Thread(target=listen_for_master, daemon=True).start()

    try:
        while not control_flags['stop']:
            if control_flags['paused']:
                print("⏸️ Firewall pausado. Aguardando retomada...")
                while control_flags['paused']:
                    time.sleep(1)

            print(f"\n📡 Capturando pacotes por {CAPTURE_INTERVAL} segundos...")
            sniff(prn=packet_handler, timeout=CAPTURE_INTERVAL)

            process_and_classify(model)
            captured_packets.clear()
            cycle_count += 1

            if cycle_count % RETRAIN_INTERVAL == 0:
                new_model = retrain_model(cycle_count, model)
                if new_model:
                    model = new_model
                    print("✅ IA atualizada com sucesso!")

            print(f"➡️ Próximo ciclo iniciando em {CAPTURE_INTERVAL} segundos...\n")
            time.sleep(CAPTURE_INTERVAL)

        print("🛑 Firewall desligado pelo modo mestre.")

    except KeyboardInterrupt:
        print("\n🛑 Firewall IA interrompido manualmente")

# ------------------- Entrada -------------------

if __name__ == "__main__":
    if "--mestre" in sys.argv:
        print("🛠️ Entrando no Modo Mestre...")
        key_input = input("Digite a chave mestra: ")
        master_control(key_input, control_flags)
    else:
        run_firewall()
