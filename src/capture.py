from scapy.all import sniff, IP
import pandas as pd
from datetime import datetime
import os

# Cria pasta data se nao existir
if not os.path.exists("data"):
    os.makedirs("data")

# Lista global para armazenar pacotes
captured_packets = []

def packet_handler(packet):
    if IP in packet:
        data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "len": len(packet)
        }
        print(data)  # debug inicial
        captured_packets.append(data)

def start_capture(limit=500):
    print("🔎 Capturando pacotes...")
    sniff(prn=packet_handler, count=limit)
    print("✅ Captura finalizada")

    # Confirma que capturamos pacotes
    if not captured_packets:
        print("⚠️ Nenhum pacote capturado! Verifique a rede ou aumente o limite.")
        return

    # Salvar pacotes crus em CSV
    df = pd.DataFrame(captured_packets)
    df.to_csv("data/capture.csv", index=False)
    print("📁 Dados salvos em data/capture.csv")

    # --- Extração de features básicas ---
    df['time'] = pd.to_datetime(df['time'])
    df['minute'] = df['time'].dt.floor('T')  # agrupar por minuto
    grouped = df.groupby(['src', 'minute']).agg(
        pkt_count=('len', 'count'),
        avg_pkt_len=('len', 'mean'),
        bytes_sum=('len', 'sum'),
        dst_ports_count=('dst', 'nunique')
    ).reset_index()

    grouped.to_csv("data/features.csv", index=False)
    print("📁 Features básicas salvas em data/features.csv")

if __name__ == "__main__":
    start_capture()
