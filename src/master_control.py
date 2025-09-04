import subprocess
import os
import shutil
from ai_model import load_model

# Chave mestra segura
MASTER_KEY = "123456"

# ------------------- Funções auxiliares -------------------

def unblock_ip_windows(ip_address):
    """Remove regra de bloqueio no Windows"""
    rule_name = f"BloqueioIA_{ip_address}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ])
    print(f"⚠️ IP {ip_address} desbloqueado.")

def list_blocked_ips():
    """Lista todos os IPs bloqueados pela IA"""
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=BloqueioIA_*"],
        capture_output=True, text=True
    )
    blocked_ips = []
    for line in result.stdout.splitlines():
        if "RemoteIP:" in line:
            blocked_ips.append(line.split(":")[1].strip())
    return blocked_ips

# ------------------- Função mestre -------------------

def master_control(key_input, control_flags):
    """Ativa o modo mestre para desbloqueio, reversão de IA e controle do firewall"""
    if key_input != MASTER_KEY:
        print("❌ Chave incorreta! Ação não permitida.")
        return None

    print("🔑 Modo mestre ativado!")

    model = None
    while True:
        print("\n=== MENU MESTRE ===")
        print("0: Sair do modo mestre e voltar ao firewall automático")
        print("1: Desbloquear IPs")
        print("2: Reverter modelo da IA")
        print("3: Pausar/Retomar firewall")
        print("4: Desligar firewall")
        choice = input("Escolha uma opção: ").strip()

        if choice == "0":
            print("🔄 Saindo do modo mestre. Retornando ao firewall automático...")
            break

        elif choice == "1":
            blocked_ips = list_blocked_ips()
            if blocked_ips:
                print("\nIPs atualmente bloqueados:")
                for i, ip in enumerate(blocked_ips):
                    print(f"{i+1}. {ip}")
                indices = input("Digite números separados por vírgula (ou 'all' para todos): ")
                if indices.strip().lower() == "all":
                    for ip in blocked_ips:
                        unblock_ip_windows(ip)
                else:
                    for idx in indices.split(","):
                        idx = int(idx)-1
                        if 0 <= idx < len(blocked_ips):
                            unblock_ip_windows(blocked_ips[idx])
            else:
                print("Nenhum IP bloqueado.")

        elif choice == "2":
            prev_model_path = "data/models/ia_model_prev.pkl"
            active_model_path = "data/models/ia_model.pkl"
            if os.path.exists(prev_model_path):
                shutil.copy(active_model_path, "data/models/ia_model_backup.pkl")
                shutil.copy(prev_model_path, active_model_path)
                model = load_model(active_model_path)
                print("✅ IA revertida para a versão anterior!")
            else:
                print("❌ Nenhum backup disponível.")

        elif choice == "3":
            control_flags['paused'] = not control_flags['paused']
            if control_flags['paused']:
                print("⏸️ Firewall pausado")
            else:
                print("▶️ Firewall retomado")

        elif choice == "4":
            control_flags['stop'] = True
            print("🛑 Firewall será desligado")
            break

        else:
            print("❌ Opção inválida, tente novamente.")

    return model
