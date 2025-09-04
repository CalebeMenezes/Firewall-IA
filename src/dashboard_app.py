import os
import time
import platform
import subprocess
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime, timedelta
from master_control import MASTER_KEY  # sua chave mestra
from main import control_flags  # flags compartilhadas com main.py
import rules_manager
import alerts_manager
import streamlit as st
from audit_manager import log_action, load_audit_log
import re
import audit_manager
import bcrypt
from ai_model import apply_feedback

# ----------------------- brute force --------------------------------
if "login_attempts" not in st.session_state:
    st.session_state["login_attempts"] = 0
if "login_blocked_until" not in st.session_state:  # <-- corrigido aqui
    st.session_state["login_blocked_until"] = None
#--------------------- Usuarios e permissoes ------------------------
USERS = {
    "admin": {"password_hash": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()), "role": "admin"},
    "viewer": {"password_hash": bcrypt.hashpw("viewer123".encode(), bcrypt.gensalt()), "role": "viewer"}
}

# ------------------------ Inicialização da sessão ---------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["user"] = None
    st.session_state["role"] = None

# -------------------- Tela de login ---------------------------------
if not st.session_state["logged_in"]:
    st.markdown(
        """
        <style>
        /* Fundo degradê animado */
        .stApp {
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #1f1c2c, #928dab);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
        }

        @keyframes gradientBG {
            0% {background-position: 0% 50%;}
            50% {background-position: 100% 50%;}
            100% {background-position: 0% 50%;}
        }

        /* Box de login centralizada com fade-in e fade-out */
        .login-box {
            width: 700px;
            padding: 2rem;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(12px);
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            text-align: flex;
            color: white;
            opacity: 0;
            animation: fadeIn 1s forwards;
            transition: opacity 0.8s ease;
        }

        .login-box.fade-out {
            opacity: 0;
        }

        @keyframes fadeIn {
            to { opacity: 1; }
        }

        .login-title {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.3rem;
            text-align: center;
        }

        .login-subtitle {
            font-size: 1rem;
            color: #ddd;
            margin-bottom: 2rem;
            text-align: center;
        }

        /* Input fields */
        div.stTextInput > label {
            color: white;
            font-weight: bold;
           
        }
        div.stTextInput > div > input {
            background-color: rgba(255,255,255,0.15);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 0.5rem 1rem;
        }
        div.stTextInput > div > input:focus {
            outline: 2px solid #6a0dad;
        }

        /* Botão Entrar */
        div.stButton > button:first-child {
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
            border-radius: 12px;
            padding: 0.6rem 2rem;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        div.stButton > button:first-child:hover {
            background-color: #45a049;
            transform: scale(1.05);
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    if st.session_state["login_blocked_until"]:
        now = datetime.now()
        if now < st.session_state["login_blocked_until"]:
            remaining = (st.session_state["login_blocked_until"] - now).seconds
            st.warning(f"Muitas tentativas incorretas. Tente novamente em {remaining} segundos.")
            st.stop()
        else:
            st.session_state["login_blocked_until"] = None
            st.session_state["login_attempts"] = 0

    st.markdown("""
    <div class="login-box" id="loginBox">
        <div class="login-title">🔐 Login do Dashboard</div>
        <div class="login-subtitle">Digite suas credenciais para acessar</div>
    """, unsafe_allow_html=True)

    with st.form("login_form"):
            username = st.text_input("Usuário")
            password = st.text_input("Senha", type="password")
            submitted = st.form_submit_button("Entrar")

            if submitted:
                import bcrypt
                if username in USERS and bcrypt.checkpw(password.encode(), USERS[username]["password_hash"]):
                    # Adiciona fade-out e aguarda 0.8s antes de logar
                    st.markdown(
                        """
                        <script>
                        const box = window.parent.document.getElementById("loginBox");
                        box.classList.add("fade-out");
                        setTimeout(() => { window.parent.location.reload(); }, 800);
                        </script>
                        """,
                        unsafe_allow_html=True
                    )
                    st.session_state["logged_in"] = True
                    st.session_state["user"] = username
                    st.session_state["role"] = USERS[username]["role"]
                    st.session_state["login_attempts"] = 0 
                    st.session_state["login_blocked_unitil"] = None
                    st.rerun()
                else:
                    st.session_state["login_attempts"] += 1
                    attempts_left = 3 - st.session_state["login_attempts"]
                    if attempts_left > 0:
                        st.error(f"Usuario ou senha incorretos! Tentativas restantes: {attempts_left}")
                    else:
                        # Bloqueia por 1 minutos
                        st.session_state["login_blocked_until"] = datetime.now() + timedelta(minutes=1)
                        st.error("Muitas tentativas incorretas. Voce foi bloqueado por 1 minuto.")

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


# ------------------ Botão de logout estilizado -------------------------
with st.sidebar:
    if st.session_state["logged_in"]:
        logout_clicked = st.button("Sair", key="logout")
        if logout_clicked:
            st.session_state["logged_in"] = False
            st.session_state["user"] = None
            st.session_state["role"] = None
            st.rerun()

        # Aplica estilo vermelho ao botão logout
        st.markdown('<style>div.stButton > button:first-child {background-color: #e74c3c; color:white; font-weight:bold; border-radius:8px; height:2.5em;}</style>', unsafe_allow_html=True)



# ------------------- Conteudo dashboard ------------------------
 
 
HISTORY_PATH = "data/history_features.csv"
FIREWALL_LOG = "data/logs/firewall_log.txt"
MODEL_CSV = "data/logs/retrain_log.csv"

# ------------------------- Utils ---------------------
@st.cache_data(ttl=2)
def load_history():
    if not os.path.exists(HISTORY_PATH):
        return pd.DataFrame(columns=[
            'src', 'minute', 'pkt_count', 'avg_pkt_len', 'bytes_sum', 'dst_ports_count', 'level', 'score'
        ])
    df = pd.read_csv(HISTORY_PATH)
    if 'minute' in df.columns:
        df['minute'] = pd.to_datetime(df['minute'], errors='coerce')
    df = df.dropna(subset=['src', 'minute', 'pkt_count', 'level'])
    return df

@st.cache_data(ttl=5)
def list_blocked_ips():
    if platform.system() != 'Windows':
        return []
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=BloqueioIA_*"],
            capture_output=True, text=True
        )
        blocked = []
        for line in result.stdout.splitlines():
            if "remoteIP" in line:
                ip = line.split(":", 1)[1].strip()
                if ip and ip != 'Any':
                    blocked.append(ip)
        return blocked
    except Exception:
        return []

# ------------------- Configuração da página -----------------------------
st.set_page_config(page_title="Firewall IA", layout="wide")

# Cabeçalho moderno do Dashboard
st.markdown(
    """
    <div style="display:flex; align-items:center; justify-content:space-between;">
        <h1 style="margin:0;">🚀 Firewall IA</h1>
        <span style="color:gray;">Acompanhe tráfego, alertas, bloqueios e saúde do modelo</span>
    </div>
    """,
    unsafe_allow_html=True
)

if "refresh" not in st.session_state:
    st.session_state["refresh"] = False

# Função para atualizar manualmente o dashboard
def atualizar_dashboard():
    st.session_state["refresh"] = not st.session_state["refresh"]

# Sidebar com estilo responsivo e moderno
with st.sidebar:
    st.markdown("## ⚙️ Configurações do Dashboard")

    with st.expander("Parâmetros de Métricas"):
        window_minutes = st.slider(
            "Janela (minutos) para métricas ao vivo",
            min_value=5,
            max_value=240,
            value=60,
            step=5
        )
        auto_refresh = st.checkbox("Atualizar automaticamente", value=True)
        refresh_sec = st.slider(
            "Intervalo de atualização automática (s)",
            min_value=2,
            max_value=30,
            value=5
        )

    st.markdown("---")
    st.button("🔄 Atualizar agora", on_click=atualizar_dashboard)

if st.session_state["refresh"]:
    pass

# ------------------- Estado do dashboard -----------------------------
if "firewall_process" not in st.session_state:
    st.session_state["firewall_process"] = None

# ------------------- Controle do Firewall -----------------------------
if st.session_state["role"] == "admin":
    st.sidebar.subheader("⚙️ Controle do Firewall")

    # Mostra o status atual
    proc = st.session_state.get("firewall_process")
    firewall_status = "Desligado"
    if proc and proc.poll() is None:
        firewall_status = "Pausado" if st.session_state.get("paused", False) else "Rodando"

    st.sidebar.markdown(f"**📡 Status atual:** `{firewall_status}`")

    # Botões alinhados
    col1, col2, col3 = st.sidebar.columns(3)
    with col1:
        start_firewall = st.button("Iniciar")
    with col2:
        pause_resume = st.button("Pausar/Retomar")
    with col3:
        stop_firewall = st.button("Desligar")

    # ---- Iniciar Firewall ----
    if start_firewall:
        if proc is None or proc.poll() is not None:
            process = subprocess.Popen(["python", "main.py"])
            st.session_state["firewall_process"] = process
            st.session_state["paused"] = False
            st.toast("✅ Firewall iniciado em modo mestre.")
            audit_manager.log_action(
                st.session_state["user"],
                st.session_state["role"],
                "Iniciou o Firewall",
                "-"
            )
        else:
            st.warning("⚠️ Firewall já está rodando.")

    # ---- Pausar / Retomar ----
    if pause_resume:
        if proc and proc.poll() is None:
            st.session_state["paused"] = not st.session_state.get("paused", False)
            if st.session_state["paused"]:
                st.toast("⏸️ Firewall pausado.")
                audit_manager.log_action(
                    st.session_state["user"],
                    st.session_state["role"],
                    "Pausou o Firewall",
                    "-"
                )
            else:
                st.toast("▶️ Firewall retomado.")
                audit_manager.log_action(
                    st.session_state["user"],
                    st.session_state["role"],
                    "Retomou o Firewall",
                    "-"
                )
        else:
            st.warning("⚠️ Firewall não está rodando.")

    # ---- Desligar Firewall ----
    if stop_firewall:
        if proc and proc.poll() is None:
            proc.terminate()
            st.session_state["firewall_process"] = None
            st.session_state["paused"] = False
            st.toast("⛔ Firewall desligado.")
            audit_manager.log_action(
                st.session_state["user"],
                st.session_state["role"],
                "Desligou o Firewall",
                "-"
            )
        else:
            st.warning("⚠️ Firewall não está rodando.")

else:
    st.sidebar.info("👀 Você está no modo *visualizador*. Controles do firewall indisponíveis.")

# ----------------------- Treinamento IA -------------------------------
tab_train = st.sidebar.expander("Treinamento IA", expanded=True)
with tab_train:
    st.subheader("Treinamento e Re-treinamento da IA")

    if st.button("Treinar IA"):
        st.info("Treinamento iniciando...")
        from ai_model import train_model_from_history, load_model
        model = train_model_from_history(HISTORY_PATH)
        st.success("Treinamento conlcuido")

# --------------------- Gestão de Regras ------------------------
st.title("Gestão de Regras")
rules = rules_manager.load_rules()
tab_view, tab_add, tab_remove = st.tabs(["Visualizar Regras", "Adicionar Regra", "Remover Regra"])

# Visualizar regras
with tab_view:
    st.subheader("IPs Bloqueados")
    st.write(rules["blocked"] if rules["blocked"] else "Nenhum IP bloqueado")
    st.subheader("IPs Permitidos")
    st.write(rules["allowed"] if rules["allowed"] else "Nenhum IP permitido")

# Adicionar regra
def validar_ip(ip: str) -> bool:
    padrao = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(padrao, ip):
        return all(0 <= int(octeto) <= 255 for octeto in ip.split('.'))
    return False

with tab_add:
    st.subheader("Adicionar nova regra")
    with st.form("form_add_rule"):
        ip_add = st.text_input("Digite o IP para adicionar")
        rule_type_add = st.radio("Tipo de regra", ["blocked", "allowed"])
        submitted_add = st.form_submit_button("Adicionar IP")
        if submitted_add:
            if not validar_ip(ip_add):
                st.warning("Digite um IP válido (ex: 192.168.0.1).")
            elif rules_manager.add_rule(ip_add, rule_type_add):
                log_action(st.session_state["user"], st.session_state["role"], f"adicionou a {rule_type_add}", ip_add)
                st.success(f"IP {ip_add} adicionado a {rule_type_add}")
            else:
                st.warning(f"IP {ip_add} já está em {rule_type_add}")

# Remover regra
with tab_remove:
    st.subheader("Remover regra existente")
    with st.form("form_remove_rule"):
        rule_type_remove = st.radio("Remover de", ["blocked", "allowed"])
        submitted_remove = st.form_submit_button("Remover IP")
        # Pega a lista de IPs para o tipo escolhido
        ip_options = rules[rule_type_remove] if rules[rule_type_remove] else []
        
        if ip_options:
            ip_remove = st.selectbox("Selecione o IP para remover", ip_options)
            submitted_remove = st.form_submit_button("Remover IP")
            if submitted_remove:
                if rules_manager.remove_rule(ip_remove, rule_type_remove):
                    log_action(st.session_state["user"], st.session_state["role"], f"removeu de {rule_type_remove}", ip_remove)
                    st.success(f"IP {ip_remove} removido de {rule_type_remove}")
                else:
                    st.warning(f"IP {ip_remove} não encontrado em {rule_type_remove}")
        else:
            st.info("Nenhum IP disponível para remover.")

# ----------------------- auditoria de açoes -----------------------------
st.subheader("Auditoria de ações")

audit_logs = load_audit_log()
if audit_logs:
    audit_df = pd.DataFrame(audit_logs)
    st.dataframe(audit_df.sort_values('timestamp', ascending=False))
else:
    st.info("Nenhuma ação registrada ainda")


# --------------------------- Alertas Inteligentes ----------------------
st.subheader("Alertas em tempo real")

alerts = alerts_manager.load_alerts()

if alerts:
    # Cabeçalho do painel
    col_ip, col_ocorr, col_first, col_block, col_ignore = st.columns([2,1,2,1,1])
    col_ip.markdown("**IP**")
    col_ocorr.markdown("**Ocorrências**")
    col_first.markdown("**Primeiro visto**")
    col_block.markdown("**Bloquear**")
    col_ignore.markdown("**Ignorar**")

    for ip, data in alerts.items():
        ocorrencias = data.get("ocorrencias", 1)
        first_seen = data.get("first_seen", "Desconhecido")

        col_ip, col_ocorr, col_first, col_block, col_ignore = st.columns([2,1,2,1,1])
        col_ip.write(ip)
        col_ocorr.write(ocorrencias)
        col_first.write(first_seen)

        # Botão Bloquear
        if col_block.button("Bloquear", key=f"block_{ip}"):
            rules_manager.add_rule(ip, "blocked")
            alerts_manager.remove_alert(ip)
            st.experimental_rerun()  # Recarrega o dashboard para atualizar a lista

        # Botão Ignorar
        if col_ignore.button("Ignorar", key=f"ignore_{ip}"):
            alerts_manager.remove_alert(ip)
            st.experimental_rerun()  # Recarrega o dashboard para atualizar a lista
else:
    st.info("Nenhum alerta no momento")


# ------------------- Carregamento e métricas --------------------------
df = load_history()
now = datetime.now()
window_start = now - timedelta(minutes=window_minutes)
recent = df[df['minute'] >= window_start].copy() if not df.empty else df

col1, col2, col3, col4 = st.columns(4)
col1.metric("Pacotes (janela)", int(recent['pkt_count'].sum()) if not recent.empty else 0)
col2.metric("IPs únicos (janela)", recent['src'].nunique() if not recent.empty else 0)
col3.metric("Alertas amarelos (janela)", int((recent['level']=="Amarelo").sum()) if not recent.empty else 0)
col4.metric("Bloqueios vermelhos (janela)", int((recent['level']=="Vermelho").sum()) if not recent.empty else 0)

# --------------------------- Gráficos --------------------------------
st.subheader("Tráfego por minutos (top IPs)")

if not recent.empty:
    # Seleciona os top IPs
    top_ips = recent.groupby('src')['pkt_count'].sum().sort_values(ascending=False).head(8).index.tolist()
    plot_df = recent[recent['src'].isin(top_ips)].groupby(['minute','src'], as_index=False)['pkt_count'].sum()
    
    # Transformar para linhas suavizadas e cores dinâmicas
    fig = px.line(
        plot_df,
        x='minute',
        y='pkt_count',
        color='src',
        markers=True,
        line_shape='spline',
        hover_data={'minute':True, 'pkt_count':True, 'src':True},
        color_discrete_sequence=px.colors.qualitative.D3
    )
    fig.update_traces(mode='lines+markers', marker=dict(size=6), line=dict(width=3))
    fig.update_layout(
        height=400,
        margin=dict(l=20,r=20,t=40,b=20),
        template='plotly_dark',
        legend_title_text='IP'
    )
    
    # Container para atualização em tempo real
    chart_placeholder = st.empty()
    chart_placeholder.plotly_chart(fig, use_container_width=True)

# Distribuição de níveis e Top Vermelhos
colA, colB = st.columns(2)

with colA:
    st.subheader("🧭 Distribuição de níveis (janela)")
    if not recent.empty:
        lvl = recent['level'].value_counts().rename_axis('level').reset_index(name='count')
        color_map = {"Verde":"green", "Amarelo":"gold", "Vermelho":"red"}
        fig2 = px.bar(
            lvl,
            x='level',
            y='count',
            text='count',
            color='level',
            color_discrete_map=color_map
        )
        fig2.update_traces(textposition='outside')
        fig2.update_layout(height=380, template='plotly_dark', margin=dict(l=10,r=10,t=30,b=10))
        st.plotly_chart(fig2, use_container_width=True)

with colB:
    st.subheader("🚨 Top IPs Vermelho (janela)")
    if not recent.empty:
        reds = recent[recent['level']=="Vermelho"]
        top_reds = reds.groupby('src')['pkt_count'].sum().sort_values(ascending=False).head(10).rename_axis('src').reset_index(name='pkt_count')
        if not top_reds.empty:
            fig3 = px.bar(
                top_reds,
                x='src',
                y='pkt_count',
                text='pkt_count',
                color='pkt_count',
                color_continuous_scale='reds'
            )
            fig3.update_traces(textposition='outside')
            fig3.update_layout(height=380, template='plotly_dark', margin=dict(l=10,r=10,t=30,b=10))
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("Nenhum vermelho na janela.")

# ----------------------- Log live do firewall ---------------------------
st.subheader("📜 Log do Firewall (últimas entradas)")

log_container = st.empty()

# Função para colorir linhas conforme tipo de evento
def format_log_line(line):
    line = line.strip()
    if "Bloqueado" in line or "Desligado" in line:
        color = "#FF4C4C"  # vermelho
    elif "Iniciado" in line or "Ativado" in line:
        color = "#4CAF50"  # verde
    elif "Pausado" in line:
        color = "#FFD700"  # dourado
    else:
        color = "#FFFFFF"  # branco
    return f'<div style="color:{color}; font-family:monospace; margin:2px 0;">{line}</div>'

# Função para exibir logs com estilo moderno e scroll automático
def display_firewall_logs(file_path, max_lines=30):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-max_lines:]
        formatted_lines = "".join([format_log_line(line) for line in lines])
        log_container.markdown(
            f'''
            <div style="
                background: rgba(0,0,0,0.6);
                padding: 1rem;
                border-radius: 15px;
                max-height: 400px;
                overflow-y: auto;
                box-shadow: 0 8px 30px rgba(0,0,0,0.5);
                transition: all 0.5s ease;
            ">
                {formatted_lines}
            </div>
            <script>
                const logDiv = window.parent.document.querySelector('div[style*="max-height: 400px"]');
                if (logDiv) {{
                    logDiv.scrollTop = logDiv.scrollHeight;
                }}
            </script>
            ''',
            unsafe_allow_html=True
        )
    else:
        log_container.info("Sem logs recentes do firewall.")

# Atualização automática a cada 2 segundos (tempo real)
for _ in range(1):  # apenas para demo, pode usar st_autorefresh para contínuo
    display_firewall_logs(FIREWALL_LOG)
    # time.sleep(2)  # se quiser loop contínuo, descomente

# ---------------------------- IPs bloqueados ----------------------------
st.subheader("IPs bloqueados no firewall")
if platform.system() == 'Windows':
    bkl = list_blocked_ips()
    if bkl:
        st.write("Total:", len(bkl))
        st.code("\n".join(bkl))
    else:
        st.info("Nenhum IP bloqueado pela IA até o momento")
else:
    st.warning("Listagem de IPs bloqueados só disponível no Windows")

# ---------------------------- Gráfico de performance -------------------
st.subheader("📊 Comparativo de desempenho da IA")

if os.path.exists(MODEL_CSV):
    df_model = pd.read_csv(MODEL_CSV)
    if not df_model.empty:
        df_model['timestamp'] = pd.to_datetime(df_model['timestamp'], errors='coerce')

        # Gráfico moderno com linha suavizada e área preenchida
        fig4 = px.line(
            df_model,
            x="timestamp",
            y=["old_score", "new_score"],
            labels={"value": "Score", "variable": "Versão"},
            title="Evolução da performance (antiga vs nova)",
            markers=True,
            template="plotly_dark",  # Tema escuro moderno
            color_discrete_map={
                "old_score": "#FF4C4C",   # Vermelho para antigo
                "new_score": "#4CAF50"    # Verde para novo
            }
        )

        # Adiciona preenchimento suave entre linhas
        fig4.update_traces(mode="lines+markers", line=dict(shape="spline", width=3), marker=dict(size=6))
        fig4.update_layout(
            height=400,
            margin=dict(l=10,r=10,t=40,b=10),
            legend=dict(title="", orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            hovermode="x unified",
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)"
        )

        # Sombreamento entre linhas para melhor visualização
        fig4.update_traces(fill='tonexty', opacity=0.1)

        st.plotly_chart(fig4, use_container_width=True)
    else:
        st.info("Ainda não há dados de comparativo disponíveis.")
else:
    st.warning("O arquivo de comparativo (.csv) ainda não foi gerado.")

# ---------------------------- Ultimos eventos ---------------------------
tab_feedback = st.tabs(["Últimos Eventos", "Correções IA"])[1]  # segunda aba

with tab_feedback:
    st.subheader("📦 Corrigir classificação de pacotes")
    last_events = pd.read_csv(HISTORY_PATH).sort_values('minute', ascending=False).head(20)

    if last_events.empty:
        st.info("Nenhum evento recente para corrigir.")
    else:
        # Container principal com scroll
        with st.container():
            st.markdown(
                '<div style="max-height:600px; overflow-y:auto; padding-right:5px;">',
                unsafe_allow_html=True
            )

            for idx, row in last_events.iterrows():
                level_color = {
                    "Verde": "#4CAF50",
                    "Amarelo": "#FFC107",
                    "Vermelho": "#FF4C4C"
                }.get(row['level'], "#999")

                # Cada evento dentro de um expander
                with st.expander(f"IP: {row['src']} | Nível: {row['level']} | Score: {row['score']}", expanded=False):
                    st.markdown(
                        f"<div style='padding:0.5rem 0;'><strong>IP:</strong> {row['src']}<br>"
                        f"<strong>Score:</strong> {row['score']}<br>"
                        f"<strong>Nível atual:</strong> <span style='color:{level_color}; font-weight:bold;'>{row['level']}</span></div>",
                        unsafe_allow_html=True
                    )

                    # Radio + botão para correção
                    cols = st.columns([2, 1])
                    new_level = cols[0].radio(
                        "Corrigir nível",
                        ["Verde", "Amarelo", "Vermelho"],
                        index=["Verde", "Amarelo", "Vermelho"].index(row['level']),
                        key=f"level_{idx}"
                    )
                    if cols[1].button("✅ Aplicar", key=f"correct_{idx}", use_container_width=True):
                        apply_feedback(row, new_level)
                        st.success(f"Alteração aplicada para IP {row['src']}")

            st.markdown("</div>", unsafe_allow_html=True)

# ------------------------ Rodapé ---------------------------------------
st.caption("Atualiza automaticamente.")
