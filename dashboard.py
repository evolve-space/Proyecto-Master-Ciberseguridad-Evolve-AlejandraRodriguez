import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import subprocess
import os
import streamlit_authenticator as stauth
from dotenv import load_dotenv

load_dotenv()

def hora_local():
    return datetime.now() + timedelta(hours=2)

HETZNER_TOKEN = os.getenv("HETZNER_TOKEN")
HETZNER_FIREWALL_ID = os.getenv("HETZNER_FIREWALL_ID")
API_KEY = os.getenv("API_KEY")
HEADERS = {"X-API-Key": API_KEY}

# ── Configuración ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Noctua. — Autonomous Security Operations",
    page_icon="/root/asoar/static/favicon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
[data-testid="stForm"] {
    max-width: 420px !important;
    margin: 0 auto !important;
    padding: 32px !important;
    background: white !important;
    border-radius: 12px !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1) !important;
    border-top: 3px solid #1a3a6c !important;
}
</style>
""", unsafe_allow_html=True)

# ── Autenticación ──────────────────────────────────────────────────────────────
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_NAME = os.getenv("AUTH_NAME", "Administrador")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "noctua2026")

credentials = {
    "usernames": {
        AUTH_USERNAME: {
            "name": AUTH_NAME,
            "password": stauth.Hasher.hash(AUTH_PASSWORD)
        }
    }
}

authenticator = stauth.Authenticate(
    credentials,
    "noctua_cookie",
    "noctua_key_2026",
    cookie_expiry_days=1
)

# Mostrar logo solo si no está autenticado
if not st.session_state.get("authentication_status"):
    _, col_center, _ = st.columns([1, 2, 1])
    with col_center:
        with open("/root/asoar/static/noctua_logo.svg", "r") as f:
            logo_svg = f.read()
        st.markdown(f'<div style="text-align:center; margin-bottom:24px;">{logo_svg}</div>', unsafe_allow_html=True)

authenticator.login(location="main")
name = st.session_state.get("name")
authentication_status = st.session_state.get("authentication_status")
username = st.session_state.get("username")

if authentication_status == False:
    st.error("Usuario o contraseña incorrectos")
    st.stop()

if authentication_status is None:
    st.stop()


# Notificaciones en tiempo real
notif_file = "/root/asoar/notificaciones.json"
if os.path.exists(notif_file):
    try:
        with open(notif_file, "r") as f:
            notifs = json.load(f)
        no_leidas = [n for n in notifs if not n.get("leida")]
        for n in no_leidas:
            st.toast(f"IP bloqueada: {n['ip']}")
            n["leida"] = True
        if no_leidas:
            with open(notif_file, "w") as f:
                json.dump(notifs, f, indent=2)
    except:
        pass

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""<style>
    :root { color-scheme: light !important; }
    html, body, [class*="css"], [data-testid="stAppViewContainer"] {
        color-scheme: light !important;
        background-color: #f5f6fa !important;
        color: #2c3e50 !important;
    }
    [data-testid="stHeader"] { background-color: #f5f6fa !important; }
    .main, .stApp { background-color: #f5f6fa; }
    section[data-testid="stSidebar"] { background-color: #ffffff !important; border-right: 1px solid #e0e0e0; }
    section[data-testid="stSidebar"] * { color: #2c3e50 !important; }
    section[data-testid="stSidebar"] label { color: #2c3e50 !important; font-weight: 500; }
    section[data-testid="stSidebar"] .stButton > button[kind="secondary"] {
        background: transparent !important;
        color: #2c3e50 !important;
        border: 1px solid #e0e0e0 !important;
        width: 100% !important;
        text-align: left !important;
        margin-bottom: 4px !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="secondary"] p {
        color: #2c3e50 !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: #1a3a6c !important;
        color: white !important;
        border: none !important;
        width: 100% !important;
        text-align: left !important;
        margin-bottom: 4px !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] p {
        color: white !important;
    }
    section[data-testid="stSidebar"] .stButton > button:hover {
        opacity: 0.85 !important;
    }
    .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.07); margin-bottom: 16px; border-top: 3px solid #2c3e50; transition: transform 0.2s ease, box-shadow 0.2s ease; }
    .metric-card:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0,0,0,0.12) !important; }
    .metric-card.danger  { border-top-color: #e74c3c; }
    .metric-card.warning { border-top-color: #f39c12; }
    .metric-card.success { border-top-color: #27ae60; }
    .metric-card.info    { border-top-color: #2980b9; }
    .metric-value { font-size: 2rem; font-weight: 700; color: #2c3e50; margin: 4px 0 0 0; animation: fadeInUp 0.5s ease; }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .metric-label { font-size: 0.75rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; margin: 0; }
    .section-header { font-size: 0.8rem; font-weight: 700; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; padding: 16px 0 8px 0; border-bottom: 1px solid #ecf0f1; margin-bottom: 16px; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.72rem; font-weight: 600; }
    .badge-green  { background: #d5f5e3; color: #1e8449; }
    .badge-red    { background: #fadbd8; color: #922b21; }
    .badge-yellow { background: #fef9e7; color: #9a7d0a; }
    .service-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 0.9rem; color: #2c3e50; }
    .stButton > button { background: #2c3e50; color: white; border: none; border-radius: 6px; font-weight: 600; }
    .stButton > button:hover { background: #1a252f; color: white; }
    @keyframes parpadeo {
        0%, 100% { background-color: #fff5f5; }
        50% { background-color: #ffd5d5; }
    }
    .critica-alert {
        animation: parpadeo 1.2s infinite;
        border-top: 3px solid #c0392b !important;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.07);
        margin-bottom: 16px;
    }

    div[data-testid="stForm"] {
        max-width: 420px !important;
        margin: 0 auto !important;
    }

    input[type="text"], input[type="password"] {
        border: 1px solid #bdc3c7 !important;
        border-radius: 6px !important;
        padding: 8px 12px !important;
    }
    input[type="text"]:focus, input[type="password"]:focus {
        border: 1px solid #1a3a6c !important;
        box-shadow: 0 0 0 2px rgba(26,58,108,0.15) !important;
    }
    div[data-baseweb="input"] {
        border: 1px solid #bdc3c7 !important;
        border-radius: 6px !important;
    }
    div[data-baseweb="base-input"]:hover {
        border: 1px solid #1a3a6c !important;
    }

</style>
""", unsafe_allow_html=True)

# ── Leer alertas reales de Wazuh ───────────────────────────────────────────────
@st.cache_data(ttl=30)
def cargar_alertas_wazuh():
    try:
        result = subprocess.run(
            ["bash", "-c", "find /var/ossec/logs/alerts/ -name '*.json' | xargs cat 2>/dev/null"],
            capture_output=True, text=True
        )
        lineas = result.stdout.strip().split("\n")
        alertas = []
        for linea in lineas:
            try:
                a = json.loads(linea)
                alertas.append({
                    "timestamp": pd.to_datetime(a.get("timestamp", ""), utc=True, errors="coerce"),
                    "tipo": a.get("rule", {}).get("description", "Desconocido"),
                    "nivel": int(a.get("rule", {}).get("level", 0)),
                    "ip": a.get("data", {}).get("srcip", a.get("agent", {}).get("ip", "N/A")),
                    "agente": a.get("agent", {}).get("name", "master"),
                    "id_regla": str(a.get("rule", {}).get("id", "")),
                    "accion": "BLOQUEADA" if int(a.get("rule", {}).get("level", 0)) >= 10 else "MONITOREADA"
                })
            except:
                continue
        df = pd.DataFrame(alertas)
        if not df.empty:
            df = df.dropna(subset=["timestamp"])
            df["timestamp"] = df["timestamp"].dt.tz_localize(None)
            df = df.sort_values("timestamp", ascending=False)
        return df
    except Exception as e:
        return pd.DataFrame()

# ── IPs bloqueadas en Hetzner ──────────────────────────────────────────────────
@st.cache_data(ttl=30)
def cargar_ips_hetzner():
    try:
        headers = {"Authorization": f"Bearer {HETZNER_TOKEN}"}
        r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers, timeout=5)
        if r.status_code == 200:
            reglas = r.json().get("firewall", {}).get("rules", [])
            return [
                reg.get("source_ips", [""])[0].replace("/32", "")
                for reg in reglas
                if reg.get("direction") == "in" and "ASOAR" in reg.get("description", "")
            ]
    except:
        pass
    return []

df = cargar_alertas_wazuh()
ips_bloqueadas = cargar_ips_hetzner()

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    with open("/root/asoar/static/noctua_logo.svg", "r") as f:
        logo_svg = f.read()
    st.markdown(logo_svg, unsafe_allow_html=True)
    st.markdown("---")
    opciones = [
        "Panel General",
        "Alertas y Eventos",
        "IPs Bloqueadas",
        "Endpoints",
        "Normativas",
        "Deteccion APT",
        "Simulador de Ataques",
        "Informes",
        "Estado del Sistema",
        "About"
    ]

    if "pagina" not in st.session_state:
        st.session_state.pagina = "Panel General"

    for opcion in opciones:
        activo = st.session_state.pagina == opcion
        if st.button(
            opcion,
            key=f"nav_{opcion}",
            use_container_width=True,
            type="primary" if activo else "secondary"
        ):
            st.session_state.pagina = opcion
            st.rerun()

    pagina = st.session_state.pagina
    st.markdown("---")
    if st.session_state.get("authentication_status"):
        authenticator.logout("Cerrar sesion", "sidebar", key="logout_sidebar")
    st.markdown("---")
    st.markdown(f"**Sesion:** `{hora_local().strftime('%d/%m/%Y %H:%M')}`")
    if st.button("Actualizar datos", key="btn_actualizar"):
        st.cache_data.clear()
        st.rerun()

# Breadcrumb estilo SOC
alertas_activas = len(df[df["nivel"] >= 10]) if not df.empty else 0
color_live = "#e74c3c" if alertas_activas > 0 else "#27ae60"

st.markdown(f"""
<div style="font-size:0.78rem; color:#7f8c8d; margin-bottom:12px; padding:8px 16px;
            background:white; border-radius:6px; border:1px solid #ecf0f1;
            display:flex; justify-content:space-between; align-items:center;
            box-shadow:0 1px 3px rgba(0,0,0,0.05);">
    <div>
        <span style="color:#1a3a6c; font-weight:700; letter-spacing:1px">NOCTUA.</span>
        <span style="margin:0 8px; color:#bdc3c7">›</span>
        <span style="color:#2c3e50; font-weight:500; letter-spacing:0.5px">{pagina.upper()}</span>
        <span style="margin-left:12px">
            <span style="display:inline-block; width:7px; height:7px; border-radius:50%;
                         background:{color_live}; margin-right:4px; vertical-align:middle"></span>
            <span style="color:{color_live}; font-weight:600; font-size:0.72rem">LIVE</span>
        </span>
    </div>
    <div style="display:flex; gap:16px; align-items:center;">
        <span style="background:#f39c12; color:white; padding:2px 8px; border-radius:3px;
                     font-size:0.7rem; font-weight:700; letter-spacing:0.5px">TLP:AMBER</span>
        <span style="color:#7f8c8d">Analista: <strong style="color:#2c3e50">{name}</strong></span>
        <span style="color:#7f8c8d">{hora_local().strftime('%d/%m/%Y %H:%M')}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PANEL GENERAL
# ══════════════════════════════════════════════════════════════════════════════
if pagina == "Panel General":
    st.markdown("## Panel General")
    st.markdown(f"*Ultima actualizacion: {hora_local().strftime('%d/%m/%Y %H:%M:%S')}*")
    st.markdown("---")

    if df.empty:
        st.warning("No se encontraron alertas en Wazuh. Verifica que el servicio este activo.")
    else:
        total = len(df)
        criticas = len(df[df["nivel"] >= 12])
        altas = len(df[df["nivel"] >= 10])
        bloqueadas_count = len(ips_bloqueadas)

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid #5d6d7e;">
                <p class="metric-label">Total Alertas</p>
                <p style="font-size:3rem; font-weight:700; color:#2c3e50; margin:4px 0 0 0;">{total}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver alertas", key="btn_total", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Alertas y Eventos"
                st.rerun()

        with col2:
            color_alto = "#27ae60" if altas == 0 else "#f39c12"
            bg_alto = "#f9f9f9" if altas == 0 else "#fffbf0"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color_alto}; background:{bg_alto};">
                <p class="metric-label">Nivel Alto (10+)</p>
                <p style="font-size:3rem; font-weight:700; color:{color_alto}; margin:4px 0 0 0;">{altas}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver nivel alto", key="btn_altas", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Alertas y Eventos"
                st.rerun()

        with col3:
            if criticas > 0:
                st.markdown(f"""
                <div class="critica-alert">
                    <p class="metric-label">Nivel Critico (12+)</p>
                    <p style="font-size:3rem; font-weight:700; color:#c0392b; margin:4px 0 0 0;">{criticas}</p>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="metric-card" style="border-top:3px solid #bdc3c7;">
                    <p class="metric-label">Nivel Critico (12+)</p>
                    <p style="font-size:3rem; font-weight:700; color:#bdc3c7; margin:4px 0 0 0;">{criticas}</p>
                </div>""", unsafe_allow_html=True)
            if st.button("Ver criticos", key="btn_criticas", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Alertas y Eventos"
                st.rerun()

        with col4:
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid #6c3483; background:#faf5ff;">
                <p class="metric-label">IPs Bloqueadas</p>
                <p style="font-size:3rem; font-weight:700; color:#6c3483; margin:4px 0 0 0;">{bloqueadas_count}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver IPs", key="btn_bloqueadas", use_container_width=True, type="secondary"):
                st.session_state.pagina = "IPs Bloqueadas"
                st.rerun()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-header">Top Tipos de Alerta</div>', unsafe_allow_html=True)
            top_tipos = df["tipo"].value_counts().head(8).reset_index()
            top_tipos.columns = ["Tipo", "Count"]
            fig = px.bar(top_tipos, x="Count", y="Tipo", orientation="h", color="Count", color_continuous_scale="Reds")
            fig.update_layout(plot_bgcolor="white", paper_bgcolor="white", showlegend=False,
                            coloraxis_showscale=False, margin=dict(l=0,r=0,t=10,b=0), height=300,
                            yaxis_title="", xaxis_title="")
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown('<div class="section-header">Distribucion por Nivel</div>', unsafe_allow_html=True)
            niveles = df["nivel"].value_counts().sort_index().reset_index()
            niveles.columns = ["Nivel", "Count"]
            fig2 = px.bar(niveles, x="Nivel", y="Count", color="Count", color_continuous_scale="OrRd")
            fig2.update_layout(plot_bgcolor="white", paper_bgcolor="white", showlegend=False,
                             coloraxis_showscale=False, margin=dict(l=0,r=0,t=10,b=0), height=300)
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown('<div class="section-header">Actividad Reciente (Timeline)</div>', unsafe_allow_html=True)
        df_time = df.copy()
        df_time["hora"] = df_time["timestamp"].dt.floor("h")
        timeline = df_time.groupby("hora").size().reset_index(name="alertas")
        fig3 = px.area(timeline, x="hora", y="alertas", color_discrete_sequence=["#2c3e50"])
        fig3.update_layout(plot_bgcolor="white", paper_bgcolor="white",
                          margin=dict(l=0,r=0,t=10,b=0), height=180,
                          xaxis_title="", yaxis_title="Alertas")
        st.plotly_chart(fig3, use_container_width=True)

        st.markdown('<div class="section-header">Ultimas Alertas</div>', unsafe_allow_html=True)
        df_show = df.head(10)[["timestamp","tipo","ip","nivel","agente","accion"]].copy()
        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m %H:%M")
        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Agente","Estado"]
        st.dataframe(df_show, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# ALERTAS Y EVENTOS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Alertas y Eventos":
    st.markdown("## Alertas y Eventos")
    st.markdown("---")

    if df.empty:
        st.warning("No hay alertas disponibles.")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            filtro_nivel = st.slider("Nivel minimo", 0, 15, 3)
        with col2:
            opciones_accion = ["Todas"] + list(df["accion"].unique())
            filtro_accion = st.selectbox("Estado", opciones_accion)
        with col3:
            filtro_texto = st.text_input("Buscar por tipo o IP", "")

        df_f = df[df["nivel"] >= filtro_nivel]
        if filtro_accion != "Todas":
            df_f = df_f[df_f["accion"] == filtro_accion]
        if filtro_texto:
            mask = df_f["tipo"].str.contains(filtro_texto, case=False, na=False) | \
                   df_f["ip"].str.contains(filtro_texto, case=False, na=False)
            df_f = df_f[mask]

        st.markdown(f"**{len(df_f)} eventos encontrados**")
        df_show = df_f[["timestamp","tipo","ip","nivel","agente","id_regla","accion"]].copy()
        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m/%Y %H:%M")
        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Agente","Regla","Estado"]
        st.dataframe(df_show, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# IPs BLOQUEADAS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "IPs Bloqueadas":
    st.markdown("## IPs Bloqueadas en Hetzner Firewall")
    st.markdown("---")

    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(f'<div class="metric-card danger"><p class="metric-label">IPs Bloqueadas Activas</p><p class="metric-value">{len(ips_bloqueadas)}</p></div>', unsafe_allow_html=True)

    if ips_bloqueadas:
        st.markdown('<div class="section-header">Lista de IPs Bloqueadas por ASOAR</div>', unsafe_allow_html=True)
        df_ips = pd.DataFrame(ips_bloqueadas, columns=["IP Bloqueada"])
        df_ips["Bloqueada por"] = "ASOAR - Automatico"
        df_ips["Firewall"] = "asoar-firewall"
        st.dataframe(df_ips, use_container_width=True, hide_index=True)
    else:
        st.info("No hay IPs bloqueadas actualmente por ASOAR.")

    import geoip2.database
    st.markdown('<div class="section-header">Mapa de Origen de Ataques</div>', unsafe_allow_html=True)

    try:
        reader = geoip2.database.Reader('/root/asoar/static/GeoLite2-Country.mmdb')
        paises = {}
        for ip in ips_bloqueadas:
            try:
                if ip and ip != "0.0.0.0":
                    response = reader.country(ip)
                    pais = response.country.name
                    if pais:
                        paises[pais] = paises.get(pais, 0) + 1
            except:
                continue
        reader.close()

        if paises:
            df_mapa = pd.DataFrame(list(paises.items()), columns=["Pais", "Ataques"])
            df_mapa = df_mapa.sort_values("Ataques", ascending=False)
            fig_mapa = px.choropleth(
                df_mapa, locations="Pais", locationmode="country names",
                color="Ataques", color_continuous_scale=["#f5f6fa", "#2d6aa0", "#0f1f35"],
                labels={"Ataques": "IPs Bloqueadas"}
            )
            fig_mapa.update_layout(
                plot_bgcolor="white", paper_bgcolor="white",
                margin=dict(l=0, r=0, t=10, b=0), height=400,
                geo=dict(showframe=False, showcoastlines=True, coastlinecolor="#ecf0f1",
                        showland=True, landcolor="#f5f6fa", showocean=True,
                        oceancolor="#eaf2f8", projection_type="natural earth")
            )
            st.plotly_chart(fig_mapa, use_container_width=True)
            st.markdown('<div class="section-header">Top Paises de Origen</div>', unsafe_allow_html=True)
            st.dataframe(df_mapa, use_container_width=True, hide_index=True)
        else:
            st.info("No se pudo geolocalizar ninguna IP.")
    except Exception as e:
        st.error(f"Error cargando el mapa: {e}")

    st.markdown('<div class="section-header">Historico de IPs</div>', unsafe_allow_html=True)
    try:
        r = requests.get("http://localhost:8000/historico", headers=HEADERS, timeout=5)
        historico = r.json()
    except:
        historico = []

    if historico:
        df_hist = pd.DataFrame(historico)
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"]).dt.strftime("%d/%m/%Y %H:%M")
        if "desbloqueada_en" in df_hist.columns:
            df_hist["desbloqueada_en"] = pd.to_datetime(df_hist["desbloqueada_en"], errors="coerce").dt.strftime("%d/%m/%Y %H:%M")
        df_hist.columns = [c.replace("_", " ").title() for c in df_hist.columns]
        st.dataframe(df_hist, use_container_width=True, hide_index=True)
    else:
        st.info("No hay historico de IPs todavia.")

    st.markdown('<div class="section-header">Desbloquear IP</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col1:
        ip_desbloquear = st.text_input("IP a desbloquear", placeholder="Ej: 1.2.3.4")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Desbloquear", type="primary"):
            if ip_desbloquear:
                try:
                    r = requests.delete(f"http://localhost:8000/desbloquear/{ip_desbloquear}", headers=HEADERS, timeout=10)
                    if r.status_code == 200:
                        st.success(f"IP {ip_desbloquear} desbloqueada correctamente")
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error("Error al desbloquear la IP")
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Introduce una IP para desbloquear")

# ══════════════════════════════════════════════════════════════════════════════
# SIMULADOR
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Simulador de Ataques":
    st.markdown("## Simulador de Ataques")
    st.markdown("Envia alertas de prueba al motor ASOAR para verificar el funcionamiento del sistema.")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        ip_atacante = st.text_input("IP del atacante", value="5.6.7.8")
        nivel = st.slider("Nivel de alerta Wazuh", 1, 15, 10)
    with col2:
        descripcion = st.selectbox("Tipo de ataque", [
            "Multiple failed SSH logins",
            "SQL Injection attempt",
            "Port scan detected",
            "Brute force attack",
            "Malware detected",
            "Privilege escalation attempt",
            "Suspicious outbound connection"
        ])

    if st.button("Ejecutar Simulacion"):
        with st.spinner("Procesando con IA..."):
            try:
                r = requests.post("http://localhost:8000/alerta",
                    json={"rule": {"level": nivel, "description": descripcion},
                          "data": {"srcip": ip_atacante}}, headers=HEADERS, timeout=60)
                resultado = r.json()
                st.markdown("---")
                if resultado.get("accion") == "BLOQUEADA":
                    st.error(f"ACCION: IP {ip_atacante} bloqueada en Hetzner firewall")
                else:
                    st.warning("ACCION: Alerta ignorada — nivel insuficiente o falso positivo")
                col1, col2, col3 = st.columns(3)
                col1.metric("Nivel", nivel)
                col2.metric("Accion", resultado.get("accion", "-"))
                col3.metric("IP", ip_atacante)
                with st.expander("Ver respuesta completa"):
                    st.json(resultado)
            except Exception as e:
                st.error(f"Error: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO DEL SISTEMA
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Estado del Sistema":
    st.markdown("## Estado del Sistema")
    st.markdown("---")

    def check_service(url, method="get", payload=None, timeout=5):
        try:
            if method == "post":
                r = requests.post(url, json=payload, headers=HEADERS, timeout=timeout)
            else:
                r = requests.get(url, headers=HEADERS, timeout=timeout)
            return r.status_code < 400
        except:
            return False

    servicios = {
        "ASOAR API (FastAPI)": check_service("http://localhost:8000/"),
        "Ollama / phi3": check_service("http://localhost:11434/api/tags"),
        "Wazuh Manager": True,
        "Wazuh Dashboard": True,
        "Hetzner Firewall": len(ips_bloqueadas) >= 0
    }

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="section-header">Servicios</div>', unsafe_allow_html=True)
        for nombre, estado in servicios.items():
            badge = f'<span class="badge badge-green">Online</span>' if estado else f'<span class="badge badge-red">Offline</span>'
            st.markdown(f'<div class="service-row"><span>{nombre}</span>{badge}</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="section-header">Informacion del Entorno</div>', unsafe_allow_html=True)
        try:
            agentes_count = len(requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5).json())
        except:
            agentes_count = 0
        datos_info = {
            "Campo": ["Version", "Alertas cargadas", "IPs bloqueadas", "Endpoints activos"],
            "Valor": ["Noctua ASOAR v1.0", len(df), len(ips_bloqueadas), agentes_count]
        }
        st.dataframe(pd.DataFrame(datos_info), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Arquitectura del Sistema</div>', unsafe_allow_html=True)
    datos_arq = {
        "Componente": ["Wazuh", "FastAPI", "Ollama (phi3)", "Hetzner API", "Streamlit"],
        "Funcion": ["Deteccion de amenazas", "Intermediario y orquestador", "Analisis con IA", "Bloqueo automatico", "Panel de control"],
        "Puerto": ["443 / 55000", "8000", "11434", "HTTPS", "8501"],
        "Estado": ["Activo" if servicios["Wazuh Manager"] else "Inactivo",
                   "Activo" if servicios["ASOAR API (FastAPI)"] else "Inactivo",
                   "Activo" if servicios["Ollama / phi3"] else "Inactivo",
                   "Conectado", "Activo"]
    }
    st.dataframe(pd.DataFrame(datos_arq), use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Endpoints":
    st.markdown("## Endpoints Monitorizados")
    st.markdown("---")

    try:
        r = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5)
        agentes = r.json()
    except:
        agentes = {}

    if not agentes:
        st.info("No hay endpoints registrados. Ejecuta el agente PowerShell en un equipo Windows.")
    else:
        st.markdown(f"**{len(agentes)} equipo(s) registrado(s)**")
        st.markdown("---")

        for hostname, info in agentes.items():
            datos = info.get("datos", {})
            seg = datos.get("seguridad", {})
            rend = datos.get("rendimiento", {})
            puntuacion = datos.get("puntuacion_seguridad", 0)
            ultima_conexion = info.get("ultima_conexion", "N/A")

            if puntuacion >= 80:
                color = "#27ae60"
            elif puntuacion >= 50:
                color = "#f39c12"
            else:
                color = "#e74c3c"

            st.markdown(f"""
            <div class="metric-card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <p class="metric-label">Endpoint</p>
                        <p class="metric-value">{hostname}</p>
                        <p style="font-size:0.85rem; color:#7f8c8d; margin:4px 0">
                            IP: {datos.get('ip','N/A')} &nbsp;|&nbsp;
                            OS: {datos.get('os','N/A')} &nbsp;|&nbsp;
                            Ultima conexion: {ultima_conexion[:16]}
                        </p>
                    </div>
                    <div style="text-align:center;">
                        <p style="font-size:2.5rem; font-weight:700; color:{color}; margin:0">{puntuacion}</p>
                        <p style="font-size:0.75rem; color:#7f8c8d; margin:0">PUNTUACION</p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                estado = "Activo" if seg.get("defender_activo") else "Inactivo"
                badge = "badge-green" if seg.get("defender_activo") else "badge-red"
                st.markdown(f'<div class="metric-card"><p class="metric-label">Windows Defender</p><span class="badge {badge}">{estado}</span></div>', unsafe_allow_html=True)
            with col2:
                estado = "Activo" if seg.get("firewall_activo") else "Inactivo"
                badge = "badge-green" if seg.get("firewall_activo") else "badge-red"
                st.markdown(f'<div class="metric-card"><p class="metric-label">Firewall</p><span class="badge {badge}">{estado}</span></div>', unsafe_allow_html=True)
            with col3:
                pendientes = seg.get("actualizaciones_pendientes", -1)
                criticas = seg.get("actualizaciones_criticas", 0)
                badge = "badge-red" if criticas > 0 else "badge-green" if pendientes == 0 else "badge-yellow"
                st.markdown(f'<div class="metric-card"><p class="metric-label">Actualizaciones</p><span class="badge {badge}">{pendientes} pendientes ({criticas} criticas)</span></div>', unsafe_allow_html=True)
            with col4:
                admins = seg.get("usuarios_admin", [])
                badge = "badge-yellow" if len(admins) > 2 else "badge-green"
                st.markdown(f'<div class="metric-card"><p class="metric-label">Admins Locales</p><span class="badge {badge}">{len(admins)} usuarios</span></div>', unsafe_allow_html=True)

            col1, col2 = st.columns(2)
            with col1:
                cpu = rend.get("cpu_porcentaje", 0)
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=cpu, title={"text": "CPU %"},
                    gauge={"axis": {"range": [0, 100]},
                           "bar": {"color": "#e74c3c" if cpu > 80 else "#f39c12" if cpu > 60 else "#27ae60"}}
                ))
                fig.update_layout(height=250, margin=dict(l=30,r=30,t=60,b=30), paper_bgcolor="white")
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                ram = rend.get("ram_porcentaje", 0)
                fig = go.Figure(go.Indicator(
                    mode="gauge+number", value=ram, title={"text": "RAM %"},
                    gauge={"axis": {"range": [0, 100]},
                           "bar": {"color": "#e74c3c" if ram > 80 else "#f39c12" if ram > 60 else "#27ae60"}}
                ))
                fig.update_layout(height=250, margin=dict(l=30,r=30,t=60,b=30), paper_bgcolor="white")
                st.plotly_chart(fig, use_container_width=True)

            col_exp1, col_exp2, col_exp3 = st.columns(3)
            with col_exp1:
                with st.expander(f"Puertos en escucha ({len(seg.get('puertos_escucha', []))})"):
                    puertos = seg.get("puertos_escucha", [])
                    if puertos:
                        df_puertos = pd.DataFrame({"Puerto": [str(p) for p in puertos]})
                        st.dataframe(df_puertos, use_container_width=True, hide_index=True)
            with col_exp2:
                procesos_sospechosos = seg.get("procesos_sospechosos", [])
                with st.expander(f"Procesos sospechosos ({len(procesos_sospechosos)})"):
                    if procesos_sospechosos:
                        df_proc = pd.DataFrame(procesos_sospechosos)
                        df_proc = df_proc.rename(columns={"nombre": "Nombre", "pid": "PID", "cpu": "CPU", "memoria_mb": "Memoria (MB)"})
                        st.dataframe(df_proc, use_container_width=True, hide_index=True)
                    else:
                        st.success("No se detectaron procesos sospechosos")
            with col_exp3:
                eventos = seg.get("eventos_seguridad", [])
                with st.expander(f"Eventos de seguridad ({len(eventos)})"):
                    if eventos:
                        df_ev = pd.DataFrame(eventos)
                        if not df_ev.empty:
                            df_ev = df_ev[["tiempo", "tipo", "id"]]
                            df_ev.columns = ["Fecha/Hora", "Tipo", "ID"]
                            st.dataframe(df_ev, use_container_width=True, hide_index=True)
                    else:
                        st.info("Sin eventos recientes")

            with st.expander(f"Software instalado ({len(seg.get('software_instalado', []))})"):
                software = seg.get("software_instalado", [])
                if software:
                    df_sw = pd.DataFrame(software)
                    if not df_sw.empty:
                        df_sw = df_sw.rename(columns={
                            "nombre": "Nombre", "version": "Version",
                            "publisher": "Publisher", "fecha_instalacion": "Fecha instalacion"
                        })
                        df_sw["Fecha instalacion"] = pd.to_datetime(
                            df_sw["Fecha instalacion"], format="%Y%m%d", errors="coerce"
                        ).dt.strftime("%d/%m/%Y")
                        st.dataframe(df_sw, use_container_width=True, hide_index=True)

            st.markdown("---")

# ══════════════════════════════════════════════════════════════════════════════
# NORMATIVAS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Normativas":
    st.markdown("## Control de Normativas")
    st.markdown("Evaluacion automatica de cumplimiento basada en los datos de los endpoints.")
    st.markdown("---")

    try:
        r = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5)
        agentes = r.json()
    except:
        agentes = {}

    if not agentes:
        st.info("No hay endpoints registrados. Ejecuta el agente PowerShell en un equipo Windows.")
    else:
        hostname_sel = st.selectbox("Selecciona un endpoint", list(agentes.keys()))

        try:
            r = requests.get(f"http://localhost:8000/cumplimiento/{hostname_sel}", headers=HEADERS, timeout=5)
            data = r.json()
        except:
            data = {}

        if data and "score_global" in data:
            score_global = data["score_global"]
            color_global = "#27ae60" if score_global >= 80 else "#f39c12" if score_global >= 50 else "#e74c3c"

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">Puntuacion Global</p>
                    <p class="metric-value" style="color:{color_global}">{score_global}%</p>
                    <p style="font-size:0.75rem;color:#7f8c8d">3 marcos normativos</p>
                </div>""", unsafe_allow_html=True)
            with col2:
                score = data["iso27001"]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">ISO/IEC 27001:2022</p>
                    <p class="metric-value" style="color:{color}">{score}%</p>
                </div>""", unsafe_allow_html=True)
            with col3:
                score = data["nis2"]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">NIS2 2022/2555</p>
                    <p class="metric-value" style="color:{color}">{score}%</p>
                </div>""", unsafe_allow_html=True)
            with col4:
                score = data["ens"]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">ENS RD 311/2022</p>
                    <p class="metric-value" style="color:{color}">{score}%</p>
                </div>""", unsafe_allow_html=True)

            st.markdown("---")

            for key, nombre in [("iso27001", "ISO/IEC 27001:2022"), ("nis2", "NIS2 - Directiva UE 2022/2555"), ("ens", "Esquema Nacional de Seguridad")]:
                st.markdown(f'<div class="section-header">{nombre}</div>', unsafe_allow_html=True)
                for ctrl in data[key]["controles"]:
                    cumple = ctrl["cumple"]
                    badge = f'<span class="badge badge-green">Cumple</span>' if cumple else f'<span class="badge badge-red">No cumple</span>'
                    st.markdown(f"""
                    <div style="background:white; padding:12px 16px; border-radius:6px; margin-bottom:8px;
                                border-left:3px solid {'#27ae60' if cumple else '#e74c3c'};
                                box-shadow:0 1px 3px rgba(0,0,0,0.06);">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <span style="font-size:0.75rem;color:#7f8c8d;font-weight:600">{ctrl['control']}</span>
                                <span style="font-size:0.9rem;color:#2c3e50;margin-left:12px">{ctrl['nombre']}</span>
                            </div>
                            <div style="display:flex;align-items:center;gap:12px;">
                                <span style="font-size:0.8rem;color:#7f8c8d">{ctrl['detalle']}</span>
                                {badge}
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("<br>", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# INFORMES
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Informes":
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm
    import io

    st.markdown("## Informes")
    st.markdown("Genera informes ejecutivos en PDF del estado de seguridad del sistema.")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        tipo_informe = st.selectbox("Tipo de informe", [
            "Informe Ejecutivo de Seguridad",
            "Informe de IPs Bloqueadas",
            "Informe de Cumplimiento Normativo"
        ])
    with col2:
        try:
            r = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5)
            agentes_disp = list(r.json().keys())
        except:
            agentes_disp = []
        endpoint_sel = st.selectbox("Endpoint", agentes_disp if agentes_disp else ["Sin endpoints"])

    if st.button("Generar Informe PDF", type="primary"):
        with st.spinner("Generando informe..."):
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            style_title = ParagraphStyle('title', fontSize=24, fontName='Helvetica-Bold', textColor=colors.HexColor('#0f1f35'), spaceAfter=6)
            style_subtitle = ParagraphStyle('subtitle', fontSize=11, fontName='Helvetica', textColor=colors.HexColor('#4a6fa5'), spaceAfter=20)
            style_h2 = ParagraphStyle('h2', fontSize=13, fontName='Helvetica-Bold', textColor=colors.HexColor('#1a3a6c'), spaceAfter=8, spaceBefore=16)
            style_body = ParagraphStyle('body', fontSize=10, fontName='Helvetica', textColor=colors.HexColor('#2c3e50'), spaceAfter=6)
            style_small = ParagraphStyle('small', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#7f8c8d'))
            elements = []

            elements.append(Paragraph("NOCTUA.", style_title))
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("Autonomous Security Operations Platform", style_subtitle))
            elements.append(Spacer(1, 0.3*cm))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a3a6c')))
            elements.append(Spacer(1, 0.4*cm))
            elements.append(Paragraph(tipo_informe.upper(), ParagraphStyle('report_type', fontSize=16, fontName='Helvetica-Bold', textColor=colors.HexColor('#1a3a6c'), spaceAfter=8)))
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph(f"Generado el {hora_local().strftime('%d/%m/%Y a las %H:%M:%S')}", style_small))
            elements.append(Spacer(1, 0.5*cm))

            if tipo_informe == "Informe Ejecutivo de Seguridad":
                elements.append(Paragraph("Resumen Ejecutivo", style_h2))
                elements.append(Paragraph(
                    f"Este informe presenta el estado actual de la plataforma Noctua ASOAR. "
                    f"Se han procesado {len(df)} alertas de seguridad, de las cuales "
                    f"{len(df[df['nivel'] >= 10]) if not df.empty else 0} son de nivel alto o critico. "
                    f"El sistema ha bloqueado automaticamente {len(ips_bloqueadas)} direcciones IP maliciosas.",
                    style_body))
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph("Metricas de Seguridad", style_h2))
                data_tabla = [
                    ["Metrica", "Valor", "Estado"],
                    ["Total Alertas", str(len(df)), "-"],
                    ["Alertas Nivel Alto (10+)", str(len(df[df["nivel"] >= 10]) if not df.empty else 0), "Revisar" if not df.empty and len(df[df["nivel"] >= 10]) > 0 else "OK"],
                    ["Alertas Nivel Critico (12+)", str(len(df[df["nivel"] >= 12]) if not df.empty else 0), "Critico" if not df.empty and len(df[df["nivel"] >= 12]) > 0 else "OK"],
                    ["IPs Bloqueadas", str(len(ips_bloqueadas)), "Activo"],
                    ["Endpoints Monitorizados", str(len(agentes_disp)), "Activo"],
                ]
                tabla = Table(data_tabla, colWidths=[7*cm, 4*cm, 4*cm])
                tabla.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1f35')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                    ('PADDING', (0,0), (-1,-1), 6),
                ]))
                elements.append(tabla)

            elif tipo_informe == "Informe de IPs Bloqueadas":
                elements.append(Paragraph("IPs Bloqueadas por ASOAR", style_h2))
                elements.append(Paragraph(f"El sistema ha bloqueado automaticamente {len(ips_bloqueadas)} IPs identificadas como maliciosas mediante IA.", style_body))
                elements.append(Spacer(1, 0.3*cm))
                if ips_bloqueadas:
                    data_ips = [["IP Bloqueada", "Bloqueada por", "Firewall"]]
                    for ip in ips_bloqueadas:
                        data_ips.append([ip, "ASOAR - Automatico", "asoar-firewall"])
                    tabla_ips = Table(data_ips, colWidths=[6*cm, 5*cm, 4*cm])
                    tabla_ips.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1f35')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0,0), (-1,-1), 9),
                        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                        ('PADDING', (0,0), (-1,-1), 6),
                    ]))
                    elements.append(tabla_ips)

            elif tipo_informe == "Informe de Cumplimiento Normativo":
                if endpoint_sel and endpoint_sel != "Sin endpoints":
                    try:
                        r = requests.get(f"http://localhost:8000/cumplimiento/{endpoint_sel}", headers=HEADERS, timeout=5)
                        data_norm = r.json()
                    except:
                        data_norm = {}
                    if data_norm and "score_global" in data_norm:
                        elements.append(Paragraph(f"Endpoint: {endpoint_sel}", style_h2))
                        elements.append(Paragraph(f"Puntuacion global: {data_norm['score_global']}% basada en 3 marcos normativos.", style_body))
                        elements.append(Spacer(1, 0.3*cm))
                        for key, nombre in [("iso27001", "ISO/IEC 27001:2022"), ("nis2", "NIS2 - Directiva UE 2022/2555"), ("ens", "Esquema Nacional de Seguridad")]:
                            elements.append(Paragraph(f"{nombre} - {data_norm[key]['score']}%", style_h2))
                            data_ctrl = [["Control", "Nombre", "Estado", "Detalle"]]
                            for ctrl in data_norm[key]["controles"]:
                                data_ctrl.append([ctrl["control"], ctrl["nombre"], "Cumple" if ctrl["cumple"] else "No cumple", ctrl["detalle"]])
                            tabla_ctrl = Table(data_ctrl, colWidths=[2.5*cm, 5*cm, 2.5*cm, 5*cm])
                            tabla_ctrl.setStyle(TableStyle([
                                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3a6c')),
                                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                                ('FONTSIZE', (0,0), (-1,-1), 8),
                                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                                ('PADDING', (0,0), (-1,-1), 5),
                            ]))
                            elements.append(tabla_ctrl)
                            elements.append(Spacer(1, 0.3*cm))

            elements.append(Spacer(1, 1*cm))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0')))
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph(f"Noctua. — Autonomous Security Operations Platform | {hora_local().strftime('%d/%m/%Y')}", style_small))

            doc.build(elements)
            buffer.seek(0)
            st.success("Informe generado correctamente.")
            st.download_button(label="Descargar PDF", data=buffer,
                file_name=f"noctua_informe_{hora_local().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf", type="primary")

# ══════════════════════════════════════════════════════════════════════════════
# DETECCION APT
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Deteccion APT":
    st.markdown("## Deteccion de Campanas APT")
    st.markdown("Motor predictivo LSTM con Federated Learning y explicabilidad XAI")
    st.markdown("---")

    # Estado del detector
    try:
        estado = requests.get("http://localhost:8000/apt/estado", headers=HEADERS, timeout=5).json()
    except:
        estado = {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        modelo_ok = estado.get("modelo_cargado", False)
        color = "#27ae60" if modelo_ok else "#e74c3c"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Motor LSTM</p>
            <p style="font-size:1.2rem;font-weight:700;color:{color}">
                {"Activo" if modelo_ok else "Inactivo"}
            </p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #6c3483;">
            <p class="metric-label">Eventos en Buffer</p>
            <p style="font-size:2rem;font-weight:700;color:#6c3483;">
                {estado.get("eventos_en_buffer", 0)}
            </p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #e74c3c;">
            <p class="metric-label">Campanas Totales</p>
            <p style="font-size:2rem;font-weight:700;color:#e74c3c;">
                {estado.get("campanas_totales", 0)}
            </p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #f39c12;">
            <p class="metric-label">Campanas 24h</p>
            <p style="font-size:2rem;font-weight:700;color:#f39c12;">
                {estado.get("campanas_24h", 0)}
            </p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # Fases MITRE ATT&CK
    st.markdown('<div class="section-header">Fases MITRE ATT&CK Monitorizadas</div>', unsafe_allow_html=True)
    fases_colores = {
        "reconnaissance":       "#95a5a6",
        "initial_access":       "#e67e22",
        "execution":            "#e74c3c",
        "persistence":          "#c0392b",
        "privilege_escalation": "#8e44ad",
        "defense_evasion":      "#6c3483",
        "credential_access":    "#d35400",
        "discovery":            "#2980b9",
        "lateral_movement":     "#c0392b",
        "collection":           "#922b21",
        "exfiltration":         "#641e16",
        "unknown":              "#bdc3c7",
    }
    cols = st.columns(6)
    for i, (fase, color) in enumerate(fases_colores.items()):
        with cols[i % 6]:
            st.markdown(f"""
            <div style="background:{color};color:white;padding:6px 8px;
                        border-radius:6px;font-size:0.7rem;font-weight:600;
                        text-align:center;margin-bottom:6px;">
                {fase.replace("_", " ").upper()}
            </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # Campanas detectadas
    st.markdown('<div class="section-header">Campanas APT Detectadas</div>', unsafe_allow_html=True)
    try:
        campanas = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
    except:
        campanas = []

    if campanas:
        df_apt = pd.DataFrame(campanas)
        df_apt["timestamp"] = pd.to_datetime(df_apt["timestamp"]).dt.strftime("%d/%m/%Y %H:%M")
        col_order = ["timestamp", "fase_mitre", "confianza", "nivel_riesgo", "ip", "n_eventos"]
        col_order = [c for c in col_order if c in df_apt.columns]
        df_apt = df_apt[col_order]
        df_apt.columns = [c.replace("_", " ").title() for c in col_order]
        st.dataframe(df_apt, use_container_width=True, hide_index=True)

        # Grafica de fases detectadas
        if "Fase Mitre" in df_apt.columns:
            st.markdown('<div class="section-header">Distribucion de Fases APT</div>', unsafe_allow_html=True)
            conteo = df_apt["Fase Mitre"].value_counts().reset_index()
            conteo.columns = ["Fase", "Count"]
            fig = px.bar(conteo, x="Fase", y="Count", color="Count",
                        color_continuous_scale="Reds")
            fig.update_layout(plot_bgcolor="white", paper_bgcolor="white",
                            margin=dict(l=0,r=0,t=10,b=0), height=250,
                            showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No se han detectado campanas APT todavia. El sistema esta monitorizando activamente.")
        st.markdown(f"""
        <div style="background:#f5f6fa;padding:16px;border-radius:8px;
                    border-left:3px solid #27ae60;margin-top:8px;">
            <p style="font-size:0.9rem;color:#2c3e50;margin:0">
                El motor LSTM analiza cada alerta recibida y acumula eventos en un buffer
                deslizante de 32 posiciones. Cuando detecta una secuencia consistente con
                una campana APT segun el framework MITRE ATT&CK, registra la campana aqui
                con su fase, confianza y explicacion XAI.
            </p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # Explicaciones XAI
    st.markdown('<div class="section-header">Explicaciones XAI — Cumplimiento EU AI Act</div>', unsafe_allow_html=True)
    try:
        explicaciones = requests.get("http://localhost:8000/apt/xai", headers=HEADERS, timeout=5).json()
    except:
        explicaciones = []

    if explicaciones:
        for exp in explicaciones[-3:]:
            nivel_color = {
                "CRITICO": "#e74c3c", "ALTO": "#e67e22",
                "MEDIO": "#f39c12", "BAJO": "#27ae60"
            }.get(exp.get("nivel_riesgo", "BAJO"), "#bdc3c7")

            st.markdown(f"""
            <div style="background:white;padding:16px;border-radius:8px;
                        border-left:4px solid {nivel_color};
                        box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                    <span style="font-weight:600;color:#2c3e50">
                        {exp.get("fase_detectada","").replace("_"," ").upper()}
                    </span>
                    <span style="color:#7f8c8d;font-size:0.85rem">
                        Confianza: {exp.get("confianza",0)}%
                    </span>
                </div>
                <p style="font-size:0.85rem;color:#2c3e50;margin:0 0 8px 0">
                    {exp.get("narrativa","")}
                </p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    {"".join([
                        f'<span style="background:#f5f6fa;padding:3px 8px;border-radius:4px;font-size:0.75rem;color:#2c3e50">'
                        f'{f["feature"].replace("_"," ")}: {f["importancia"]}%</span>'
                        for f in exp.get("top_features",[])
                    ])}
                </div>
            </div>""", unsafe_allow_html=True)
    else:
        st.info("Las explicaciones XAI apareceran aqui cuando se detecte una campana APT activa.")

    st.markdown("---")

    # Importancia global de features
    st.markdown('<div class="section-header">Importancia Global de Features (XAI)</div>', unsafe_allow_html=True)
    try:
        importancia = requests.get("http://localhost:8000/apt/importancia", headers=HEADERS, timeout=5).json()
    except:
        importancia = {}

    if importancia:
        df_imp = pd.DataFrame(list(importancia.items()), columns=["Feature", "Importancia"])
        df_imp = df_imp.sort_values("Importancia", ascending=False)
        df_imp["Feature"] = df_imp["Feature"].str.replace("_", " ").str.title()
        fig = px.bar(df_imp, x="Importancia", y="Feature", orientation="h",
                    color="Importancia", color_continuous_scale="Blues")
        fig.update_layout(plot_bgcolor="white", paper_bgcolor="white",
                         margin=dict(l=0,r=0,t=10,b=0), height=300,
                         showlegend=False, coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("La importancia global de features se calculara tras las primeras detecciones APT.")




# ══════════════════════════════════════════════════════════════════════════════
# ABOUT
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "About":
    st.markdown("## Acerca de Noctua.")
    st.markdown("---")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div class="metric-card">
            <p class="metric-label">Descripcion del Proyecto</p>
            <p style="font-size:0.95rem; color:#2c3e50; line-height:1.7; margin-top:8px">
                <strong>Noctua.</strong> es una plataforma ASOAR (Autonomous Security Operations,
                Analysis and Response) diseñada especificamente para PYMEs que no disponen de un
                equipo de seguridad dedicado.
                <br><br>
                El sistema combina deteccion de amenazas en tiempo real con inteligencia artificial
                local para analizar alertas y tomar decisiones de bloqueo automaticas, sin depender
                de servicios cloud externos ni exponer datos sensibles.
                <br><br>
                Desarrollado como proyecto de fin de master en ciberseguridad, Noctua. demuestra
                que es posible implementar un SOC autonomo y economicamente viable para organizaciones
                de cualquier tamaño.
                <br><br>
                Esta primera fase establece los cimientos de la plataforma: deteccion, analisis con IA,
                respuesta automatica y control normativo basico. Las siguientes fases contemplaran
                mejoras en el motor de IA, integracion con bases de datos para historico avanzado,
                soporte multi-tenant para gestionar multiples clientes PYME, y un sistema de
                notificaciones avanzado con integracion en canales corporativos. Todo ello sin coste
                adicional, aprovechando herramientas open source y gratuitas.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">Informacion del Proyecto</p>
            <br>
            <p style="font-size:0.85rem; color:#2c3e50; line-height:2">
                <strong>Version:</strong> 1.0 — Fase 1<br>
                <strong>Autor:</strong> Alejandra R.<br>
                <strong>Master:</strong> Ciberseguridad<br>
                <strong>Año:</strong> 2026<br>
                <strong>Licencia:</strong> Privada<br>
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Arquitectura del Sistema</div>', unsafe_allow_html=True)
    componentes = [
        {"Componente": "Wazuh", "Rol": "Vigilancia", "Descripcion": "SIEM/XDR open source. Detecta amenazas, analiza logs y genera alertas en tiempo real.", "Tecnologia": "Python / C"},
        {"Componente": "Ollama / phi3", "Rol": "Cerebro IA", "Descripcion": "Modelo de lenguaje local que analiza cada alerta y decide autonomamente si bloquear o ignorar.", "Tecnologia": "LLM / Python"},
        {"Componente": "FastAPI", "Rol": "Intermediario", "Descripcion": "API REST que orquesta el flujo entre Wazuh, Ollama y Hetzner. Incluye autenticacion y rate limiting.", "Tecnologia": "Python"},
        {"Componente": "Hetzner API", "Rol": "Accion", "Descripcion": "Ejecuta el bloqueo real de IPs maliciosas modificando las reglas del firewall en la nube.", "Tecnologia": "REST API"},
        {"Componente": "Agente PowerShell", "Rol": "Endpoint", "Descripcion": "Script instalado en equipos Windows que envia telemetria de seguridad al servidor cada 5 minutos.", "Tecnologia": "PowerShell"},
        {"Componente": "Streamlit", "Rol": "Panel Visual", "Descripcion": "Dashboard web profesional con autenticacion, graficas en tiempo real y control de normativas.", "Tecnologia": "Python"},
    ]
    st.dataframe(pd.DataFrame(componentes), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Flujo de Respuesta Automatica</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="background:white; padding:24px; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.07);">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div style="text-align:center; flex:1;">
                <div style="background:#1a3a6c; color:white; padding:12px 16px; border-radius:8px; font-size:0.85rem; font-weight:600">
                    ATACANTE<br><span style="font-weight:400; font-size:0.75rem">Intento de intrusion</span>
                </div>
            </div>
            <div style="color:#bdc3c7; font-size:1.2rem">→</div>
            <div style="text-align:center; flex:1;">
                <div style="background:#2d6aa0; color:white; padding:12px 16px; border-radius:8px; font-size:0.85rem; font-weight:600">
                    WAZUH<br><span style="font-weight:400; font-size:0.75rem">Deteccion y alerta</span>
                </div>
            </div>
            <div style="color:#bdc3c7; font-size:1.2rem">→</div>
            <div style="text-align:center; flex:1;">
                <div style="background:#2d6aa0; color:white; padding:12px 16px; border-radius:8px; font-size:0.85rem; font-weight:600">
                    OLLAMA IA<br><span style="font-weight:400; font-size:0.75rem">Analisis autonomo</span>
                </div>
            </div>
            <div style="color:#bdc3c7; font-size:1.2rem">→</div>
            <div style="text-align:center; flex:1;">
                <div style="background:#2d6aa0; color:white; padding:12px 16px; border-radius:8px; font-size:0.85rem; font-weight:600">
                    FASTAPI<br><span style="font-weight:400; font-size:0.75rem">Orquestacion</span>
                </div>
            </div>
            <div style="color:#bdc3c7; font-size:1.2rem">→</div>
            <div style="text-align:center; flex:1;">
                <div style="background:#c8922a; color:white; padding:12px 16px; border-radius:8px; font-size:0.85rem; font-weight:600">
                    HETZNER<br><span style="font-weight:400; font-size:0.75rem">Bloqueo automatico</span>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Normativas Soportadas</div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""<div class="metric-card"><p class="metric-label">ISO/IEC 27001:2022</p>
        <p style="font-size:0.85rem; color:#7f8c8d; margin-top:8px; line-height:1.6">
        Estandar internacional para la gestion de la seguridad de la informacion.
        Noctua evalua automaticamente los controles del Anexo A.</p></div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""<div class="metric-card"><p class="metric-label">NIS2 — Directiva UE 2022/2555</p>
        <p style="font-size:0.85rem; color:#7f8c8d; margin-top:8px; line-height:1.6">
        Directiva europea de ciberseguridad. Noctua verifica las medidas
        tecnicas del Articulo 21 en tiempo real.</p></div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""<div class="metric-card"><p class="metric-label">ENS — RD 311/2022</p>
        <p style="font-size:0.85rem; color:#7f8c8d; margin-top:8px; line-height:1.6">
        Esquema Nacional de Seguridad espanol. Evaluacion automatica
        de las medidas del Anexo II.</p></div>""", unsafe_allow_html=True)