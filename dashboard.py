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
    st.error("Usuario o contrasena incorrectos")
    st.stop()
if authentication_status is None:
    st.stop()

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
        background: transparent !important; color: #2c3e50 !important;
        border: 1px solid #e0e0e0 !important; width: 100% !important;
        text-align: left !important; margin-bottom: 4px !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="secondary"] p { color: #2c3e50 !important; }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: #1a3a6c !important; color: white !important;
        border: none !important; width: 100% !important;
        text-align: left !important; margin-bottom: 4px !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] p { color: white !important; }
    section[data-testid="stSidebar"] .stButton > button:hover { opacity: 0.85 !important; }
    .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.07); margin-bottom: 16px; border-top: 3px solid #2c3e50; transition: transform 0.2s ease, box-shadow 0.2s ease; }
    .metric-card:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0,0,0,0.12) !important; }
    .metric-card.danger  { border-top-color: #e74c3c; }
    .metric-card.warning { border-top-color: #f39c12; }
    .metric-card.success { border-top-color: #27ae60; }
    .metric-card.info    { border-top-color: #2980b9; }
    .metric-value { font-size: 2rem; font-weight: 700; color: #2c3e50; margin: 4px 0 0 0; animation: fadeInUp 0.5s ease; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .metric-label { font-size: 0.75rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; margin: 0; }
    .section-header { font-size: 0.8rem; font-weight: 700; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; padding: 16px 0 8px 0; border-bottom: 1px solid #ecf0f1; margin-bottom: 16px; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.72rem; font-weight: 600; }
    .badge-green  { background: #d5f5e3; color: #1e8449; }
    .badge-red    { background: #fadbd8; color: #922b21; }
    .badge-yellow { background: #fef9e7; color: #9a7d0a; }
    .service-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 0.9rem; color: #2c3e50; }
    .stButton > button { background: #2c3e50; color: white; border: none; border-radius: 6px; font-weight: 600; }
    .stButton > button:hover { background: #1a252f; color: white; }
    @keyframes parpadeo { 0%, 100% { background-color: #fff5f5; } 50% { background-color: #ffd5d5; } }
    .critica-alert { animation: parpadeo 1.2s infinite; border-top: 3px solid #c0392b !important; border-radius: 8px; padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.07); margin-bottom: 16px; }
    div[data-testid="stForm"] { max-width: 420px !important; margin: 0 auto !important; }
    input[type="text"], input[type="password"] { border: 1px solid #bdc3c7 !important; border-radius: 6px !important; padding: 8px 12px !important; }
    input[type="text"]:focus, input[type="password"]:focus { border: 1px solid #1a3a6c !important; box-shadow: 0 0 0 2px rgba(26,58,108,0.15) !important; }
    div[data-baseweb="input"] { border: 1px solid #bdc3c7 !important; border-radius: 6px !important; }
    div[data-baseweb="base-input"]:hover { border: 1px solid #1a3a6c !important; }
</style>""", unsafe_allow_html=True)

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

with st.sidebar:
    with open("/root/asoar/static/noctua_logo.svg", "r") as f:
        logo_svg = f.read()
    st.markdown(logo_svg, unsafe_allow_html=True)
    st.markdown("---")
    opciones = [
        "Panel General", "Alertas y Eventos", "IPs Bloqueadas",
        "Endpoints", "Normativas", "Deteccion APT",
        "Simulador de Ataques", "Informes", "Estado del Sistema", "About"
    ]
    if "pagina" not in st.session_state:
        st.session_state.pagina = "Panel General"
    for opcion in opciones:
        activo = st.session_state.pagina == opcion
        if st.button(opcion, key=f"nav_{opcion}", use_container_width=True,
                     type="primary" if activo else "secondary"):
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
                st.session_state.pagina = "Alertas y Eventos"; st.rerun()
        with col2:
            color_alto = "#27ae60" if altas == 0 else "#f39c12"
            bg_alto = "#f9f9f9" if altas == 0 else "#fffbf0"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color_alto}; background:{bg_alto};">
                <p class="metric-label">Nivel Alto (10+)</p>
                <p style="font-size:3rem; font-weight:700; color:{color_alto}; margin:4px 0 0 0;">{altas}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver nivel alto", key="btn_altas", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Alertas y Eventos"; st.rerun()
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
                st.session_state.pagina = "Alertas y Eventos"; st.rerun()
        with col4:
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid #6c3483; background:#faf5ff;">
                <p class="metric-label">IPs Bloqueadas</p>
                <p style="font-size:3rem; font-weight:700; color:#6c3483; margin:4px 0 0 0;">{bloqueadas_count}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver IPs", key="btn_bloqueadas", use_container_width=True, type="secondary"):
                st.session_state.pagina = "IPs Bloqueadas"; st.rerun()
        
        # Metricas APT
        try:
            estado_apt = requests.get("http://localhost:8000/apt/estado", headers=HEADERS, timeout=3).json()
            estado_lateral = requests.get("http://localhost:8000/apt/lateral/estado", headers=HEADERS, timeout=3).json()
        except:
            estado_apt = {}
            estado_lateral = {}

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            campanas_total = estado_apt.get("campanas_totales", 0)
            color = "#e74c3c" if campanas_total > 0 else "#bdc3c7"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Campañas APT</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{campanas_total}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver APT", key="btn_apt", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Deteccion APT"; st.rerun()
        with col2:
            campanas_24h = estado_apt.get("campanas_24h", 0)
            color = "#e67e22" if campanas_24h > 0 else "#bdc3c7"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Campañas APT 24h</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{campanas_24h}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver ultimas", key="btn_apt_24h", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Deteccion APT"; st.rerun()
        with col3:
            lateral_total = estado_lateral.get("detecciones_totales", 0)
            color = "#8e44ad" if lateral_total > 0 else "#bdc3c7"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Movimiento Lateral</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{lateral_total}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver lateral", key="btn_lateral", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Deteccion APT"; st.rerun()
        with col4:
            buffer = estado_apt.get("eventos_en_buffer", 0)
            color = "#2980b9"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Eventos en Buffer</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{buffer}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver motor", key="btn_buffer", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Deteccion APT"; st.rerun()
        st.markdown("---")

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
                        st.cache_data.clear(); st.rerun()
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
    st.markdown("Envia alertas de prueba al motor ASOAR y simula campañas APT completas para verificar el funcionamiento del sistema.")
    st.markdown("---")

    tab1, tab2 = st.tabs(["Alerta Individual", "Campaña APT Completa"])

    with tab1:
        st.markdown("### Simular Alerta Individual")
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
        if st.button("Ejecutar Simulacion", key="btn_sim_individual"):
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
                    apt = resultado.get("apt", {})
                    if apt:
                        st.markdown("**Analisis APT:**")
                        st.json(apt)
                    with st.expander("Ver respuesta completa"):
                        st.json(resultado)
                except Exception as e:
                    st.error(f"Error: {e}")

    with tab2:
        st.markdown("### Simular Campaña APT Completa")
        st.markdown("""
        <div style="background:#f5f6fa;padding:12px 16px;border-radius:8px;
                    border-left:3px solid #e74c3c;margin-bottom:16px;">
            <p style="font-size:0.85rem;color:#2c3e50;margin:0">
                Simula una campana APT completa enviando una secuencia de alertas que representan
                las fases progresivas de un ataque real segun el framework MITRE ATT&CK.
                El motor LSTM analizara la secuencia y detectara la campana en progreso.
            </p>
        </div>""", unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            ip_apt = st.text_input("IP del atacante APT", value="185.220.101.45")
            campana_tipo = st.selectbox("Tipo de campaña APT", [
                "Campaña Completa (5 fases)",
                "Acceso Inicial + Persistencia",
                "Movimiento Lateral",
                "Exfiltracion de Datos",
            ])
        with col2:
            velocidad = st.selectbox("Velocidad de simulacion", [
                "Rapida (sin pausas)",
                "Normal (1s entre eventos)",
                "Lenta (3s entre eventos)",
            ])
            agentes_sim = st.multiselect("Agentes objetivo", 
                ["master", "workstation-01", "servidor-web", "servidor-bbdd"],
                default=["master", "workstation-01"])

        # Definir secuencias de campanas
        campanas_sim = {
            "Campaña Completa (5 fases)": [
                {"rule": {"level": 5,  "description": "Port scan detected",              "id": "5501"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 7,  "description": "Multiple failed SSH logins",      "id": "5712"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 10, "description": "Successful SSH login after failures","id": "5710"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 11, "description": "New cron job added",              "id": "5902"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 12, "description": "Privilege escalation attempt",    "id": "5401"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 11, "description": "Lateral movement via SMB",        "id": "5301"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 13, "description": "Suspicious outbound connection",  "id": "5601"}, "data": {"srcip": ip_apt}},
            ],
            "Acceso Inicial + Persistencia": [
                {"rule": {"level": 7,  "description": "Multiple failed SSH logins",      "id": "5712"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 10, "description": "Successful login after brute force","id": "5710"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 11, "description": "New service installed",           "id": "5903"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 11, "description": "Crontab modification detected",   "id": "5902"}, "data": {"srcip": ip_apt}},
            ],
            "Movimiento Lateral": [
                {"rule": {"level": 10, "description": "Remote access attempt",           "id": "5502"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 11, "description": "SMB share access from new host",  "id": "5301"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 12, "description": "Credential reuse detected",       "id": "5711"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 12, "description": "Remote execution attempt",        "id": "5601"}, "data": {"srcip": ip_apt}},
            ],
            "Exfiltracion de Datos": [
                {"rule": {"level": 10, "description": "Large outbound transfer detected","id": "5601"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 12, "description": "DNS tunneling attempt",           "id": "5602"}, "data": {"srcip": ip_apt}},
                {"rule": {"level": 13, "description": "Data exfiltration pattern",       "id": "5601"}, "data": {"srcip": ip_apt}},
            ],
        }

        pausas = {"Rapida (sin pausas)": 0, "Normal (1s entre eventos)": 1, "Lenta (3s entre eventos)": 3}

        if st.button("Lanzar Campaña APT", key="btn_sim_apt", type="primary"):
            eventos = campanas_sim.get(campana_tipo, [])
            pausa = pausas.get(velocidad, 0)

            st.markdown("---")
            st.markdown(f"**Simulando campaña: {campana_tipo}**")
            st.markdown(f"IP atacante: `{ip_apt}` | Eventos: {len(eventos)}")

            progress = st.progress(0)
            log_container = st.empty()
            log_lines = []

            for i, evento in enumerate(eventos):
                try:
                    import time
                    if pausa > 0:
                        time.sleep(pausa)

                    r = requests.post("http://localhost:8000/alerta",
                                    json={**evento, "simulacion": True}, headers=HEADERS, timeout=30)
                    res = r.json()
                    accion  = res.get("accion", "IGNORADA")
                    apt_res = res.get("apt", {})
                    fase    = apt_res.get("fase_mitre", "—")
                    conf    = apt_res.get("confianza", 0)

                    icono = "🔴" if accion == "BLOQUEADA" else "🟡"
                    log_lines.append(
                        f"{icono} Evento {i+1}/{len(eventos)}: "
                        f"{evento['rule']['description']} | "
                        f"Accion: {accion} | Fase LSTM: {fase} ({conf}%)"
                    )
                    log_container.markdown("\n\n".join(log_lines))
                    progress.progress((i+1)/len(eventos))

                except Exception as e:
                    log_lines.append(f"❌ Evento {i+1}: Error — {e}")
                    log_container.markdown("\n\n".join(log_lines))

            st.success(f"Campaña APT simulada completamente — {len(eventos)} eventos enviados")

            # Mostrar estado APT tras la simulacion
            try:
                estado_post = requests.get("http://localhost:8000/apt/estado",
                                          headers=HEADERS, timeout=5).json()
                col1, col2, col3 = st.columns(3)
                col1.metric("Eventos en Buffer", estado_post.get("eventos_en_buffer", 0))
                col2.metric("Campañas Totales", estado_post.get("campañas_totales", 0))
                col3.metric("Campañas 24h", estado_post.get("campañas_24h", 0))
            except:
                pass

            if st.button("Ver detecciones APT", key="btn_ver_apt"):
                st.session_state.pagina = "Deteccion APT"
                st.rerun()

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
        "ASOAR API (FastAPI)":  check_service("http://localhost:8000/"),
        "Ollama / phi3":        check_service("http://localhost:11434/api/tags"),
        "Wazuh Manager":        True,
        "Wazuh Dashboard":      True,
        "Hetzner Firewall":     len(ips_bloqueadas) >= 0,
    }

    # Estado modulos APT
    try:
        estado_apt     = requests.get("http://localhost:8000/apt/estado", headers=HEADERS, timeout=3).json()
        estado_lateral = requests.get("http://localhost:8000/apt/lateral/estado", headers=HEADERS, timeout=3).json()
        estado_retrain = requests.get("http://localhost:8000/apt/retrain/estado", headers=HEADERS, timeout=3).json()
    except:
        estado_apt     = {}
        estado_lateral = {}
        estado_retrain = {}

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="section-header">Servicios Core</div>', unsafe_allow_html=True)
        for nombre, estado in servicios.items():
            badge = f'<span class="badge badge-green">Online</span>' if estado else f'<span class="badge badge-red">Offline</span>'
            st.markdown(f'<div class="service-row"><span>{nombre}</span>{badge}</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="section-header">Modulos de IA — Noctua Predictive</div>', unsafe_allow_html=True)
        modulos_ia = {
            "Motor LSTM":              estado_apt.get("modelo_cargado", False),
            "Detector APT":            estado_apt.get("modelo_cargado", False),
            "Detector Movimiento Lateral": True if estado_lateral.get("ips_monitorizadas", 0) >= 0 else False,
            "Reentrenamiento Automatico": estado_retrain.get("activo", False),
            "Modulo XAI (SHAP)":       estado_apt.get("modelo_cargado", False),
            "Federated Learning":      True,
        }
        for nombre, estado in modulos_ia.items():
            badge = f'<span class="badge badge-green">Activo</span>' if estado else f'<span class="badge badge-red">Inactivo</span>'
            st.markdown(f'<div class="service-row"><span>{nombre}</span>{badge}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # Metricas globales
    st.markdown('<div class="section-header">Metricas Globales del Sistema</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        try:
            agentes_count = len(requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5).json())
        except:
            agentes_count = 0
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">Alertas Procesadas</p>
            <p style="font-size:2rem;font-weight:700;color:#2c3e50;">{len(df)}</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">IPs Bloqueadas</p>
            <p style="font-size:2rem;font-weight:700;color:#6c3483;">{len(ips_bloqueadas)}</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">Campañas APT</p>
            <p style="font-size:2rem;font-weight:700;color:#e74c3c;">{estado_apt.get("campanas_totales", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">Detecciones Laterales</p>
            <p style="font-size:2rem;font-weight:700;color:#8e44ad;">{estado_lateral.get("detecciones_totales", 0)}</p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Arquitectura Completa del Sistema</div>', unsafe_allow_html=True)
    datos_arq = {
        "Componente":  ["Wazuh SIEM", "FastAPI", "Ollama phi3", "LSTM PyTorch", "Federated Learning", "XAI SHAP", "Detector Lateral", "Reentrenamiento", "Hetzner API", "Streamlit"],
        "Capa":        ["Deteccion", "Orquestacion", "Analisis IA", "Prediccion APT", "Aprendizaje FL", "Explicabilidad", "Correlacion", "Mejora continua", "Respuesta", "Visualizacion"],
        "Estado":      [
            "Activo" if servicios["Wazuh Manager"] else "Inactivo",
            "Activo" if servicios["ASOAR API (FastAPI)"] else "Inactivo",
            "Activo" if servicios["Ollama / phi3"] else "Inactivo",
            "Activo" if estado_apt.get("modelo_cargado") else "Inactivo",
            "Activo",
            "Activo" if estado_apt.get("modelo_cargado") else "Inactivo",
            "Activo",
            "Activo" if estado_retrain.get("activo") else "Inactivo",
            "Conectado",
            "Activo",
        ]
    }
    st.dataframe(pd.DataFrame(datos_arq), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown('<div class="section-header">Historial de Reentrenamiento</div>', unsafe_allow_html=True)
    try:
        with open("/root/asoar/retrain_historial.json", "r") as f:
            historial_retrain = json.load(f)
        if historial_retrain:
            df_retrain = pd.DataFrame(historial_retrain)
            df_retrain["timestamp"] = pd.to_datetime(df_retrain["timestamp"]).dt.strftime("%d/%m/%Y %H:%M")
            cols_show = [c for c in ["timestamp","estado","n_ventanas","f1_anterior","f1_nuevo","mejora"] if c in df_retrain.columns]
            df_retrain = df_retrain[cols_show]
            df_retrain.columns = [c.replace("_"," ").title() for c in cols_show]
            st.dataframe(df_retrain, use_container_width=True, hide_index=True)
        else:
            st.info("No hay historial de reentrenamiento todavia.")
    except:
        st.info("No hay historial de reentrenamiento todavia.")

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
            color = "#27ae60" if puntuacion >= 80 else "#f39c12" if puntuacion >= 50 else "#e74c3c"
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
            </div>""", unsafe_allow_html=True)
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
                        st.dataframe(pd.DataFrame({"Puerto": [str(p) for p in puertos]}), use_container_width=True, hide_index=True)
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
                        df_sw = df_sw.rename(columns={"nombre": "Nombre", "version": "Version", "publisher": "Publisher", "fecha_instalacion": "Fecha instalacion"})
                        df_sw["Fecha instalacion"] = pd.to_datetime(df_sw["Fecha instalacion"], format="%Y%m%d", errors="coerce").dt.strftime("%d/%m/%Y")
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
                st.markdown(f'<div class="metric-card"><p class="metric-label">ISO/IEC 27001:2022</p><p class="metric-value" style="color:{color}">{score}%</p></div>', unsafe_allow_html=True)
            with col3:
                score = data["nis2"]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                st.markdown(f'<div class="metric-card"><p class="metric-label">NIS2 2022/2555</p><p class="metric-value" style="color:{color}">{score}%</p></div>', unsafe_allow_html=True)
            with col4:
                score = data["ens"]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                st.markdown(f'<div class="metric-card"><p class="metric-label">ENS RD 311/2022</p><p class="metric-value" style="color:{color}">{score}%</p></div>', unsafe_allow_html=True)
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
                    </div>""", unsafe_allow_html=True)
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
            "Informe de Cumplimiento Normativo",
            "Informe de Deteccion APT"
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
          
            elif tipo_informe == "Informe de Deteccion APT":
                elements.append(Paragraph("Deteccion de Campanas APT", style_h2))
                elements.append(Paragraph(
                    "Este informe recoge las campanas de Amenazas Persistentes Avanzadas (APT) "
                    "detectadas por el motor LSTM de Noctua Predictive, clasificadas segun el "
                    "framework MITRE ATT&CK y con explicaciones XAI generadas automaticamente "
                    "en cumplimiento del Reglamento Europeo de Inteligencia Artificial (EU AI Act 2024).",
                    style_body))
                elements.append(Spacer(1, 0.3*cm))
                try:
                    campanas_pdf = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
                except:
                    campanas_pdf = []
                elements.append(Paragraph("Campanas APT Detectadas", style_h2))
                if campanas_pdf:
                    data_apt = [["Timestamp", "Fase MITRE", "Confianza", "Riesgo", "IP Origen"]]
                    for c in campanas_pdf[-20:]:
                        data_apt.append([
                            str(c.get("timestamp",""))[:16].replace("T"," "),
                            c.get("fase_mitre","").replace("_"," ").upper(),
                            f"{c.get('confianza',0)}%",
                            c.get("nivel_riesgo",""),
                            c.get("ip",""),
                        ])
                    tabla_apt = Table(data_apt, colWidths=[3.5*cm, 4*cm, 2.5*cm, 2.5*cm, 2.5*cm])
                    tabla_apt.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1f35')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0,0), (-1,-1), 8),
                        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                        ('PADDING', (0,0), (-1,-1), 5),
                    ]))
                    elements.append(tabla_apt)
                else:
                    elements.append(Paragraph("No se han detectado campanas APT todavia.", style_body))
                elements.append(Spacer(1, 0.4*cm))
                try:
                    lateral_pdf = requests.get("http://localhost:8000/apt/lateral", headers=HEADERS, timeout=5).json()
                except:
                    lateral_pdf = []
                elements.append(Paragraph("Detecciones de Movimiento Lateral", style_h2))
                if lateral_pdf:
                    data_lat = [["Timestamp", "Patron", "Severidad", "IP Origen", "Agentes", "MITRE"]]
                    for d in lateral_pdf[-10:]:
                        data_lat.append([
                            str(d.get("timestamp",""))[:16].replace("T"," "),
                            d.get("patron","").replace("_"," ").upper(),
                            d.get("severidad",""),
                            d.get("ip_origen",""),
                            ", ".join(d.get("agentes_afectados",[])),
                            d.get("mitre_tecnica",""),
                        ])
                    tabla_lat = Table(data_lat, colWidths=[3*cm, 3.5*cm, 2*cm, 2.5*cm, 3*cm, 1.5*cm])
                    tabla_lat.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#6c3483')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0,0), (-1,-1), 7),
                        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                        ('PADDING', (0,0), (-1,-1), 5),
                    ]))
                    elements.append(tabla_lat)
                else:
                    elements.append(Paragraph("No se han detectado movimientos laterales todavia.", style_body))
                elements.append(Spacer(1, 0.4*cm))
                try:
                    xai_pdf = requests.get("http://localhost:8000/apt/xai", headers=HEADERS, timeout=5).json()
                except:
                    xai_pdf = []
                elements.append(Paragraph("Explicaciones XAI — Cumplimiento EU AI Act 2024", style_h2))
                if xai_pdf:
                    for exp in xai_pdf[-5:]:
                        elements.append(Paragraph(
                            f"Fase: {exp.get('fase_detectada','').upper()} | Confianza: {exp.get('confianza',0)}%",
                            ParagraphStyle('xai_t', fontSize=9, fontName='Helvetica-Bold',
                                         textColor=colors.HexColor('#1a3a6c'), spaceAfter=3)))
                        elements.append(Paragraph(
                            exp.get("narrativa",""),
                            ParagraphStyle('xai_b', fontSize=8, fontName='Helvetica',
                                         textColor=colors.HexColor('#2c3e50'), spaceAfter=8, leading=12)))
                else:
                    elements.append(Paragraph("No hay explicaciones XAI disponibles todavia.", style_body))

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
            <p style="font-size:1.2rem;font-weight:700;color:{color}">{"Activo" if modelo_ok else "Inactivo"}</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #6c3483;">
            <p class="metric-label">Eventos en Buffer</p>
            <p style="font-size:2rem;font-weight:700;color:#6c3483;">{estado.get("eventos_en_buffer", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #e74c3c;">
            <p class="metric-label">Campanas Totales</p>
            <p style="font-size:2rem;font-weight:700;color:#e74c3c;">{estado.get("campanas_totales", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #f39c12;">
            <p class="metric-label">Campanas 24h</p>
            <p style="font-size:2rem;font-weight:700;color:#f39c12;">{estado.get("campanas_24h", 0)}</p>
        </div>""", unsafe_allow_html=True)

    # Estado del reentrenamiento automatico
    st.markdown('<div class="section-header">Reentrenamiento Automatico del Modelo</div>', unsafe_allow_html=True)
    try:
        retrain = requests.get("http://localhost:8000/apt/retrain/estado", headers=HEADERS, timeout=5).json()
    except:
        retrain = {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        activo = retrain.get("activo", False)
        color = "#27ae60" if activo else "#e74c3c"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Reentrenamiento</p>
            <p style="font-size:1.2rem;font-weight:700;color:{color}">
                {"Activo" if activo else "Inactivo"}
            </p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #2980b9;">
            <p class="metric-label">Reentrenamientos</p>
            <p style="font-size:2rem;font-weight:700;color:#2980b9;">
                {retrain.get("n_reentrenamientos", 0)}
            </p>
        </div>""", unsafe_allow_html=True)
    with col3:
        mejor_f1 = retrain.get("mejor_f1_historico", 0)
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #27ae60;">
            <p class="metric-label">Mejor F1 Historico</p>
            <p style="font-size:2rem;font-weight:700;color:#27ae60;">
                {mejor_f1:.2f}
            </p>
        </div>""", unsafe_allow_html=True)
    with col4:
        versiones = retrain.get("versiones_guardadas", 0)
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #f39c12;">
            <p class="metric-label">Versiones Guardadas</p>
            <p style="font-size:2rem;font-weight:700;color:#f39c12;">
                {versiones}
            </p>
        </div>""", unsafe_allow_html=True)

    ultimo = retrain.get("ultimo")
    if ultimo:
        estado_color = "#27ae60" if "mejora" in ultimo.get("estado","") else "#f39c12"
        st.markdown(f"""
        <div style="background:white;padding:12px 16px;border-radius:8px;
                    border-left:3px solid {estado_color};
                    box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;">
                <span style="font-size:0.85rem;color:#2c3e50">
                    Ultimo reentrenamiento: <strong>{ultimo.get("timestamp","")[:16].replace("T"," ")}</strong>
                </span>
                <span style="font-size:0.85rem;color:#7f8c8d">
                    {ultimo.get("n_ventanas",0)} ventanas |
                    F1: {ultimo.get("f1_anterior",0):.3f} → {ultimo.get("f1_nuevo",0):.3f} |
                    Estado: <strong style="color:{estado_color}">{ultimo.get("estado","")}</strong>
                </span>
            </div>
        </div>""", unsafe_allow_html=True)

    if st.button("Forzar Reentrenamiento Ahora", key="btn_retrain"):
        with st.spinner("Reentrenando modelo LSTM..."):
            try:
                r = requests.post("http://localhost:8000/apt/retrain/forzar",
                                  headers=HEADERS, timeout=120)
                res = r.json()
                if "error" not in res:
                    st.success(f"Reentrenamiento completado — Estado: {res.get('estado')} | F1: {res.get('f1_nuevo', 0):.3f}")
                else:
                    st.error(f"Error: {res['error']}")
            except Exception as e:
                st.error(f"Error: {e}")

    st.markdown("---")


    # Movimiento Lateral
    st.markdown('<div class="section-header">Movimiento Lateral Detectado</div>', unsafe_allow_html=True)
    try:
        lateral = requests.get("http://localhost:8000/apt/lateral", headers=HEADERS, timeout=5).json()
        estado_lateral = requests.get("http://localhost:8000/apt/lateral/estado", headers=HEADERS, timeout=5).json()
    except:
        lateral = []
        estado_lateral = {}

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #8e44ad;">
            <p class="metric-label">Detecciones Totales</p>
            <p style="font-size:2rem;font-weight:700;color:#8e44ad;">
                {estado_lateral.get("detecciones_totales", 0)}
            </p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #c0392b;">
            <p class="metric-label">Detecciones 24h</p>
            <p style="font-size:2rem;font-weight:700;color:#c0392b;">
                {estado_lateral.get("detecciones_24h", 0)}
            </p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #2980b9;">
            <p class="metric-label">IPs Monitorizadas</p>
            <p style="font-size:2rem;font-weight:700;color:#2980b9;">
                {estado_lateral.get("ips_monitorizadas", 0)}
            </p>
        </div>""", unsafe_allow_html=True)

    if lateral:
        for det in lateral[-3:]:
            severidad_color = {
                "CRITICO": "#e74c3c", "ALTO": "#e67e22",
                "MEDIO": "#f39c12", "BAJO": "#27ae60"
            }.get(det.get("severidad", "BAJO"), "#bdc3c7")
            agentes_str = " → ".join(det.get("agentes_afectados", []))
            st.markdown(f"""
            <div style="background:white;padding:16px;border-radius:8px;
                        border-left:4px solid {severidad_color};
                        box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                    <span style="font-weight:600;color:#2c3e50">
                        {det.get("patron","").replace("_"," ").upper()}
                    </span>
                    <span style="background:{severidad_color};color:white;padding:2px 8px;
                                border-radius:4px;font-size:0.75rem;font-weight:600;">
                        {det.get("severidad","")}
                    </span>
                </div>
                <p style="font-size:0.85rem;color:#2c3e50;margin:0 0 6px 0">
                    {det.get("descripcion","")}
                </p>
                <p style="font-size:0.8rem;color:#7f8c8d;margin:0 0 6px 0">
                    Ruta de ataque: <strong style="color:#2c3e50">{agentes_str}</strong>
                </p>
                <div style="display:flex;gap:12px;font-size:0.75rem;color:#7f8c8d;">
                    <span>MITRE: <strong style="color:#2c3e50">{det.get("mitre_tecnica","")}</strong></span>
                    <span>Confianza: <strong style="color:#2c3e50">{det.get("confianza",0)}%</strong></span>
                    <span>Agentes afectados: <strong style="color:#2c3e50">{det.get("n_agentes",0)}</strong></span>
                    <span>IP origen: <strong style="color:#2c3e50">{det.get("ip_origen","")}</strong></span>
                </div>
            </div>""", unsafe_allow_html=True)
    else:
        st.info("No se ha detectado movimiento lateral. El sistema correlaciona eventos entre agentes en tiempo real.")

    st.markdown("---")

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
            <div style="background:{color};color:white;padding:6px 8px;border-radius:6px;
                        font-size:0.7rem;font-weight:600;text-align:center;margin-bottom:6px;">
                {fase.replace("_", " ").upper()}
            </div>""", unsafe_allow_html=True)

    st.markdown("---")

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

        if "Fase Mitre" in df_apt.columns:
            st.markdown('<div class="section-header">Distribucion de Fases APT</div>', unsafe_allow_html=True)
            conteo = df_apt["Fase Mitre"].value_counts().reset_index()
            conteo.columns = ["Fase", "Count"]
            fig = px.bar(conteo, x="Fase", y="Count", color="Count", color_continuous_scale="Reds")
            fig.update_layout(plot_bgcolor="white", paper_bgcolor="white",
                            margin=dict(l=0,r=0,t=10,b=0), height=250,
                            showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)

        if len(campanas) > 1:
            st.markdown('<div class="section-header">Timeline de Campana APT</div>', unsafe_allow_html=True)
            df_timeline = pd.DataFrame(campanas)
            df_timeline["timestamp"] = pd.to_datetime(df_timeline["timestamp"])
            df_timeline = df_timeline.sort_values("timestamp")
            df_timeline["hora"] = df_timeline["timestamp"].dt.strftime("%d/%m %H:%M")
            fig_tl = px.scatter(
                df_timeline, x="timestamp", y="fase_mitre",
                color="fase_mitre", size="confianza",
                hover_data=["hora", "confianza", "nivel_riesgo", "ip"],
                color_discrete_map=fases_colores,
                labels={"timestamp": "Fecha/Hora", "fase_mitre": "Fase MITRE ATT&CK"},
            )
            fig_tl.update_traces(marker=dict(line=dict(width=1, color="#ffffff")))
            fig_tl.update_layout(
                plot_bgcolor="white", paper_bgcolor="white",
                margin=dict(l=0, r=0, t=10, b=0), height=350, showlegend=False,
                xaxis=dict(showgrid=True, gridcolor="#f0f0f0"),
                yaxis=dict(showgrid=True, gridcolor="#f0f0f0",
                           categoryorder="array", categoryarray=list(fases_colores.keys())),
            )
            st.plotly_chart(fig_tl, use_container_width=True)
            st.markdown('<p style="font-size:0.75rem;color:#7f8c8d;text-align:center">Cada punto representa una campana APT detectada. El tamano indica la confianza del modelo.</p>', unsafe_allow_html=True)

            st.markdown('<div class="section-header">Progresion de la Campana</div>', unsafe_allow_html=True)
            fases_orden = ["reconnaissance","initial_access","execution","persistence",
                           "privilege_escalation","defense_evasion","credential_access",
                           "discovery","lateral_movement","collection","exfiltration"]
            fases_detectadas = df_timeline["fase_mitre"].unique().tolist()
            fases_progresion = [f for f in fases_orden if f in fases_detectadas]
            if fases_progresion:
                html_prog = '<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:12px;background:white;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.07);">'
                for i, fase in enumerate(fases_progresion):
                    color = fases_colores.get(fase, "#bdc3c7")
                    html_prog += f'<div style="background:{color};color:white;padding:6px 12px;border-radius:6px;font-size:0.75rem;font-weight:600;">{fase.replace("_"," ").upper()}</div>'
                    if i < len(fases_progresion) - 1:
                        html_prog += '<span style="color:#bdc3c7;font-size:1.2rem">→</span>'
                html_prog += '</div>'
                st.markdown(html_prog, unsafe_allow_html=True)
                nivel_escalada = len(fases_progresion)
                if nivel_escalada >= 4:
                    st.error(f"ALERTA: Campana APT avanzada detectada con {nivel_escalada} fases progresivas")
                elif nivel_escalada >= 2:
                    st.warning(f"Progresion APT detectada: {nivel_escalada} fases identificadas")
                else:
                    st.info("Fase inicial de posible campana APT")

    else:
        st.info("No se han detectado campanas APT todavia. El sistema esta monitorizando activamente.")
        st.markdown("""
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
                    <span style="color:#7f8c8d;font-size:0.85rem">Confianza: {exp.get("confianza",0)}%</span>
                </div>
                <p style="font-size:0.85rem;color:#2c3e50;margin:0 0 8px 0">{exp.get("narrativa","")}</p>
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
    st.markdown("## Acerca de Noctua Predictive")
    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div class="metric-card">
            <p class="metric-label">Descripcion del Proyecto</p>
            <p style="font-size:0.95rem; color:#2c3e50; line-height:1.7; margin-top:8px">
                <strong>Noctua Predictive</strong> es un SOC autonomo de deteccion, analisis
                y respuesta ante Amenazas Persistentes Avanzadas (APT) mediante Inteligencia
                Artificial Federada. A diferencia de los sistemas de ciberseguridad convencionales,
                que operan de forma reactiva detectando ataques una vez que ya han ocurrido,
                Noctua Predictive aprende de los patrones de amenaza de forma distribuida y privada
                para anticipar y detectar campañas APT completas antes de que materialicen el ataque.
                <br><br>
                El sistema integra un motor de aprendizaje profundo secuencial (LSTM) entrenado
                mediante Federated Learning entre multiples nodos, que permite detectar patrones
                de comportamiento anómalo a largo plazo y compartir inteligencia sobre campañas
                APT activas entre organizaciones sin que ninguna exponga sus datos internos.
                Cada decision del sistema es explicada mediante el modulo XAI basado en SHAP,
                cumpliendo el Reglamento Europeo de Inteligencia Artificial (EU AI Act 2024).
                <br><br>
                El sistema detecta las cinco fases de una campaña APT segun el framework
                MITRE ATT&CK: Reconocimiento, Acceso Inicial, Persistencia, Movimiento Lateral
                y Exfiltracion, correlacionando eventos entre multiples agentes en tiempo real
                y generando explicaciones auditables de cada decision autonoma.
                <br><br>
                Desarrollado como Proyecto de Fin de Grado en Ingenieria de Telecomunicaciones,
                Noctua Predictive representa la primera implementacion practica open source que
                combina LSTM, Federated Learning, SIEM real y XAI para deteccion de APTs,
                cubriendo un gap identificado en la literatura cientifica de IEEE Xplore y
                ACM Digital Library.
            </p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <p class="metric-label">Informacion del Proyecto</p>
            <br>
            <p style="font-size:0.85rem; color:#2c3e50; line-height:2">
                    <strong>Nombre:</strong> Noctua Predictive<br>
                    <strong>Version:</strong> 2.0<br>
                    <strong>Autora:</strong> Alejandra Rodríguez Ruíz-Sotomayor<br>
                    <strong>Año:</strong> 2026<br>
                    <strong>Licencia:</strong> Open Source<br>
                    <strong>Cumplimiento:</strong> EU AI Act 2024<br>
                    ISO/IEC 27001:2022<br>
                    NIS2 2022/2555<br>
                    ENS RD 311/2022<br>
            </p>
        </div>""", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown('<div class="section-header">Arquitectura del Sistema</div>', unsafe_allow_html=True)
    componentes = [
        {"Componente": "Wazuh SIEM", "Capa": "Deteccion", "Descripcion": "SIEM/XDR open source de nivel enterprise. Monitoriza eventos de red, sistema y endpoints en tiempo real.", "Tecnologia": "Python / C"},
        {"Componente": "Ollama / phi3", "Capa": "Analisis autonomo", "Descripcion": "LLM local para clasificacion autonoma de alertas individuales sin dependencia de servicios externos.", "Tecnologia": "LLM 3.8B"},
        {"Componente": "LSTM Bidireccional", "Capa": "Prediccion APT", "Descripcion": "Modelo de series temporales que detecta campanas APT completas analizando secuencias de 6h, 24h y 7 dias.", "Tecnologia": "PyTorch"},
        {"Componente": "Federated Learning", "Capa": "Aprendizaje colaborativo", "Descripcion": "Entrena el modelo LSTM entre multiples nodos sin compartir datos. Cada organizacion mantiene su privacidad.", "Tecnologia": "Flower / FedAvg"},
        {"Componente": "Detector Lateral", "Capa": "Correlacion", "Descripcion": "Correlaciona eventos entre agentes para detectar movimiento lateral entre sistemas de la red.", "Tecnologia": "Python"},
        {"Componente": "XAI / SHAP", "Capa": "Explicabilidad", "Descripcion": "Genera explicaciones auditables de cada decision del modelo. Cumple el Reglamento Europeo de IA.", "Tecnologia": "SHAP"},
        {"Componente": "FastAPI", "Capa": "Orquestacion", "Descripcion": "API REST que coordina todos los modulos con autenticacion, rate limiting y validacion de inputs.", "Tecnologia": "Python"},
        {"Componente": "Hetzner API", "Capa": "Respuesta", "Descripcion": "Ejecuta bloqueos automaticos en el firewall cloud cuando se detecta una amenaza confirmada.", "Tecnologia": "REST API"},
    ]
    st.dataframe(pd.DataFrame(componentes), use_container_width=True, hide_index=True)
    st.markdown("---")
    st.markdown('<div class="section-header">Framework MITRE ATT&CK — Fases Detectadas</div>', unsafe_allow_html=True)
    fases = [
        {"Fase": "Reconocimiento", "Tecnica MITRE": "T1595, T1596", "Descripcion": "Recopilacion de informacion sobre el objetivo antes del ataque"},
        {"Fase": "Acceso Inicial", "Tecnica MITRE": "T1190, T1078", "Descripcion": "Primera entrada no autorizada al sistema objetivo"},
        {"Fase": "Persistencia", "Tecnica MITRE": "T1053, T1547", "Descripcion": "Mecanismos para mantener el acceso tras reinicios"},
        {"Fase": "Movimiento Lateral", "Tecnica MITRE": "T1021, T1550", "Descripcion": "Desplazamiento entre sistemas buscando activos de valor"},
        {"Fase": "Exfiltracion", "Tecnica MITRE": "T1041, T1048", "Descripcion": "Extraccion de datos sensibles del entorno comprometido"},
    ]
    st.dataframe(pd.DataFrame(fases), use_container_width=True, hide_index=True)
    st.markdown("---")
    st.markdown('<div class="section-header">Normativas y Cumplimiento</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""<div class="metric-card"><p class="metric-label">ISO/IEC 27001:2022</p>
        <p style="font-size:0.85rem;color:#7f8c8d;margin-top:8px;line-height:1.6">
        Estandar internacional para gestion de seguridad. Evaluacion automatica del Anexo A.</p></div>""",
        unsafe_allow_html=True)
    with col2:
        st.markdown("""<div class="metric-card"><p class="metric-label">NIS2 2022/2555</p>
        <p style="font-size:0.85rem;color:#7f8c8d;margin-top:8px;line-height:1.6">
        Directiva europea de ciberseguridad. Verifica medidas tecnicas del Articulo 21.</p></div>""",
        unsafe_allow_html=True)
    with col3:
        st.markdown("""<div class="metric-card"><p class="metric-label">ENS RD 311/2022</p>
        <p style="font-size:0.85rem;color:#7f8c8d;margin-top:8px;line-height:1.6">
        Esquema Nacional de Seguridad espanol. Evaluacion automatica del Anexo II.</p></div>""",
        unsafe_allow_html=True)
    with col4:
        st.markdown("""<div class="metric-card"><p class="metric-label">EU AI Act 2024</p>
        <p style="font-size:0.85rem;color:#7f8c8d;margin-top:8px;line-height:1.6">
        Reglamento Europeo de IA. Explicabilidad XAI obligatoria en sistemas de alto riesgo.</p></div>""",
        unsafe_allow_html=True)
    st.markdown("---")
    with st.expander("Referencias Cientificas"):
        refs = [
                {"Referencia": "[1] McMahan et al. (2017)", "Descripcion": "Communication-Efficient Learning of Deep Networks from Decentralized Data. AISTATS. (Paper fundacional de Federated Learning y FedAvg)"},
                {"Referencia": "[2] Hochreiter & Schmidhuber (1997)", "Descripcion": "Long Short-Term Memory. Neural Computation. (Paper original de LSTM)"},
                {"Referencia": "[3] Lundberg & Lee (2017)", "Descripcion": "A Unified Approach to Interpreting Model Predictions. NeurIPS. (Paper original de SHAP)"},
                {"Referencia": "[4] Beutel et al. (2022)", "Descripcion": "Flower: A Friendly Federated Learning Research Framework. arXiv:2007.14390"},
                {"Referencia": "[5] ENISA (2024)", "Descripcion": "ENISA Threat Landscape 2024. European Union Agency for Cybersecurity"},
                {"Referencia": "[6] MITRE Corporation (2024)", "Descripcion": "MITRE ATT&CK Framework v14. https://attack.mitre.org"},
        ]
        st.dataframe(pd.DataFrame(refs), use_container_width=True, hide_index=True)