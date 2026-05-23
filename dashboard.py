import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import subprocess
from dotenv import load_dotenv
load_dotenv()

HETZNER_TOKEN = os.getenv("HETZNER_TOKEN")
HETZNER_FIREWALL_ID = os.getenv("HETZNER_FIREWALL_ID")
API_KEY = os.getenv("API_KEY")

API_KEY = "noctua-2026-secure-key"
HEADERS = {"X-API-Key": API_KEY}

# ── Configuración ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ASOAR - Centro de Operaciones de Seguridad",
    layout="wide",
    initial_sidebar_state="expanded"
)


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
    section[data-testid="stSidebar"] .stButton > button { 
        background: #2c3e50 !important; 
        color: white !important; 
        border: none !important;
        width: 100%;
    }
    section[data-testid="stSidebar"] .stButton > button:hover { 
      background: #1a252f !important; 
    }
    section[data-testid="stSidebar"] .stButton > button p {
        color: white !important;
    }
    .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.07); margin-bottom: 16px; border-top: 3px solid #2c3e50; }
    .metric-card.danger  { border-top-color: #e74c3c; }
    .metric-card.warning { border-top-color: #f39c12; }
    .metric-card.success { border-top-color: #27ae60; }
    .metric-card.info    { border-top-color: #2980b9; }
    .metric-value { font-size: 2rem; font-weight: 700; color: #2c3e50; margin: 4px 0 0 0; }
    .metric-label { font-size: 0.75rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; margin: 0; }
    .section-header { font-size: 0.8rem; font-weight: 700; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; padding: 16px 0 8px 0; border-bottom: 1px solid #ecf0f1; margin-bottom: 16px; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.72rem; font-weight: 600; }
    .badge-green  { background: #d5f5e3; color: #1e8449; }
    .badge-red    { background: #fadbd8; color: #922b21; }
    .badge-yellow { background: #fef9e7; color: #9a7d0a; }
    .service-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 0.9rem; color: #2c3e50; }
    .stButton > button { background: #2c3e50; color: white; border: none; border-radius: 6px; font-weight: 600; }
    .stButton > button:hover { background: #1a252f; color: white; }
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
    pagina = st.radio("", [
        "Panel General",
        "Alertas y Eventos",
        "IPs Bloqueadas",
        "Endpoints",
        "Normativas",
        "Simulador de Ataques",
        "Estado del Sistema"
    ], label_visibility="collapsed")
    st.markdown("---")
    st.markdown(f"**Sesion:** `{datetime.now().strftime('%d/%m/%Y %H:%M')}`")
    if st.button("Actualizar datos"):
        st.cache_data.clear()
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# PANEL GENERAL
# ══════════════════════════════════════════════════════════════════════════════
if pagina == "Panel General":
    st.markdown("## Panel General")
    st.markdown(f"*Ultima actualizacion: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}*")
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
            st.markdown(f'<div class="metric-card info"><p class="metric-label">Total Alertas</p><p class="metric-value">{total}</p></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card warning"><p class="metric-label">Nivel Alto (10+)</p><p class="metric-value">{altas}</p></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card danger"><p class="metric-label">Nivel Critico (12+)</p><p class="metric-value">{criticas}</p></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="metric-card success"><p class="metric-label">IPs Bloqueadas</p><p class="metric-value">{bloqueadas_count}</p></div>', unsafe_allow_html=True)

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
                          "data": {"srcip": ip_atacante}}, headers = HEADERS, timeout=60)
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
                r = requests.post(url, json=payload, headers = HEADERS, timeout=timeout)
            else:
                r = requests.get(url, headers = HEADERS, timeout=timeout)
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
        st.markdown(f"- **Version:** Noctua ASOAR v1.0")
        st.markdown(f"- **Alertas cargadas:** {len(df)}")
        st.markdown(f"- **IPs bloqueadas:** {len(ips_bloqueadas)}")
        st.markdown(f"- **Endpoints activos:** {len(requests.get('http://localhost:8000/agentes', headers=HEADERS, timeout=5).json()) if True else 0}")

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
        r = requests.get("http://localhost:8000/agentes", headers = HEADERS, timeout=5)
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

            # Color de la puntuación
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

            # Rendimiento
            col1, col2 = st.columns(2)
            with col1:
                cpu = rend.get("cpu_porcentaje", 0)
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=cpu,
                    title={"text": "CPU %"},
                    gauge={"axis": {"range": [0, 100]},
                           "bar": {"color": "#e74c3c" if cpu > 80 else "#f39c12" if cpu > 60 else "#27ae60"}}
                ))
                fig.update_layout(height=200, margin=dict(l=30,r=30,t=60,b=30), paper_bgcolor="white")
                st.plotly_chart(fig, use_container_width=True)

            with col2:
                ram = rend.get("ram_porcentaje", 0)
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=ram,
                    title={"text": "RAM %"},
                    gauge={"axis": {"range": [0, 100]},
                           "bar": {"color": "#e74c3c" if ram > 80 else "#f39c12" if ram > 60 else "#27ae60"}}
                ))
                fig.update_layout(height=200, margin=dict(l=30,r=30,t=60,b=30), paper_bgcolor="white")
                st.plotly_chart(fig, use_container_width=True)

            # Puertos
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
                        "nombre": "Nombre",
                        "version": "Version", 
                        "publisher": "Publisher",
                        "fecha_instalacion": "Fecha instalacion"
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
        r = requests.get("http://localhost:8000/agentes", headers = HEADERS, timeout=5)
        agentes = r.json()
    except:
        agentes = {}

    if not agentes:
        st.info("No hay endpoints registrados. Ejecuta el agente PowerShell en un equipo Windows.")
    else:
        hostname_sel = st.selectbox("Selecciona un endpoint", list(agentes.keys()))

        try:
            r = requests.get(f"http://localhost:8000/cumplimiento/{hostname_sel}", headers = HEADERS, timeout=5)
            data = r.json()
        except:
            data = {}

        if data and "score_global" in data:
            # Score global
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

            for key, nombre in [("iso27001", "ISO/IEC 27001:2022"), ("nis2", "NIS2 (Directiva UE 2022/2555)"), ("ens", "Esquema Nacional de Seguridad")]:
                score = data[key]["score"]
                color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                controles = data[key]["controles"]
                ok = sum(1 for c in controles if c["cumple"])
                parcial = len(controles) - ok

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

            # Detalle por normativa
            for key, nombre in [("iso27001", "ISO/IEC 27001:2022"), ("nis2", "NIS2 - Directiva UE 2022/2555"), ("ens", "Esquema Nacional de Seguridad")]:
                st.markdown(f'<div class="section-header">{nombre}</div>', unsafe_allow_html=True)
                controles = data[key]["controles"]

                for ctrl in controles:
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