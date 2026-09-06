import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import subprocess
import os
import sys
import streamlit_authenticator as stauth
from dotenv import load_dotenv
load_dotenv()

# IPs conocidas que no son amenazas reales
IPS_WHITELIST = [
    "47.62.74.87",       # IP propia - acceso al dashboard
    "91.98.126.215",     # IP del servidor Hetzner
    "66.132.0.0/16",     # Censys - escaner de investigacion
    "199.45.155.0/24"    # Censys
    "162.142.125.0/24",  # Shodan
    "198.20.69.0/24",    # Shodan
    "71.6.134.232/29",   # Stretchoid
]

def es_ip_whitelist(ip: str) -> bool:
    """Comprueba si una IP está en la lista blanca."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entrada in IPS_WHITELIST:
            if "/" in entrada:
                if ip_obj in ipaddress.ip_network(entrada, strict=False):
                    return True
            else:
                if str(ip_obj) == entrada:
                    return True
    except:
        pass
    return False

def hora_local():
    return datetime.now() + timedelta(hours=2)

HETZNER_TOKEN = os.getenv("HETZNER_TOKEN")
HETZNER_FIREWALL_ID = os.getenv("HETZNER_FIREWALL_ID")
API_KEY = os.getenv("API_KEY")
HEADERS = {"X-API-Key": API_KEY}
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

def tabla_oscura(df, **kwargs):
    kwargs.pop("use_container_width", None)
    kwargs.pop("hide_index", None)
    html = df.to_html(index=False, border=0)
    html = f"""
    <div style="overflow-x:auto;overflow-y:auto;max-height:300px;border-radius:8px;border:1px solid #21262d;margin-bottom:16px;">
    <style>
    .noctua-table {{ width:100%;border-collapse:collapse;font-size:13px;font-family:sans-serif; }}
    .noctua-table th {{
        background:#010409;color:#8b949e;padding:10px 12px;
        text-align:left;font-size:11px;text-transform:uppercase;
        letter-spacing:0.5px;border-bottom:1px solid #21262d;font-weight:600;
    }}
    .noctua-table td {{
        background:#161b22;color:#c9d1d9;padding:8px 12px;
        border-bottom:1px solid #21262d;
    }}
    .noctua-table tr:nth-child(even) td {{ background:#0d1117; }}
    .noctua-table tr:hover td {{ background:#1c2128; }}
    </style>
    {html.replace('<table', '<table class="noctua-table"')}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

st.set_page_config(
    page_title="Noctua Predictive. — Autonomous Security Operations",
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
    background: #161b22 !important;
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

st.markdown("""
<style>
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"],
    [data-testid="stMainBlockContainer"],
    .main, .stApp { 
        background-color: #0d1117 !important; 
        color-scheme: dark !important;
    }
    [data-testid="stHeader"] { background-color: #0d1117 !important; }
    [data-testid="stForm"] {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
        border-top: 3px solid #388bfd !important;
        border-radius: 12px !important;
        padding: 32px !important;
        max-width: 420px !important;
        margin: 0 auto !important;
    }
    [data-testid="stForm"] * { color: #c9d1d9 !important; }
    [data-testid="stForm"] input {
        background: #0d1117 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
    }
    [data-testid="stForm"] button {
        background: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        width: 100% !important;
    }
    [data-testid="stForm"] button:hover {
        background: #2d333b !important;
        border-color: #388bfd !important;
    }
    [data-testid="stForm"] button[data-testid="stBaseButton-minimal"] {
        width: auto !important;
        padding: 4px 8px !important;
        background: transparent !important;
        border: none !important;
    }
    [data-testid="stForm"] button[data-testid="stBaseButton-minimal"] {
        width: auto !important;
        padding: 4px 8px !important;
        background: transparent !important;
        border: none !important;
    }
    button[aria-label="Show password text"] {
        width: 32px !important;
        height: 32px !important;
        padding: 4px !important;
        background: transparent !important;
        border: none !important;
        min-height: unset !important;
    }
    button[aria-label="Show password text"] svg {
        width: 16px !important;
        height: 16px !important;
        fill: #8b949e !important;
    }
    [data-baseweb="base-input"] button {
        width: 32px !important;
        height: 32px !important;
        min-height: unset !important;
        padding: 4px !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }
    [data-baseweb="base-input"] button svg {
        width: 16px !important;
        height: 16px !important;
        fill: #8b949e !important;
    }
    button[aria-label="Show password text"],
    button[aria-label="Hide password text"] {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        width: 36px !important;
        min-height: unset !important;
        height: 36px !important;
        padding: 6px !important;
    }
    button[aria-label="Show password text"] svg,
    button[aria-label="Hide password text"] svg {
        fill: #8b949e !important;
        width: 18px !important;
        height: 18px !important;
    }
    label, p, span { color: #c9d1d9 !important; }

    /* ── TEXTAREA ────────────────────────────────────────────────────────── */
    textarea {
        background: #161b22 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
    }
    textarea:focus {
        border: 1px solid #388bfd !important;
        box-shadow: 0 0 0 3px rgba(56,139,253,0.15) !important;
    }


</style>
""", unsafe_allow_html=True)

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

if authentication_status is False:
    st.error("Usuario o contrasena incorrectos")
    st.stop()

if authentication_status is None:
    st.stop()

# ── Verificacion MFA ──────────────────────────────────────────────────────────
sys.path.insert(0, '/root/asoar')
try:
    from mfa import mfa_activo, verificar_codigo, generar_qr_bytes, generar_secreto, guardar_config_mfa, obtener_secreto
    MFA_DISPONIBLE = True
except Exception as e:
    print(f"MFA error: {e}")
    MFA_DISPONIBLE = False

if MFA_DISPONIBLE and mfa_activo(username):
    if not st.session_state.get("mfa_verificado"):
        st.markdown("---")
        _, col_center, _ = st.columns([1, 2, 1])
        with col_center:
            st.markdown("""
            <div style="background:#161b22;padding:32px;border-radius:12px;
                        box-shadow:0 4px 20px rgba(0,0,0,0.1);
                        border-top:3px solid #1a3a6c;text-align:center;">
                <p style="font-size:1.1rem;font-weight:700;color:#1a3a6c;margin-bottom:8px">
                    Verificacion MFA
                </p>
                <p style="font-size:0.85rem;color:#7f8c8d;margin-bottom:16px">
                    Introduce el codigo de 6 digitos de tu app autenticadora
                </p>
            </div>""", unsafe_allow_html=True)
            with st.form("form_mfa"):
                codigo_mfa = st.text_input("Codigo MFA", max_chars=6, placeholder="000000")
                submitted = st.form_submit_button("Verificar", use_container_width=True, type="primary")
                if submitted:
                    if verificar_codigo(username, codigo_mfa):
                        st.session_state.mfa_verificado = True
                        st.rerun()
                    else:
                        st.error("Codigo incorrecto. Intentalo de nuevo.")
        st.stop()

# ── Wizard MFA ────────────────────────────────────────────────────────────────
if st.session_state.get("mfa_wizard"):
    paso = st.session_state.get("mfa_paso", 1)
    _, col_center, _ = st.columns([1, 2, 1])
    with col_center:
        if paso == 1:
            st.markdown("""
            <div style="background:#161b22;padding:40px 32px;border-radius:16px;
                        box-shadow:0 8px 32px rgba(0,0,0,0.15);
                        border-top:4px solid #1a3a6c;text-align:center;">
                <div style="font-size:2.5rem;margin-bottom:16px"></div>
                <p style="font-size:1.3rem;font-weight:700;color:#1a3a6c;margin-bottom:12px">
                    Autenticacion de Doble Factor
                </p>
                <p style="font-size:0.95rem;color:#7f8c8d;line-height:1.6;margin-bottom:24px">
                    Vamos a garantizar la seguridad de tu cuenta activando
                    la autenticacion de doble factor (2FA). Este proceso
                    solo tarda 2 minutos.
                </p>
                <p style="font-size:0.8rem;color:#bdc3c7;">Paso 1 de 5</p>
            </div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Cancelar", key="mfa_cancel_1", use_container_width=True):
                    st.session_state.pop("mfa_wizard", None)
                    st.session_state.pop("mfa_paso", None)
                    st.rerun()
            with col2:
                if st.button("Siguiente →", key="mfa_next_1", use_container_width=True, type="primary"):
                    st.session_state.mfa_paso = 2
                    st.rerun()

        elif paso == 2:
            st.markdown("""
            <div style="background:#161b22;padding:40px 32px;border-radius:16px;
                        box-shadow:0 8px 32px rgba(0,0,0,0.15);
                        border-top:4px solid #1a3a6c;text-align:center;">
                <div style="font-size:2.5rem;margin-bottom:16px">📱</div>
                <p style="font-size:1.3rem;font-weight:700;color:#1a3a6c;margin-bottom:12px">
                    Instala la App Autenticadora
                </p>
                <p style="font-size:0.9rem;color:#7f8c8d;line-height:1.6;margin-bottom:20px">
                    Necesitas una aplicacion de autenticacion en tu movil.
                    Si ya la tienes instalada, pulsa Siguiente.
                </p>
                <div style="display:flex;gap:16px;justify-content:center;margin-bottom:20px;">
                    <a href="https://play.google.com/store/apps/details?id=com.beemdevelopment.aegis"
                       target="_blank"
                       style="background:#1a3a6c;color:white;padding:12px 20px;border-radius:8px;
                              text-decoration:none;font-size:0.85rem;font-weight:600;">
                        🤖 Android — Aegis
                    </a>
                    <a href="https://apps.apple.com/app/google-authenticator/id388497605"
                       target="_blank"
                       style="background:#2d6aa0;color:white;padding:12px 20px;border-radius:8px;
                              text-decoration:none;font-size:0.85rem;font-weight:600;">
                        🍎 iPhone — Google Auth
                    </a>
                </div>
                <p style="font-size:0.8rem;color:#bdc3c7;">Paso 2 de 5</p>
            </div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("← Atrás", key="mfa_back_2", use_container_width=True):
                    st.session_state.mfa_paso = 1
                    st.rerun()
            with col2:
                if st.button("Siguiente →", key="mfa_next_2", use_container_width=True, type="primary"):
                    st.session_state.mfa_paso = 3
                    st.rerun()

        elif paso == 3:
            st.markdown("""
            <div style="background:#161b22;padding:40px 32px;border-radius:16px;
                        box-shadow:0 8px 32px rgba(0,0,0,0.15);
                        border-top:4px solid #1a3a6c;text-align:center;">
                <div style="font-size:2.5rem;margin-bottom:16px">⚙️</div>
                <p style="font-size:1.3rem;font-weight:700;color:#1a3a6c;margin-bottom:12px">
                    Configurar la Cuenta en la Aplicacion
                </p>
                <p style="font-size:0.9rem;color:#7f8c8d;line-height:1.6;margin-bottom:20px">
                    En el siguiente paso vamos a generar un codigo QR unico
                    para vincular tu cuenta de Noctua Predictive con la
                    aplicacion autenticadora. Asegurate de tener el movil
                    a mano antes de continuar.
                </p>
                <p style="font-size:0.8rem;color:#bdc3c7;">Paso 3 de 5</p>
            </div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("← Atrás", key="mfa_back_3", use_container_width=True):
                    st.session_state.mfa_paso = 2
                    st.rerun()
            with col2:
                if st.button("Siguiente →", key="mfa_next_3", use_container_width=True, type="primary"):
                    secreto_nuevo = generar_secreto()
                    guardar_config_mfa(username, secreto_nuevo, activo=True)
                    st.session_state.mfa_secreto_nuevo = secreto_nuevo
                    st.session_state.mfa_paso = 4
                    st.rerun()

        elif paso == 4:
            st.markdown("""
            <div style="background:#161b22;padding:40px 32px;border-radius:16px;
                        box-shadow:0 8px 32px rgba(0,0,0,0.15);
                        border-top:4px solid #1a3a6c;text-align:center;">
                <div style="font-size:2.5rem;margin-bottom:8px">📷</div>
                <p style="font-size:1.3rem;font-weight:700;color:#1a3a6c;margin-bottom:8px">
                    Digitalizacion del Codigo QR
                </p>
                <p style="font-size:0.9rem;color:#7f8c8d;line-height:1.6;margin-bottom:16px">
                    Usa la aplicacion para escanear el codigo QR,
                    despues vuelve y selecciona Siguiente.
                </p>
            </div>""", unsafe_allow_html=True)
            if "mfa_secreto_nuevo" in st.session_state:
                qr_bytes = generar_qr_bytes(username, st.session_state.mfa_secreto_nuevo)
                _, col_qr, _ = st.columns([1, 2, 1])
                with col_qr:
                    st.image(qr_bytes, width=220)
                st.markdown(f"""
                <p style="text-align:center;font-size:0.8rem;color:#7f8c8d;margin-top:8px">
                    O introduce el secreto manualmente:<br>
                    <code style="background:#161b22;padding:4px 8px;border-radius:4px;
                                 font-size:0.75rem;color:#1a3a6c">
                        {st.session_state.mfa_secreto_nuevo}
                    </code>
                </p>
                <p style="text-align:center;font-size:0.75rem;color:#bdc3c7;margin-top:8px">
                    Paso 4 de 5
                </p>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("← Atrás", key="mfa_back_4", use_container_width=True):
                    st.session_state.mfa_paso = 3
                    st.rerun()
            with col2:
                if st.button("Siguiente →", key="mfa_next_4", use_container_width=True, type="primary"):
                    st.session_state.mfa_paso = 5
                    st.rerun()

        elif paso == 5:
            st.markdown("""
            <div style="background:#161b22;padding:40px 32px;border-radius:16px;
                        box-shadow:0 8px 32px rgba(0,0,0,0.15);
                        border-top:4px solid #27ae60;text-align:center;">
                <div style="font-size:2.5rem;margin-bottom:16px"></div>
                <p style="font-size:1.3rem;font-weight:700;color:#1a3a6c;margin-bottom:12px">
                    Verificacion Final
                </p>
                <p style="font-size:0.9rem;color:#7f8c8d;line-height:1.6;margin-bottom:20px">
                    Introduce el codigo de 6 digitos que aparece en tu
                    aplicacion autenticadora para completar la configuracion.
                </p>
                <p style="font-size:0.8rem;color:#bdc3c7;">Paso 5 de 5</p>
            </div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            codigo_verificacion = st.text_input(
                "Codigo de verificacion", max_chars=6,
                placeholder="000000", key="mfa_codigo_verify"
            )
            col1, col2 = st.columns(2)
            with col1:
                if st.button("← Atrás", key="mfa_back_5", use_container_width=True):
                    st.session_state.mfa_paso = 4
                    st.rerun()
            with col2:
                if st.button("Activar MFA", key="mfa_activar", use_container_width=True, type="primary"):
                    if verificar_codigo(username, codigo_verificacion):
                        st.session_state.pop("mfa_wizard", None)
                        st.session_state.pop("mfa_paso", None)
                        st.session_state.pop("mfa_secreto_nuevo", None)
                        st.session_state.mfa_verificado = True
                        st.success("MFA activado correctamente.")
                        st.rerun()
                    else:
                        st.error("Codigo incorrecto. Verifica la app e intentalo de nuevo.")
    st.stop()

notif_file = "/root/asoar/notificaciones.json"
if os.path.exists(notif_file):
    try:
        with open(notif_file, "r") as f:
            notifs = json.load(f)
        no_leidas = [n for n in notifs if not n.get("leida")]
        if no_leidas:
            for n in notifs:
                n["leida"] = True
            with open(notif_file, "w") as f:
                json.dump(notifs, f, indent=2)
            for n in no_leidas:
                st.toast(f"IP bloqueada: {n['ip']}", icon="🔒")
    except:
        pass

st.markdown("""<style>

    /* ── BASE OSCURA ─────────────────────────────────────────────────────── */
    :root { color-scheme: dark !important; }
    html, body, [class*="css"],
    [data-testid="stAppViewContainer"],
    [data-testid="stMainBlockContainer"] {
        color-scheme: dark !important;
        background-color: #0d1117 !important;
        color: #e6edf3 !important;
    }
    [data-testid="stHeader"]      { background-color: #0d1117 !important; border-bottom: 1px solid #21262d; }
    [data-testid="stMain"]        { background-color: #0d1117 !important; }
    .main, .stApp                 { background-color: #0d1117 !important; }
    [data-testid="block-container"]{ background-color: #0d1117 !important; }

    /* ── SIDEBAR ─────────────────────────────────────────────────────────── */
    section[data-testid="stSidebar"] {
        background-color: #010409 !important;
        border-right: 1px solid #21262d !important;
    }
    section[data-testid="stSidebar"] * { color: #8b949e !important; }
    section[data-testid="stSidebar"] label { color: #8b949e !important; font-weight: 500; }

    section[data-testid="stSidebar"] .stButton > button[kind="secondary"] {
        background: transparent !important;
        color: #8b949e !important;
        border: 1px solid #21262d !important;
        width: 100% !important;
        text-align: left !important;
        margin-bottom: 4px !important;
        border-radius: 6px !important;
        transition: all 0.15s ease !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover {
        background: #161b22 !important;
        color: #e6edf3 !important;
        border-color: #388bfd !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="secondary"] p { color: #8b949e !important; }

    section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #1f6feb, #388bfd) !important;
        color: white !important;
        border: none !important;
        width: 100% !important;
        text-align: left !important;
        margin-bottom: 4px !important;
        border-radius: 6px !important;
        box-shadow: 0 0 12px rgba(56,139,253,0.3) !important;
    }
    section[data-testid="stSidebar"] .stButton > button[kind="primary"] p { color: white !important; }
    section[data-testid="stSidebar"] .stButton > button:hover { opacity: 0.9 !important; }

    /* ── TIPOGRAFIA GLOBAL ───────────────────────────────────────────────── */
    h1, h2, h3, h4 { color: #e6edf3 !important; letter-spacing: -0.3px; }
    p, span, div, li { color: #c9d1d9 !important; }
    .stMarkdown p  { color: #c9d1d9 !important; }

    /* ── METRIC CARDS ────────────────────────────────────────────────────── */
    .metric-card {
        background: #161b22;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.4);
        margin-bottom: 16px;
        border: 1px solid #21262d;
        border-top: 3px solid #388bfd;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.5) !important;
        border-color: #388bfd !important;
    }
    .metric-card.danger  { border-top-color: #f85149; }
    .metric-card.warning { border-top-color: #d29922; }
    .metric-card.success { border-top-color: #3fb950; }
    .metric-card.info    { border-top-color: #388bfd; }

    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #e6edf3 !important;
        margin: 6px 0 0 0;
        animation: fadeInUp 0.5s ease;
        font-variant-numeric: tabular-nums;
    }
    .metric-label {
        font-size: 0.72rem;
        color: #8b949e !important;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin: 0;
        font-weight: 600;
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    /* ── SECTION HEADER ──────────────────────────────────────────────────── */
    .section-header {
        font-size: 0.72rem;
        font-weight: 700;
        color: #388bfd !important;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        padding: 16px 0 8px 0;
        border-bottom: 1px solid #21262d;
        margin-bottom: 16px;
    }

    /* ── BADGES ──────────────────────────────────────────────────────────── */
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.72rem; font-weight: 600; }
    .badge-green  { background: #1a4a2e; color: #3fb950; border: 1px solid #2ea043; }
    .badge-red    { background: #3d1515; color: #f85149; border: 1px solid #8b1a1a; }
    .badge-yellow { background: #3d2e00; color: #d29922; border: 1px solid #9e6a03; }
    .badge-blue   { background: #0d2d6b; color: #79c0ff; border: 1px solid #1f6feb; }

    /* ── SERVICE ROW ─────────────────────────────────────────────────────── */
    .service-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 0;
        border-bottom: 1px solid #21262d;
        font-size: 0.9rem;
        color: #c9d1d9 !important;
    }

    /* ── ALERTA CRITICA ──────────────────────────────────────────────────── */
    @keyframes parpadeo {
        0%, 100% { background-color: #1a0a0a; border-color: #f85149; }
        50%       { background-color: #2d0f0f; border-color: #ff6b6b; }
    }
    .critica-alert {
        animation: parpadeo 1.2s infinite;
        border-top: 3px solid #f85149 !important;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 0 20px rgba(248,81,73,0.2);
        margin-bottom: 16px;
    }


    /* ── BOTONES GLOBALES ────────────────────────────────────────────────── */
    .stButton > button {
        background: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button:hover {
        background: #388bfd !important;
        color: white !important;
        border-color: #388bfd !important;
        box-shadow: 0 0 12px rgba(56,139,253,0.4) !important;
    }

    /* ── INPUTS ──────────────────────────────────────────────────────────── */
    div[data-testid="stForm"] { max-width: 420px !important; margin: 0 auto !important; }
    input[type="text"], input[type="password"] {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
        color: #e6edf3 !important;
        padding: 8px 12px !important;
    }
    input[type="text"]:focus, input[type="password"]:focus {
        border: 1px solid #388bfd !important;
        box-shadow: 0 0 0 3px rgba(56,139,253,0.15) !important;
        outline: none !important;
    }
    div[data-baseweb="input"] {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
    }
    div[data-baseweb="base-input"]:hover { border-color: #388bfd !important; }

    /* ── TABLAS STREAMLIT ────────────────────────────────────────────────── */
    [data-testid="stDataFrame"] table,
    .stDataFrame table {
        background: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #21262d !important;
    }
    [data-testid="stDataFrame"] th {
        background: #010409 !important;
        color: #8b949e !important;
        border-bottom: 1px solid #21262d !important;
        font-size: 0.75rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }
    [data-testid="stDataFrame"] td {
        border-bottom: 1px solid #21262d !important;
        color: #c9d1d9 !important;
    }
    [data-testid="stDataFrame"] tr:hover td { background: #1c2128 !important; }

    /* ── SELECTBOX / MULTISELECT ─────────────────────────────────────────── */
    [data-baseweb="select"] > div {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 6px !important;
        color: #e6edf3 !important;
    }
    [data-baseweb="select"] span { color: #e6edf3 !important; }
    [data-baseweb="menu"] { background: #161b22 !important; border: 1px solid #30363d !important; }
    [data-baseweb="option"]:hover { background: #1f6feb !important; }

    /* ── TABS ────────────────────────────────────────────────────────────── */
    [data-testid="stTabs"] [data-baseweb="tab-list"] {
        background: transparent !important;
        border-bottom: 1px solid #21262d !important;
        gap: 4px !important;
    }
    [data-testid="stTabs"] [data-baseweb="tab"] {
        background: transparent !important;
        color: #8b949e !important;
        border-radius: 6px 6px 0 0 !important;
        font-weight: 500 !important;
        padding: 8px 16px !important;
    }
    [data-testid="stTabs"] [aria-selected="true"] {
        background: #161b22 !important;
        color: #e6edf3 !important;
        border-bottom: 2px solid #388bfd !important;
    }
    [data-testid="stTabs"] [data-baseweb="tab"]:hover {
        color: #e6edf3 !important;
        background: #1c2128 !important;
    }

    /* ── MÉTRICAS NATIVAS STREAMLIT ──────────────────────────────────────── */
    [data-testid="stMetric"] {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
        border-radius: 8px !important;
        padding: 16px !important;
    }
    [data-testid="stMetricValue"] { color: #e6edf3 !important; font-weight: 700 !important; }
    [data-testid="stMetricLabel"] { color: #8b949e !important; }
    [data-testid="stMetricDelta"] svg { fill: #3fb950 !important; }

    /* ── SCROLLBAR ───────────────────────────────────────────────────────── */
    ::-webkit-scrollbar       { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0d1117; }
    ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #388bfd; }

    /* ── TOASTS / NOTIFICACIONES ─────────────────────────────────────────── */
    [data-testid="stAlert"] {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
        border-radius: 8px !important;
        color: #c9d1d9 !important;
    }

    /* ── GLOW EFFECT EN CARDS CRITICAS ──────────────────────────────────── */
    .metric-card.danger:hover {
        box-shadow: 0 0 20px rgba(248,81,73,0.25) !important;
    }
    .metric-card.success:hover {
        box-shadow: 0 0 20px rgba(63,185,80,0.2) !important;
    }

    /* ── PLOTLY OVERRIDE — ejes y grid oscuros ───────────────────────────── */
    .js-plotly-plot .plotly .gridlayer path { stroke: #21262d !important; }
    .js-plotly-plot .plotly text { fill: #8b949e !important; }
    .js-plotly-plot .plotly .bg { fill: #0d1117 !important; }

    /* ── BOTONES PRIMARY EN AZUL ─────────────────────────────────────────── */
    .main .stButton > button[kind="primary"],
    .main .stDownloadButton > button {
        background: linear-gradient(135deg, #1f6feb, #388bfd) !important;
        color: white !important;
        border: none !important;
        box-shadow: 0 0 12px rgba(56,139,253,0.3) !important;
    }
    .main .stButton > button[kind="primary"]:hover,
    .main .stDownloadButton > button:hover {
        background: linear-gradient(135deg, #388bfd, #58a6ff) !important;
        box-shadow: 0 0 20px rgba(56,139,253,0.5) !important;
    }

    /* ── BOTONES SECUNDARIOS CONTENIDO PRINCIPAL ─────────────────────────── */
    .main .stButton > button[kind="secondary"] {
        background: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
    }
    .main .stButton > button[kind="secondary"]:hover {
        background: #2d333b !important;
        border-color: #388bfd !important;
    }
    /* ── DOWNLOAD BUTTON EN GRIS ─────────────────────────────────────────── */
    .stDownloadButton > button {
        background: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
    }
    .stDownloadButton > button:hover {
        background: #388bfd !important;
        border-color: #388bfd !important;
    }

    /* ── DROPDOWN OPCIONES ───────────────────────────────────────────────── */
    [data-baseweb="popover"] {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
    }
    [data-baseweb="menu"] {
        background: #161b22 !important;
    }
    [data-baseweb="option"] {
        background: #161b22 !important;
        color: #c9d1d9 !important;
    }
    [data-baseweb="option"]:hover {
        background: #1f6feb !important;
        color: white !important;
    }
    li[role="option"] {
        background: #161b22 !important;
        color: #c9d1d9 !important;
    }
    li[role="option"]:hover {
        background: #1f6feb !important;
        color: white !important;
    }

    /* ── SPINNER / RECARGA ───────────────────────────────────────────────── */
    [data-testid="stStatusWidget"] {
        background: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #21262d !important;
    }
    [data-testid="stStatusWidget"] span {
        color: #c9d1d9 !important;
    }
    div[class*="StatusWidget"] {
        background: #161b22 !important;
        color: #c9d1d9 !important;
    }
    
    /* ── EXPANDER CONTENIDO ──────────────────────────────────────────────── */
    [data-testid="stExpander"] details {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
        border-radius: 8px !important;
    }
    [data-testid="stExpander"] summary {
        background: #161b22 !important;
        color: #c9d1d9 !important;
    }
    [data-testid="stExpander"] summary:hover {
        color: #388bfd !important;
    }

</style>""", unsafe_allow_html=True)


@st.cache_data(ttl=300)
def cargar_alertas_wazuh():
    try:
        result = subprocess.run(
            ["bash", "-c", "{ find /var/ossec/logs/alerts/2026/Aug -name '*.json.gz' -exec zcat {} \\; 2>/dev/null; find /var/ossec/logs/alerts/2026/Jul -name '*.json.gz' -exec zcat {} \\; 2>/dev/null; cat /var/ossec/logs/alerts/alerts.json 2>/dev/null; } | strings | tail -n 15000"],
            capture_output=True, text=True, timeout=30
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
                    "ip": a.get("data", {}).get("srcip") or a.get("data", {}).get("src_ip") or a.get("agent", {}).get("ip", "N/A"),                    
                    "agente": a.get("agent", {}).get("name", "master").replace("soc-autonomo-master", "Noctua-Server"),
                    "id_regla": str(a.get("rule", {}).get("id", "")),
                    "accion": "BLOQUEADA" if int(a.get("rule", {}).get("level", 0)) >= 10 else "MONITORIZADA"
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
                if reg.get("direction") == "in" 
                and "ASOAR" in reg.get("description", "")
                and reg.get("source_ips", [""])[0] not in ["0.0.0.0/0", "::/0", ""]
            ]
    except:
        pass
    return []

@st.cache_data(ttl=30)
def cargar_suricata():
    """Lee las alertas recientes de Suricata desde eve.json."""
    try:
        import gzip
        alertas = []
        flows = []
        # Leer el archivo actual sin comprimir
        import subprocess
        result = subprocess.run(
            ["tail", "-n", "20000", "/var/log/suricata/eve.json"],
            capture_output=True, text=True, errors="ignore"
        )
        for line in result.stdout.splitlines():
                try:
                    e = json.loads(line)
                    tipo = e.get("event_type", "")
                    if tipo == "alert":
                        alertas.append({
                            "timestamp": e.get("timestamp", ""),
                            "src_ip":    e.get("src_ip", ""),
                            "dest_port": e.get("dest_port", 0),
                            "proto":     e.get("proto", ""),
                            "firma":     e.get("alert", {}).get("signature", ""),
                            "categoria": e.get("alert", {}).get("category", ""),
                            "severidad": e.get("alert", {}).get("severity", 3),
                        })
                    elif tipo == "flow":
                        flows.append({
                            "src_ip":         e.get("src_ip", ""),
                            "dest_port":      e.get("dest_port", 0),
                            "proto":          e.get("proto", ""),
                            "pkts_toserver":  e.get("flow", {}).get("pkts_toserver", 0),
                            "bytes_toserver": e.get("flow", {}).get("bytes_toserver", 0),
                        })
                except:
                    continue
        return {"alertas": alertas, "flows": flows}
    except Exception as e:
        return {"alertas": [], "flows": []}

@st.cache_data(ttl=86400)
def consultar_abuseipdb(ip: str) -> dict:
    """Consulta la reputacion de una IP en AbuseIPDB."""
    if not ABUSEIPDB_API_KEY or ip in ["0.0.0.0", "127.0.0.1", ""]:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "score":        data.get("abuseConfidenceScore", 0),
                "pais":         data.get("countryCode", ""),
                "reportes":     data.get("totalReports", 0),
                "ultimo_reporte": data.get("lastReportedAt", ""),
                "dominio":      data.get("domain", ""),
                "isp":          data.get("isp", ""),
                "es_tor":       data.get("isTor", False),
            }
    except Exception:
        pass
    return {}

@st.cache_data(ttl=86400)
def enriquecer_ip(ip: str) -> dict:
    """Obtiene ASN, dominio inverso y geolocalización de una IP via ip-api.com."""
    if ip in ["0.0.0.0", "127.0.0.1", "", "91.98.126.215"]:
        return {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as,reverse,hosting"},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "pais":          data.get("country", ""),
                    "pais_codigo":   data.get("countryCode", ""),
                    "region":        data.get("regionName", ""),
                    "ciudad":        data.get("city", ""),
                    "isp":           data.get("isp", ""),
                    "org":           data.get("org", ""),
                    "asn":           data.get("as", ""),
                    "ptr":           data.get("reverse", ""),
                    "es_datacenter": data.get("hosting", False),
                }
    except Exception:
        pass
    return {}

df = cargar_alertas_wazuh()
ips_bloqueadas = cargar_ips_hetzner()

with st.sidebar:
    with open("/root/asoar/static/noctua_logo.svg", "r") as f:
        logo_svg = f.read()
    st.markdown(logo_svg, unsafe_allow_html=True)
    st.markdown("---")
    opciones = [
        "Panel General", "Alertas y Eventos", "IPs Bloqueadas",
        "Endpoints", "Detección APT", "Tráfico de Red",
        "Análisis Forense", "Threat Hunting", "Gestión de Incidentes", "Normativas",
        "Playbooks", "Simulador de Ataques", "Informes", "Estado del Sistema", "About"
    ]
    if "pagina" not in st.session_state:
        st.session_state.pagina = "Panel General"
    # Obtener tickets abiertos para badge
    try:
        tickets_abiertos = len(requests.get("http://localhost:8000/tickets", headers=HEADERS, params={"estado": "Abierto"}, timeout=2).json())
        tickets_abiertos += len(requests.get("http://localhost:8000/tickets", headers=HEADERS, params={"estado": "Investigando"}, timeout=2).json())
    except:
        tickets_abiertos = 0

    if tickets_abiertos > 0:
        st.markdown(f"""
        <div style="background:#161b22;color:#f85149;padding:6px 12px;border-radius:4px;
                    font-size:0.8rem;font-weight:600;margin-bottom:8px;text-align:center;
                    border:1px solid #f85149;">
            ⚑ {tickets_abiertos} ticket{'s' if tickets_abiertos > 1 else ''} pendiente{'s' if tickets_abiertos > 1 else ''}
        </div>""", unsafe_allow_html=True)

    for opcion in opciones:
        activo = st.session_state.pagina == opcion
        label = opcion
        if opcion == "Gestión de Incidentes" and tickets_abiertos > 0:
            label = f"Gestión de Incidentes ({tickets_abiertos})"
        if st.button(label, key=f"nav_{opcion}", use_container_width=True,
                     type="primary" if activo else "secondary"):
            st.session_state.pagina = opcion
            st.rerun()
    pagina = st.session_state.pagina
    st.markdown("---")
    if st.session_state.get("authentication_status"):
        authenticator.logout("Cerrar sesion", "sidebar", key="logout_sidebar")
    st.markdown("---")   

alertas_activas = len(df[df["nivel"] >= 10]) if not df.empty else 0
color_live = "#e74c3c" if alertas_activas > 0 else "#27ae60"
st.markdown(f"""
<div style="font-size:0.78rem; color:#7f8c8d; margin-bottom:12px; padding:8px 16px;
            background:#161b22; border-radius:6px; border:1px solid #21262d;
            display:flex; justify-content:space-between; align-items:center;
            box-shadow:0 1px 3px rgba(0,0,0,0.05);">
    <div>
        <span style="color:#1a3a6c; font-weight:700; letter-spacing:1px">NOCTUA PREDICTIVE.</span>
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
        <span style="color:#7f8c8d">Analista: <strong style="color:#e6edf3">{name}</strong></span>
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
            bg_alto = "#161b22" if altas == 0 else "#1a2a0a"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color_alto}; background:#161b22;">
                <p class="metric-label">Nivel Alto (10+)</p>
                <p style="font-size:3rem; font-weight:700; color:{color_alto}; margin:4px 0 0 0;">{altas}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver nivel alto", key="btn_altas", use_container_width=True, type="primary"):
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
            <div class="metric-card" style="border-top:3px solid #6c3483; background:#161b22;">
                <p class="metric-label">IPs en Blacklist</p>
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
                st.session_state.pagina = "Detección APT"; st.rerun()
        with col2:
            campanas_24h = estado_apt.get("campanas_24h", 0)
            color = "#e67e22" if campanas_24h > 0 else "#bdc3c7"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Campañas APT 24h</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{campanas_24h}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver ultimas", key="btn_apt_24h", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Detección APT"; st.rerun()
        with col3:
            lateral_total = estado_lateral.get("detecciones_totales", 0)
            color = "#8e44ad" if lateral_total > 0 else "#bdc3c7"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Movimiento Lateral</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{lateral_total}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver lateral", key="btn_lateral", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Detección APT"; st.rerun()
        with col4:
            buffer = estado_apt.get("eventos_en_buffer", 0)
            color = "#2980b9"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Eventos en Buffer</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{buffer}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver motor", key="btn_buffer", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Detección APT"; st.rerun()
        
        # Metricas Suricata
        datos_suricata = cargar_suricata()
        alertas_sur = datos_suricata.get("alertas", [])
        flows_sur = datos_suricata.get("flows", [])
        ips_atacantes = list(set([a["src_ip"] for a in alertas_sur if a["src_ip"] and not es_ip_whitelist(a["src_ip"])]))        
        st.markdown('<div class="section-header">Tráfico de Red — Suricata IDS</div>', unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            n = len(alertas_sur)
            color = "#f85149" if n > 0 else "#8b949e"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Alertas de Red Hoy</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{n}</p>
            </div>""", unsafe_allow_html=True)
        with col2:
            n = len(ips_atacantes)
            color = "#d29922" if n > 0 else "#8b949e"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">IPs Atacantes Activas</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{n}</p>
            </div>""", unsafe_allow_html=True)
        with col3:
            n = len(flows_sur)
            color = "#388bfd"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Flujos de Red</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{n}</p>
            </div>""", unsafe_allow_html=True)
        with col4:
            criticas = len([a for a in alertas_sur if a["severidad"] == 1])
            color = "#f85149" if criticas > 0 else "#8b949e"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Alertas Criticas Red</p>
                <p style="font-size:3rem;font-weight:700;color:{color};margin:4px 0 0 0;">{criticas}</p>
            </div>""", unsafe_allow_html=True)
            if st.button("Ver tráfico", key="btn_suricata", use_container_width=True, type="secondary"):
                st.session_state.pagina = "Tráfico de Red"; st.rerun()

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-header">Top Tipos de Alerta</div>', unsafe_allow_html=True)
            top_tipos = df["tipo"].value_counts().head(8).reset_index()
            top_tipos.columns = ["Tipo", "Count"]
            fig = px.bar(top_tipos, x="Count", y="Tipo", orientation="h", color="Count", color_continuous_scale="Reds")
            fig.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117", showlegend=False,
                            coloraxis_showscale=False, margin=dict(l=0,r=0,t=10,b=0), height=300,
                            yaxis_title="", xaxis_title="")
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.markdown('<div class="section-header">Distribucion por Nivel</div>', unsafe_allow_html=True)
            niveles = df["nivel"].value_counts().sort_index().reset_index()
            niveles.columns = ["Nivel", "Count"]
            fig2 = px.bar(niveles, x="Nivel", y="Count", color="Count", color_continuous_scale="OrRd")
            fig2.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117", showlegend=False,
                             coloraxis_showscale=False, margin=dict(l=0,r=0,t=10,b=0), height=300)
            st.plotly_chart(fig2, use_container_width=True)
        st.markdown('<div class="section-header">Actividad Reciente (Timeline)</div>', unsafe_allow_html=True)
        df_time = df.copy()
        df_time["hora"] = df_time["timestamp"].dt.floor("h")
        timeline = df_time.groupby("hora").size().reset_index(name="alertas")
        fig3 = px.area(timeline, x="hora", y="alertas", color_discrete_sequence=["#388bfd"])
        fig3.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                          margin=dict(l=0,r=0,t=10,b=0), height=180,
                          xaxis_title="", yaxis_title="Alertas")
        st.plotly_chart(fig3, use_container_width=True)
        st.markdown('<div class="section-header">Ultimas Alertas</div>', unsafe_allow_html=True)
        df_show = df.head(10)[["timestamp","tipo","ip","nivel","agente","accion"]].copy()
        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m %H:%M")
        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Agente","Estado"]
        tabla_oscura(df_show, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# ALERTAS Y EVENTOS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Alertas y Eventos":
    st.markdown("## Alertas y Eventos")
    st.markdown("---")
    if df.empty:
        st.warning("No hay alertas disponibles.")
    else:
        # ── Estadísticas ───────────────────────────────────────────────
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid #388bfd;">
                <p class="metric-label">Total Alertas</p>
                <p class="metric-value">{len(df)}</p>
            </div>""", unsafe_allow_html=True)
        with col2:
            n_alto = len(df[df["nivel"] >= 10])
            color = "#f85149" if n_alto > 0 else "#3fb950"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Nivel Alto (10+)</p>
                <p class="metric-value" style="color:{color}">{n_alto}</p>
            </div>""", unsafe_allow_html=True)
        with col3:
            ips_unicas = df[df["ip"] != "N/A"]["ip"].nunique()
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid #d29922;">
                <p class="metric-label">IPs Únicas</p>
                <p class="metric-value" style="color:#d29922">{ips_unicas}</p>
            </div>""", unsafe_allow_html=True)
        with col4:
            reglas_unicas = df["id_regla"].nunique()
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid #8b5cf6;">
                <p class="metric-label">Reglas Disparadas</p>
                <p class="metric-value" style="color:#8b5cf6">{reglas_unicas}</p>
            </div>""", unsafe_allow_html=True)

        st.markdown("---")

        # ── Gráficas ───────────────────────────────────────────────────
        col_g1, col_g2, col_g3 = st.columns(3)
        with col_g1:
            st.markdown('<div class="section-header">Alertas por Hora</div>', unsafe_allow_html=True)
            import plotly.express as px
            from datetime import datetime, timedelta
            hace_24h = datetime.now() - timedelta(hours=24)
            df_hora = df[df["timestamp"] >= hace_24h].copy()
            df_hora["hora"] = df_hora["timestamp"].dt.hour
            alertas_hora = df_hora.groupby("hora").size().reset_index(name="Alertas")
            alertas_hora = alertas_hora.set_index("hora").reindex(range(24), fill_value=0).reset_index()
            fig1 = px.bar(alertas_hora, x="hora", y="Alertas", 
                         color="Alertas", color_continuous_scale="Blues",
                         template="plotly_dark")
            fig1.update_layout(paper_bgcolor="#0d1117", plot_bgcolor="#0d1117", 
                              showlegend=False, coloraxis_showscale=False,
                              margin=dict(t=10, b=10, l=10, r=10), height=250)
            st.plotly_chart(fig1, use_container_width=True)
        with col_g2:
            st.markdown('<div class="section-header">Top Reglas Disparadas</div>', unsafe_allow_html=True)
            top_reglas = df.groupby("tipo").size().reset_index(name="count").sort_values("count", ascending=False).head(5)
            top_reglas["tipo"] = top_reglas["tipo"].str[:25]
            fig2 = px.bar(top_reglas, x="count", y="tipo", orientation="h",
                         color="count", color_continuous_scale="Reds",
                         template="plotly_dark")
            fig2.update_layout(paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                              showlegend=False, coloraxis_showscale=False,
                              margin=dict(t=10, b=10, l=10, r=10), height=250)
            st.plotly_chart(fig2, use_container_width=True)
        with col_g3:
            st.markdown('<div class="section-header">Distribución por Nivel</div>', unsafe_allow_html=True)
            dist_nivel = df.groupby("nivel").size().reset_index(name="Alertas")
            fig3 = px.bar(dist_nivel, x="nivel", y="Alertas",
                         color="Alertas", color_continuous_scale="Oranges",
                         template="plotly_dark")
            fig3.update_layout(paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                              showlegend=False, coloraxis_showscale=False,
                              margin=dict(t=10, b=10, l=10, r=10), height=250)
            st.plotly_chart(fig3, use_container_width=True)

        st.markdown("---")

        # ── Filtros ────────────────────────────────────────────────────
        col1, col2, col3 = st.columns(3)
        with col1:
            filtro_nivel = st.slider("Nivel mínimo", 0, 15, 7)
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

        # ── Tabla con pivoting ─────────────────────────────────────────
        df_show = df_f[["timestamp","tipo","ip","nivel","agente","id_regla","accion"]].copy()
        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m/%Y %H:%M")
        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Agente","Regla","Estado"]
        tabla_oscura(df_show, use_container_width=True, hide_index=True)

        # Pivoting al forense
        ips_alertas = df_f[df_f["ip"] != "N/A"]["ip"].dropna().unique().tolist()
        if ips_alertas:
            col_piv1, col_piv2 = st.columns([3, 1])
            with col_piv1:
                ip_pivot_alertas = st.selectbox("Investigar IP", ips_alertas, key="ip_pivot_alertas")
            with col_piv2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("Investigar en Forense", key="btn_pivot_alertas", type="primary", use_container_width=True):
                    st.session_state.pagina = "Análisis Forense"
                    st.session_state.ip_forense_pivot = ip_pivot_alertas
                    st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# IPs BLOQUEADAS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "IPs Bloqueadas":
    st.markdown("## Blacklist — IPs Bloqueadas en Hetzner Firewall")
    st.markdown("---")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(f'<div class="metric-card danger"><p class="metric-label">IPs en Blacklist</p><p class="metric-value">{len(ips_bloqueadas)}</p></div>', unsafe_allow_html=True) 
    st.markdown('<div class="section-header">Blacklist — IPs Bloqueadas en Hetzner</div>', unsafe_allow_html=True)    
    if ips_bloqueadas:
        rows = []
        for ip in ips_bloqueadas:
            abuse = consultar_abuseipdb(ip)
            score = abuse.get("score", 0)
            if score >= 80:
                badge = f'<span style="background:#e74c3c;color:white;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">{score}% MALICIOSA</span>'
            elif score >= 40:
                badge = f'<span style="background:#f39c12;color:white;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">{score}% SOSPECHOSA</span>'
            elif score > 0:
                badge = f'<span style="background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">{score}% BAJA</span>'
            else:
                badge = '<span style="background:#bdc3c7;color:white;padding:2px 8px;border-radius:4px;font-size:0.75rem">Desconocida</span>'
            enriq = enriquecer_ip(ip)
            rows.append({
                "IP":         ip,
                "Reputacion": str(score) + "%",
                "Pais":       abuse.get("pais", "—"),
                "Ciudad":     f"{enriq.get('ciudad','—')}, {enriq.get('pais_codigo','—')}",
                "ISP":        enriq.get("isp","—") or abuse.get("isp", "—"),
                "ASN":        enriq.get("asn", "—"),
                "Datacenter": "Si" if enriq.get("es_datacenter") else "No",
                "Reportes":   str(abuse.get("reportes", 0)),
                "TOR":        "Si" if abuse.get("es_tor") else "No"
            })
        df_ips = pd.DataFrame(rows)
        tabla_oscura(df_ips, use_container_width=True, hide_index=True)
    else:
        st.info("No hay IPs bloqueadas actualmente.")
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
                color="Ataques", color_continuous_scale=["#0d2d6b", "#1f6feb", "#388bfd"],
                labels={"Ataques": "IPs Bloqueadas"}
            )
            fig_mapa.update_layout(
                plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                margin=dict(l=0, r=0, t=10, b=0), height=400,
                geo=dict(showframe=False, showcoastlines=True, coastlinecolor="#30363d",
                        showland=True, landcolor="#161b22", showocean=True,
                        oceancolor="#0d1117", projection_type="natural earth",
                        bgcolor="#0d1117")
            )
            st.plotly_chart(fig_mapa, use_container_width=True)
            st.markdown('<div class="section-header">Top Paises de Origen</div>', unsafe_allow_html=True)
            df_mapa["Ataques"] = df_mapa["Ataques"].astype(str)
            tabla_oscura(df_mapa, use_container_width=True, hide_index=True)
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
        # Separar bloqueadas y desbloqueadas
        df_historial = df_hist[["ip","timestamp","accion"]].copy()
        df_historial.columns = ["IP", "Fecha", "Accion"]
        tabla_oscura(df_historial, use_container_width=True, hide_index=True)
    else:
        st.info("No hay historial de IPs todavia.")

    # Historial manual de bloqueos/desbloqueos
    st.markdown('<div class="section-header">Historial de Acciones Manuales</div>', unsafe_allow_html=True)
    try:
        with open("/root/asoar/ips_manual.json", "r") as f:
            ips_manual = json.load(f)
        if ips_manual:
            df_manual = pd.DataFrame(ips_manual)
            df_manual["timestamp"] = pd.to_datetime(df_manual["timestamp"]).dt.strftime("%d/%m/%Y %H:%M")
            df_manual = df_manual[["ip","timestamp","accion"]].copy()
            df_manual.columns = ["IP","Fecha","Accion"]
            df_manual = df_manual.sort_values("Fecha", ascending=False)
            tabla_oscura(df_manual, use_container_width=True, hide_index=True)
        else:
            st.info("No hay acciones manuales registradas todavia.")
    except:
        st.info("No hay acciones manuales registradas todavia.")

    st.markdown('<div class="section-header">Bloquear IP Manual</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        bloquear_counter = st.session_state.get("bloquear_counter", 0)
        ip_bloquear_manual = st.text_input("IP a bloquear", placeholder="Ej: 49.248.197.50", key=f"ip_bloquear_manual_{bloquear_counter}")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Bloquear", type="primary", key="btn_bloquear_manual"):
            if ip_bloquear_manual:
                try:
                    r = requests.post(f"http://localhost:8000/bloquear/{ip_bloquear_manual}", headers=HEADERS, timeout=10)
                    resp = r.json()
                    if resp.get("status") == "ya_bloqueada":
                        st.warning(f"La IP {ip_bloquear_manual} ya está bloqueada.")
                        st.session_state.bloquear_counter = st.session_state.get("bloquear_counter", 0) + 1
                        st.rerun()
                    elif r.status_code == 200:
                        st.success(f"IP {ip_bloquear_manual} bloqueada correctamente — la tabla se actualizará en 30 segundos")
                        st.session_state.bloquear_counter = st.session_state.get("bloquear_counter", 0) + 1
                        st.rerun()
                    else:
                        st.error(f"Error al bloquear: {r.text}")
                except Exception as e:
                    st.error(f"Error: {e}")

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
# PLAYBOOKS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Playbooks":
    st.markdown("## Playbooks — Respuesta Automatizada a Incidentes")
    st.markdown("Flujos de respuesta automática ante amenazas detectadas. El sistema ejecuta acciones de contención sin intervención humana.")
    st.markdown("---")

    # ── Playbooks disponibles ─────────────────────────────────────────────
    st.markdown('<div class="section-header">Playbooks Disponibles</div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="metric-card" style="border-top:3px solid #f85149;">
            <p class="metric-label">SSH Brute Force</p>
            <p style="font-size:0.85rem;color:#c9d1d9;margin:8px 0">Detecta intentos de fuerza bruta SSH y bloquea la IP automáticamente en Hetzner.</p>
            <p style="font-size:0.75rem;color:#8b949e;">Trigger: Nivel 10+ + SSH fallido<br>Acciones: Bloquear Hetzner + Ticket</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card" style="border-top:3px solid #d29922;">
            <p class="metric-label">IP Maliciosa</p>
            <p style="font-size:0.85rem;color:#c9d1d9;margin:8px 0">Responde ante IPs maliciosas confirmadas, detectadas por el LSTM con AbuseIPDB >= 80%.</p>
            <p style="font-size:0.75rem;color:#8b949e;">Trigger: LSTM + AbuseIPDB>=80%<br>Acciones: Bloquear Hetzner + Ticket</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card" style="border-top:3px solid #388bfd;">
            <p class="metric-label">Port Scan</p>
            <p style="font-size:0.85rem;color:#c9d1d9;margin:8px 0">Detecta escaneos de puertos masivos y bloquea el origen automáticamente.</p>
            <p style="font-size:0.75rem;color:#8b949e;">Trigger: >100 alertas en 60s<br>Acciones: Bloquear Hetzner</p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # ── Ejecutar playbook manualmente ────────────────────────────────────
    st.markdown('<div class="section-header">Ejecutar Playbook Manual</div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        pb_tipo = st.selectbox("Playbook", ["ssh_brute_force", "ip_maliciosa", "port_scan"])
    with col2:
        pb_ip = st.text_input("IP objetivo", placeholder="Ej: 49.248.197.50")
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Ejecutar", type="primary", use_container_width=True):
            if pb_ip:
                try:
                    r = requests.post("http://localhost:8000/playbooks/ejecutar",
                        headers=HEADERS,
                        json={"playbook": pb_tipo, "ip": pb_ip},
                        timeout=30)
                    resultado = r.json()
                    if resultado.get("estado") == "COMPLETADO":
                        st.success(f"Playbook {pb_tipo} ejecutado correctamente para {pb_ip}")
                    else:
                        st.error(f"Error: {resultado.get('error', 'Desconocido')}")
                except Exception as e:
                    st.error(f"Error: {e}")

    st.markdown("---")

    # ── Historial de ejecuciones ─────────────────────────────────────────
    st.markdown('<div class="section-header">Historial de Ejecuciones</div>', unsafe_allow_html=True)
    try:
        historial = requests.get("http://localhost:8000/playbooks/historial", headers=HEADERS, timeout=5).json()
        if historial:
            st.markdown(f"**{len(historial)} playbooks ejecutados en total**")
            for pb in reversed(historial[-10:]):
                color = "#3fb950" if pb.get("estado") == "COMPLETADO" else "#f85149" if pb.get("estado") == "ERROR" else "#d29922"
                with st.expander(f"{pb['id']} — {pb['playbook'].upper()} | {pb['ip']} | {pb['estado']}"):
                    ctx = pb.get("contexto", {})
                    narrativa = ctx.get("narrativa", "")
                    if narrativa:
                        st.markdown(f"""
                        <div style="background:#0d1117;padding:12px;border-radius:8px;border-left:4px solid {color};margin-bottom:8px;">
                            <p style="color:#c9d1d9;font-size:0.9rem;margin:0">{narrativa}</p>
                        </div>""", unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div style="background:#161b22;padding:12px;border-radius:8px;border-left:4px solid {color};">
                            <p style="color:#8b949e;font-size:0.8rem">{pb['timestamp'][:16].replace('T',' ')}</p>
                            <p style="color:#c9d1d9;font-size:0.9rem">Playbook: <strong>{pb['playbook']}</strong> | IP: <strong>{pb['ip']}</strong></p>
                            {f"<p style='color:#8b949e;font-size:0.85rem'>Fase: {ctx.get('fase_mitre','—').upper()} | Confianza: {ctx.get('confianza','—')}% | AbuseIPDB: {ctx.get('abuse_score','—')}% | País: {ctx.get('pais','—')} | ISP: {ctx.get('isp','—')}</p>" if ctx else ""}
                        </div>""", unsafe_allow_html=True)
                    if pb.get("acciones"):
                        for accion in pb["acciones"]:
                            color_a = "#3fb950" if accion.get("estado") == "OK" else "#f85149"
                            st.markdown(f"""
                            <div style="background:#0d1117;padding:6px 12px;border-radius:4px;
                                        border-left:2px solid {color_a};margin:4px 0;">
                                <span style="color:{color_a};font-weight:600">{accion['accion']}</span>
                                <span style="color:#8b949e;font-size:0.8rem;margin-left:8px">{accion['timestamp'][11:19]}</span>
                            </div>""", unsafe_allow_html=True)
            if len(historial) > 10:
                with st.expander(f"Ver historial completo ({len(historial)} ejecuciones)"):
                    for pb in reversed(historial):
                        color = "#3fb950" if pb.get("estado") == "COMPLETADO" else "#f85149"
                        st.markdown(f"**{pb['id']}** — {pb['playbook'].upper()} | {pb['ip']} | {pb['timestamp'][:16].replace('T',' ')} | <span style='color:{color}'>{pb['estado']}</span>", unsafe_allow_html=True)
        else:
            st.info("No hay ejecuciones de playbooks todavía.")
    except Exception as e:
        st.error(f"Error cargando historial: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# SIMULADOR
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Simulador de Ataques":
    st.markdown("## Simulador de Ataques")
    st.markdown("Envia alertas de prueba al motor Noctua Predictive y simula campañas APT completas para verificar el funcionamiento del sistema.")
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
        if st.button("Ejecutar Simulación", key="btn_sim_individual"):
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
        <div style="background:#161b22;padding:12px 16px;border-radius:8px;
                    border-left:3px solid #e74c3c;margin-bottom:16px;">
            <p style="font-size:0.85rem;color:#c9d1d9;margin:0">
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
                st.session_state.pagina = "Detección APT"
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

    def check_fail2ban():
        try:
            result = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def check_suricata():
        try:
            result = subprocess.run(["systemctl", "is-active", "suricata"], capture_output=True, text=True, timeout=3)
            return result.stdout.strip() == "active"
        except:
            return False

    def check_wazuh_agent_windows():
        try:
            agentes = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=3).json()
            return "WORKSTATION-01" in agentes
        except:
            return False

    servicios = {
        "ASOAR API (FastAPI)":      check_service("http://localhost:8000/apt/estado"),
        "Ollama / phi3":            check_service("http://localhost:11434/api/tags"),
        "Wazuh Manager":            True,
        "Wazuh Dashboard":          True,
        "Suricata IDS":             check_suricata(),
        "Hetzner Firewall":         len(ips_bloqueadas) >= 0,
        "Fail2ban":                 check_fail2ban(),
        "Agente Windows (Wazuh)":   check_wazuh_agent_windows(),
        "Agente Windows (EDR)":     check_wazuh_agent_windows(),
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
    st.markdown('<div class="section-header">Arquitectura Completa del Sistema</div>', unsafe_allow_html=True)
    datos_arq = {
        "Componente":  ["Wazuh SIEM", "Suricata IDS", "FastAPI", "Ollama phi3", "LSTM PyTorch", "Federated Learning", "XAI SHAP", "Detector Lateral", "Reentrenamiento", "AbuseIPDB", "Fail2ban", "CICIDS2018", "Hetzner API", "Agente PowerShell EDR", "Agente Wazuh Windows", "Streamlit"],
        "Capa":        ["Deteccion SIEM", "Deteccion Red", "Orquestacion", "Analisis IA", "Prediccion APT", "Aprendizaje FL", "Explicabilidad", "Correlacion", "Mejora continua", "Threat Intelligence", "Defensa perimetral", "Entrenamiento", "Respuesta", "Monitorizacion EDR", "Correlacion SIEM", "Visualizacion"],
        "Estado":      [
            "Activo" if servicios["Wazuh Manager"] else "Inactivo",
            "Activo" if servicios["Suricata IDS"] else "Inactivo",
            "Activo" if servicios["ASOAR API (FastAPI)"] else "Inactivo",
            "Activo" if servicios["Ollama / phi3"] else "Inactivo",
            "Activo" if estado_apt.get("modelo_cargado") else "Inactivo",
            "Activo",
            "Activo" if estado_apt.get("modelo_cargado") else "Inactivo",
            "Activo",
            "Activo" if estado_retrain.get("activo") else "Inactivo",
            "Activo" if ABUSEIPDB_API_KEY else "Inactivo",
            "Activo" if check_fail2ban() else "Inactivo",
            "Activo",
            "Conectado",
            "Activo" if servicios["Agente Windows (EDR)"] else "Inactivo",
            "Activo" if servicios["Agente Windows (Wazuh)"] else "Inactivo",
            "Activo",
        ]
    }
    tabla_oscura(pd.DataFrame(datos_arq), use_container_width=True, hide_index=True)

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
            tabla_oscura(df_retrain, use_container_width=True, hide_index=True)
        else:
            st.info("No hay historial de reentrenamiento todavia.")
    except:
        st.info("No hay historial de reentrenamiento todavia.")

    st.markdown("---")
    st.markdown('<div class="section-header">Seguridad de la Cuenta</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([5, 1])
    with col1:
        activo_mfa = mfa_activo(username) if MFA_DISPONIBLE else False
        color_mfa = "#27ae60" if activo_mfa else "#e74c3c"
        estado_txt = "Activo — cuenta protegida con TOTP" if activo_mfa else "Inactivo"
        st.markdown(f'<div style="background:#161b22;padding:16px;border-radius:8px;border-left:4px solid {color_mfa};box-shadow:0 2px 6px rgba(0,0,0,0.07);"><p style="font-weight:600;color:#2c3e50;margin-bottom:4px">Autenticacion de Doble Factor (MFA)</p><p style="font-size:0.85rem;color:#7f8c8d;margin:0">Estado: <strong style="color:{color_mfa}">{estado_txt}</strong></p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        mfa_toggle = st.toggle("Activar MFA", value=activo_mfa, key="toggle_mfa", label_visibility="collapsed")
        if mfa_toggle != activo_mfa:
            if mfa_toggle:
                st.session_state.mfa_wizard = True
                st.session_state.mfa_paso = 1
                st.rerun()
            else:
                guardar_config_mfa(username, obtener_secreto(username), activo=False)
                st.session_state.pop("mfa_verificado", None)
                st.rerun()
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
                color_cpu = "#f85149" if cpu > 80 else "#d29922" if cpu > 60 else "#3fb950"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=cpu,
                    title={"text": "CPU %", "font": {"color": "#8b949e", "size": 20}},
                    number={"font": {"color": "#e6edf3", "size": 40}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#388bfd",
                                "tickfont": {"color": "#8b949e", "size": 12}},
                        "bar": {"color": "#388bfd", "thickness": 0.5},
                        "bgcolor": "#161b22",
                        "bordercolor": "#21262d",
                        "borderwidth": 1,
                        "steps": [
                            {"range": [0, 60],  "color": "#0a3a1a"},
                            {"range": [60, 80], "color": "#3d2200"},
                            {"range": [80, 100],"color": "#3d0a0a"},
                        ],
                        "threshold": {
                            "line": {"color": "#58a6ff", "width": 3},
                            "thickness": 0.8,
                            "value": cpu
                        }
                    }
                ))
                fig.update_layout(
                    height=220,
                    margin=dict(l=20, r=20, t=60, b=20),
                    paper_bgcolor="#161b22",
                    font={"color": "#8b949e"}
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                ram = rend.get("ram_porcentaje", 0)
                color_ram = "#f85149" if ram > 80 else "#d29922" if ram > 60 else "#3fb950"
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=ram,
                    title={"text": "RAM %", "font": {"color": "#8b949e", "size": 20}},
                    number={"font": {"color": "#e6edf3", "size": 40}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#388bfd",
                                "tickfont": {"color": "#8b949e", "size": 12}},
                        "bar": {"color": "#388bfd", "thickness": 0.5},
                        "bgcolor": "#161b22",
                        "bordercolor": "#21262d",
                        "borderwidth": 1,
                        "steps": [
                            {"range": [0, 60],  "color": "#0a3a1a"},
                            {"range": [60, 80], "color": "#3d2200"},
                            {"range": [80, 100],"color": "#3d0a0a"},
                        ],
                        "threshold": {
                            "line": {"color": "#58a6ff", "width": 3},
                            "thickness": 0.8,
                            "value": ram
                        }
                    }
                ))
                fig.update_layout(
                    height=220,
                    margin=dict(l=20, r=20, t=60, b=20),
                    paper_bgcolor="#161b22",
                    font={"color": "#8b949e"}
                )
                st.plotly_chart(fig, use_container_width=True)
            col_exp1, col_exp2, col_exp3 = st.columns(3)
            with col_exp1:
                with st.expander(f"Puertos en escucha ({len(seg.get('puertos_escucha', []))})"):
                    puertos = seg.get("puertos_escucha", [])
                    if puertos:
                        # Detectar si vienen como objetos con telemetria o solo numeros
                        if isinstance(puertos[0], dict):
                            df_puertos = pd.DataFrame(puertos)
                            df_puertos.columns = ["Puerto", "Proceso", "PID", "CPU %", "RAM (MB)"]
                            tabla_oscura(df_puertos)
                        else:
                            tabla_oscura(pd.DataFrame({"Puerto": [str(p) for p in puertos]}))
            with col_exp2:
                procesos_sospechosos = seg.get("procesos_sospechosos", [])
                with st.expander(f"Procesos sospechosos ({len(procesos_sospechosos)})"):
                    if procesos_sospechosos:
                        df_proc = pd.DataFrame(procesos_sospechosos)
                        df_proc = df_proc.rename(columns={"nombre": "Nombre", "pid": "PID", "cpu": "CPU", "memoria_mb": "Memoria (MB)"})
                        tabla_oscura(df_proc, use_container_width=True, hide_index=True)
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
                            tabla_oscura(df_ev, use_container_width=True, hide_index=True)
                    else:
                        st.info("Sin eventos recientes")
            
            # Cambios de comportamiento detectados
            cambios = agentes[hostname].get("cambios", [])
            with st.expander(f"Cambios detectados ({len(cambios)})"):
                if cambios:
                    for c in cambios:
                        color = "#f85149" if c["severidad"] == "CRITICO" else "#d29922" if c["severidad"] == "ALTO" else "#388bfd"
                        st.markdown(f"""
                        <div style="background:#161b22;padding:10px 14px;border-radius:6px;
                                    border-left:3px solid {color};margin-bottom:6px;">
                            <span style="background:{color};color:white;padding:1px 6px;
                                        border-radius:3px;font-size:0.72rem;font-weight:600">
                                {c['severidad']}
                            </span>
                            <span style="color:#c9d1d9;font-size:0.85rem;margin-left:8px">
                                {c['detalle']}
                            </span>
                        </div>""", unsafe_allow_html=True)
                else:
                    st.success("Sin cambios detectados desde el ultimo snapshot.")

            with st.expander(f"Software instalado ({len(seg.get('software_instalado', []))})"):
                software = seg.get("software_instalado", [])
                if software:
                    df_sw = pd.DataFrame(software)
                    if not df_sw.empty:
                        df_sw = df_sw.rename(columns={"nombre": "Nombre", "version": "Version", "publisher": "Publisher", "fecha_instalacion": "Fecha instalacion"})
                        df_sw["Fecha instalacion"] = pd.to_datetime(df_sw["Fecha instalacion"], format="%Y%m%d", errors="coerce").dt.strftime("%d/%m/%Y")
                        tabla_oscura(df_sw, use_container_width=True, hide_index=True)
            
                        # ── Respuesta bidireccional EDR ───────────────────────────────
            st.markdown('<div class="section-header">Respuesta EDR — Acciones Remotas</div>', unsafe_allow_html=True)
            col_edr1, col_edr2, col_edr3 = st.columns(3)

            with col_edr1:
                st.markdown("**Matar proceso**")
                todos_procs = seg.get("todos_procesos", [])
                sospechosos_procs = seg.get("procesos_sospechosos", [])
                puertos_data = seg.get("puertos_escucha", [])
                # Primero sospechosos, luego con puertos, luego todos
                opciones_proc = {}
                for p in sospechosos_procs:
                    opciones_proc[f"{p['nombre']} (PID {p['pid']}) — SOSPECHOSO"] = p['pid']
                for p in puertos_data:
                    if isinstance(p, dict) and p['pid'] not in opciones_proc.values():
                        opciones_proc[f"{p['proceso']} (PID {p['pid']}) — Puerto {p['puerto']}"] = p['pid']
                for p in todos_procs:
                    if p['pid'] not in opciones_proc.values():
                        opciones_proc[f"{p['nombre']} (PID {p['pid']})"] = p['pid']
                proc_sel = st.selectbox("Selecciona proceso", list(opciones_proc.keys()) if opciones_proc else ["Sin datos"], key=f"proc_{hostname}")
                if st.button("Terminar proceso", key=f"kill_{hostname}", type="primary"):
                    if proc_sel and proc_sel != "Sin datos":
                        pid_target = opciones_proc[proc_sel]
                        requests.post(f"http://localhost:8000/agente/comando/{hostname}",
                            headers=HEADERS, json={"tipo": "matar_proceso", "params": {"pid": pid_target}})
                        st.success(f"Comando enviado — PID {pid_target} será terminado en el próximo ciclo.")

            with col_edr2:
                st.markdown("**Bloquear IP en Windows**")
                ip_bloquear = st.text_input("IP a bloquear", placeholder="1.2.3.4", key=f"ip_{hostname}")
                if st.button("Bloquear IP", key=f"block_{hostname}", type="primary"):
                    if ip_bloquear:
                        requests.post(f"http://localhost:8000/agente/comando/{hostname}",
                            headers=HEADERS, json={"tipo": "bloquear_ip", "params": {"ip": ip_bloquear}})
                        st.success(f"Comando enviado — IP {ip_bloquear} será bloqueada en el próximo ciclo.")

            with col_edr3:
                st.markdown("**Snapshot inmediato**")
                st.markdown("Fuerza una actualización de datos sin esperar los 5 minutos.")
                if st.button("Forzar snapshot", key=f"snap_{hostname}", type="secondary"):
                    requests.post(f"http://localhost:8000/agente/comando/{hostname}",
                        headers=HEADERS, json={"tipo": "snapshot_inmediato", "params": {}})
                    st.success("Comando enviado — snapshot en el próximo ciclo.")

            # Historial de comandos
            with st.expander("Historial de comandos EDR"):
                try:
                    hist = requests.get(f"http://localhost:8000/agente/comandos/{hostname}/historial",
                        headers=HEADERS, timeout=3).json()
                    comandos_hist = hist.get("comandos", [])
                    if comandos_hist:
                        df_hist = pd.DataFrame(comandos_hist)
                        df_hist = df_hist[["creado_en","tipo","estado","resultado"]].copy()
                        df_hist.columns = ["Fecha","Tipo","Estado","Resultado"]
                        df_hist["Fecha"] = pd.to_datetime(df_hist["Fecha"]).dt.strftime("%d/%m %H:%M")
                        tabla_oscura(df_hist)
                    else:
                        st.info("Sin comandos ejecutados todavía.")
                except:
                    st.info("Sin historial disponible.")
            
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
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">Puntuacion Global</p>
                    <p class="metric-value" style="color:{color_global}">{score_global}%</p>
                    <p style="font-size:0.75rem;color:#7f8c8d">4 marcos normativos</p>
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
            with col5:
                if "eu_ai_act" in data:
                    score = data["eu_ai_act"]["score"]
                    color = "#27ae60" if score >= 80 else "#f39c12" if score >= 50 else "#e74c3c"
                    st.markdown(f'<div class="metric-card"><p class="metric-label">EU AI Act 2024</p><p class="metric-value" style="color:{color}">{score}%</p></div>', unsafe_allow_html=True)
            st.markdown("---")
            for key, nombre in [("iso27001", "ISO/IEC 27001:2022"), ("nis2", "NIS2 - Directiva UE 2022/2555"), ("ens", "Esquema Nacional de Seguridad"), ("eu_ai_act", "EU AI Act 2024")]:
                st.markdown(f'<div class="section-header">{nombre}</div>', unsafe_allow_html=True)
                for ctrl in data[key]["controles"]:
                    cumple = ctrl["cumple"]
                    badge = f'<span class="badge badge-green">Cumple</span>' if cumple else f'<span class="badge badge-red">No cumple</span>'
                    st.markdown(f"""
                    <div style="background:#161b22; padding:12px 16px; border-radius:6px; margin-bottom:8px;
                                border-left:3px solid {'#27ae60' if cumple else '#e74c3c'};
                                box-shadow:0 1px 3px rgba(0,0,0,0.06);">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <span style="font-size:0.75rem;color:#8b949e;font-weight:600">{ctrl['control']}</span>
                                <span style="font-size:0.9rem;color:#c9d1d9;margin-left:12px">{ctrl['nombre']}</span>
                            </div>
                            <div style="display:flex;align-items:center;gap:12px;">
                                <span style="font-size:0.8rem;color:#7f8c8d">{ctrl['detalle']}</span>
                                {badge}
                            </div>
                        </div>
                    </div>""", unsafe_allow_html=True)
                st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("---")
    
    # ── Bloque 2: Gestión de vulnerabilidades ─────────────────────────────
    st.markdown('<div class="section-header">Gestión de Vulnerabilidades — Endpoints</div>', unsafe_allow_html=True)
    try:
        agentes_data = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5).json()
        if agentes_data:
            rows_vuln = []
            for hostname, info in agentes_data.items():
                seg = info.get("datos", {}).get("seguridad", {})
                act_pendientes = seg.get("actualizaciones_pendientes", 0)
                act_criticas = seg.get("actualizaciones_criticas", 0)
                defender = seg.get("defender_activo", False)
                firewall = seg.get("firewall_activo", False)
                puntuacion = info.get("datos", {}).get("puntuacion_seguridad", 0)
                estado = "CRITICO" if act_criticas > 0 else "ADVERTENCIA" if act_pendientes > 0 else "OK"
                color = "#f85149" if estado == "CRITICO" else "#d29922" if estado == "ADVERTENCIA" else "#3fb950"
                rows_vuln.append({
                    "Endpoint": hostname,
                    "Actualizaciones Pendientes": act_pendientes,
                    "Criticas": act_criticas,
                    "Defender": "✓" if defender else "✗",
                    "Firewall": "✓" if firewall else "✗",
                    "Puntuacion": f"{puntuacion}/100",
                    "Estado": estado
                })
            df_vuln = pd.DataFrame(rows_vuln)
            tabla_oscura(df_vuln, hide_index=True)
        else:
            st.info("No hay endpoints monitorizados.")
    except Exception as e:
        st.error(f"Error cargando datos de endpoints: {e}")

    st.markdown("---")

    # ── Bloque 3: Control de accesos ──────────────────────────────────────
    st.markdown('<div class="section-header">Control de Accesos e Identidades</div>', unsafe_allow_html=True)
    try:
        agentes_data = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5).json()
        col1, col2, col3 = st.columns(3)
        total_admins = 0
        mfa_activo = 0
        intentos_fallidos = len(df[df["tipo"].str.contains("failed|Failed|brute", na=False)]) if not df.empty else 0
        for hostname, info in agentes_data.items():
            seg = info.get("datos", {}).get("seguridad", {})
            admins = seg.get("usuarios_admin", [])
            total_admins += len(admins)
        with col1:
            color = "#3fb950" if total_admins <= 2 else "#d29922"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Usuarios Administradores</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{total_admins}</p>
                <p style="font-size:0.75rem;color:#8b949e;">Recomendado: máximo 2</p>
            </div>""", unsafe_allow_html=True)
        with col2:
            mfa_ok = mfa_activo
            color = "#3fb950" if mfa_ok > 0 else "#f85149"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">MFA Activado</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{'Sí' if mfa_ok else 'No'}</p>
                <p style="font-size:0.75rem;color:#8b949e;">Dashboard protegido con TOTP</p>
            </div>""", unsafe_allow_html=True)
        with col3:
            color = "#f85149" if intentos_fallidos > 100 else "#d29922" if intentos_fallidos > 10 else "#3fb950"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Intentos SSH Fallidos</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{intentos_fallidos}</p>
                <p style="font-size:0.75rem;color:#8b949e;">Período actual</p>
            </div>""", unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error: {e}")

    st.markdown("---")

    # ── Bloque 5: Respuesta a incidentes ──────────────────────────────────
    st.markdown('<div class="section-header">Respuesta a Incidentes — Marco Legal</div>', unsafe_allow_html=True)
    try:
        tickets_data = requests.get("http://localhost:8000/tickets", headers=HEADERS, timeout=5).json()
        tickets_criticos = [t for t in tickets_data if t.get("prioridad") == "CRITICA" and t.get("estado") not in ["Resuelto", "Cerrado"]]
        col1, col2, col3 = st.columns(3)
        with col1:
            n = len(tickets_criticos)
            color = "#f85149" if n > 0 else "#3fb950"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">Incidentes Críticos Abiertos</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{n}</p>
                <p style="font-size:0.75rem;color:#8b949e;">Requieren notificación RGPD 72h</p>
            </div>""", unsafe_allow_html=True)
        with col2:
            # MTTR de tickets
            metricas = requests.get("http://localhost:8000/tickets/metricas/resumen", headers=HEADERS, timeout=3).json()
            mttr = metricas.get("mttr_horas", 0)
            color = "#3fb950" if mttr < 24 else "#d29922" if mttr < 72 else "#f85149"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">MTTR Actual</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{mttr:.1f}h</p>
                <p style="font-size:0.75rem;color:#8b949e;">Límite RGPD: 72 horas</p>
            </div>""", unsafe_allow_html=True)
        with col3:
            sla = metricas.get("sla_24h_porcentaje", 0)
            color = "#3fb950" if sla >= 80 else "#d29922" if sla >= 50 else "#f85149"
            st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color};">
                <p class="metric-label">SLA 24h</p>
                <p style="font-size:2rem;font-weight:700;color:{color};">{sla:.0f}%</p>
                <p style="font-size:0.75rem;color:#8b949e;">Objetivo SOC: >80%</p>
            </div>""", unsafe_allow_html=True)
        # Contador 72h para incidentes criticos
        if tickets_criticos:
            st.markdown('<div class="section-header">Contador RGPD — Notificación 72 horas</div>', unsafe_allow_html=True)
            for t in tickets_criticos[:3]:
                creado = datetime.fromisoformat(t["creado_en"].replace("Z","").split("+")[0])
                horas_transcurridas = (datetime.now() - creado).total_seconds() / 3600
                horas_restantes = max(0, 72 - horas_transcurridas)
                pct = min(100, (horas_transcurridas / 72) * 100)
                color = "#f85149" if horas_restantes < 12 else "#d29922" if horas_restantes < 24 else "#3fb950"
                st.markdown(f"""
                <div style="background:#161b22;padding:12px 16px;border-radius:8px;
                            border-left:4px solid {color};margin-bottom:8px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                        <span style="color:#c9d1d9;font-weight:600">{t['id']} — {t['titulo'][:50]}</span>
                        <span style="color:{color};font-weight:700">{horas_restantes:.1f}h restantes</span>
                    </div>
                    <div style="background:#21262d;border-radius:4px;height:6px;">
                        <div style="background:{color};width:{pct}%;height:6px;border-radius:4px;"></div>
                    </div>
                </div>""", unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error: {e}")

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
            "Informe de Detección APT",
            "Informe de IOCs y Threat Intelligence"
        ])
    with col2:
        try:
            r = requests.get("http://localhost:8000/agentes", headers=HEADERS, timeout=5)
            agentes_disp = list(r.json().keys())
        except:
            agentes_disp = []
        endpoint_sel = st.selectbox("Endpoint", agentes_disp if agentes_disp else ["Sin endpoints"])
    
    # Exportar IOCs en CSV
    if st.button("Exportar IOCs en CSV", type="secondary"):
        try:
            rows = []
            for ip in ips_bloqueadas:
                abuse = consultar_abuseipdb(ip)
                enriq = enriquecer_ip(ip)
                rows.append({
                    "ip": ip,
                    "tipo": "IP_MALICIOSA",
                    "score_abuso": abuse.get("score", 0),
                    "pais": abuse.get("pais", ""),
                    "isp": enriq.get("isp", ""),
                    "asn": enriq.get("asn", ""),
                    "datacenter": enriq.get("es_datacenter", False),
                    "fecha_bloqueo": datetime.now().strftime("%d/%m/%Y")
                })
            df_iocs = pd.DataFrame(rows)
            csv = df_iocs.to_csv(index=False)
            st.download_button(
                label="Descargar IOCs.csv",
                data=csv,
                file_name=f"noctua_iocs_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        except Exception as e:
            st.error(f"Error: {e}")
    
    if st.button("Exportar IOCs en STIX/TAXII", type="secondary"):
        try:
            r = requests.get("http://localhost:8000/iocs/stix", headers=HEADERS, timeout=30)
            stix_data = json.dumps(r.json(), indent=2, ensure_ascii=False)
            st.download_button(
                label="Descargar bundle STIX",
                data=stix_data,
                file_name=f"noctua_iocs_stix_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )
        except Exception as e:
            st.error(f"Error: {e}")

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
                    f"Este informe presenta el estado actual de la plataforma Noctua Predictive. "
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
                elements.append(Paragraph("IPs Bloqueadas por Noctua Predictive", style_h2))
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
          
            elif tipo_informe == "Informe de Detección APT":
                elements.append(Paragraph("Detección de Campañas APT", style_h2))
                elements.append(Paragraph(
                    "Este informe recoge las campañas de Amenazas Persistentes Avanzadas (APT) "
                    "detectadas por el motor LSTM de Noctua Predictive, clasificadas segun el "
                    "framework MITRE ATT&CK y con explicaciones XAI generadas automaticamente "
                    "en cumplimiento del Reglamento Europeo de Inteligencia Artificial (EU AI Act 2024).",
                    style_body))
                elements.append(Spacer(1, 0.3*cm))
                try:
                    campanas_pdf = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
                except:
                    campanas_pdf = []
                elements.append(Paragraph("Campañas APT Detectadas", style_h2))
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
                    elements.append(Paragraph("No se han detectado campañas APT todavia.", style_body))
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
            
            elif tipo_informe == "Informe de IOCs y Threat Intelligence":
                elements.append(Paragraph("Indicadores de Compromiso (IOCs)", style_h2))
                elements.append(Paragraph(
                    "Este informe recoge los Indicadores de Compromiso confirmados por Noctua Predictive "
                    "durante el período de monitorización. Incluye IPs maliciosas bloqueadas, su reputación "
                    "en AbuseIPDB, origen geográfico e infraestructura asociada.",
                    style_body))
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph("IPs Maliciosas Bloqueadas", style_h2))
                data_iocs = [["IP", "Score", "País", "ISP", "ASN", "Datacenter"]]
                for ip in ips_bloqueadas:
                    try:
                        abuse = consultar_abuseipdb(ip)
                        enriq = enriquecer_ip(ip)
                        data_iocs.append([
                            ip,
                            f"{abuse.get('score', 0)}%",
                            abuse.get('pais', '—'),
                            enriq.get('isp', abuse.get('isp', '—'))[:25],
                            enriq.get('asn', '—')[:20],
                            "Sí" if enriq.get('es_datacenter') else "No"
                        ])
                    except:
                        data_iocs.append([ip, "—", "—", "—", "—", "—"])
                tabla_iocs = Table(data_iocs, colWidths=[3.5*cm, 1.5*cm, 1.5*cm, 4*cm, 4*cm, 2*cm])
                tabla_iocs.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1f35')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                elements.append(tabla_iocs)
                elements.append(Spacer(1, 0.4*cm))
                elements.append(Paragraph("Firmas de Ataque más Frecuentes", style_h2))
                datos_sur = cargar_suricata()
                from collections import Counter
                firmas = Counter(a.get("firma","") for a in datos_sur.get("alertas", []) if a.get("firma"))
                data_firmas = [["Firma Suricata", "Detecciones"]]
                for firma, n in firmas.most_common(10):
                    data_firmas.append([firma[:50], str(n)])
                tabla_firmas = Table(data_firmas, colWidths=[13*cm, 3*cm])
                tabla_firmas.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1f35')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                elements.append(tabla_firmas)

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

    # Exportar campañas APT a CSV
    st.markdown("---")
    st.markdown("### Exportar datos de Campañas APT")
    try:
        campanas_csv = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
        if campanas_csv:
            df_csv = pd.DataFrame(campanas_csv)
            csv = df_csv.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Exportar datos a CSV",
                data=csv,
                file_name=f"campanas_apt_{hora_local().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",
                key="btn_export_apt_csv"
            )
        else:
            st.info("No hay campañas APT para exportar.")
    except:
        st.info("No hay campañas APT para exportar.")

# ══════════════════════════════════════════════════════════════════════════════
# DETECCION APT
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Detección APT":
    st.markdown("## Detección de Campañas APT")
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
            <p class="metric-label">Campañas Totales</p>
            <p style="font-size:2rem;font-weight:700;color:#e74c3c;">{estado.get("campanas_totales", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #f39c12;">
            <p class="metric-label">Campañas 24h</p>
            <p style="font-size:2rem;font-weight:700;color:#f39c12;">{estado.get("campanas_24h", 0)}</p>
        </div>""", unsafe_allow_html=True)

    # Distribución de fases MITRE detectadas — evidencia visual del feature mismatch
    st.markdown('<div class="section-header">Distribución de Fases MITRE Detectadas</div>', unsafe_allow_html=True)
    try:
        campanas_dist = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
    except:
        campanas_dist = []
    if campanas_dist:
        from collections import Counter
        col_pie, col_evol = st.columns(2)
        
        with col_pie:
            fases_count = Counter(c.get("fase_mitre","unknown") for c in campanas_dist)
            df_fases = pd.DataFrame(list(fases_count.items()), columns=["Fase", "Detecciones"]).sort_values("Detecciones", ascending=False)
            import plotly.express as px
            fig_fases = px.pie(df_fases, names="Fase", values="Detecciones",
                         color_discrete_sequence=px.colors.sequential.Reds_r,
                         template="plotly_dark", hole=0.4)
            fig_fases.update_layout(paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                              margin=dict(t=10, b=10, l=10, r=10), height=280,
                              legend=dict(font=dict(color="#c9d1d9")))
            fig_fases.update_traces(textfont_color="#e6edf3")
            st.plotly_chart(fig_fases, use_container_width=True)
        
        with col_evol:
            df_evol = pd.DataFrame(campanas_dist)
            df_evol["fecha"] = pd.to_datetime(df_evol["timestamp"]).dt.date
            from datetime import date, timedelta
            hoy = date.today()
            
            fecha_min = df_evol["fecha"].min()
            fecha_max = hoy - timedelta(days=1)  # excluir día en curso
            
            rango_fechas = pd.date_range(start=fecha_min, end=fecha_max, freq="D").date
            evol_diaria = df_evol[df_evol["fecha"] <= fecha_max].groupby("fecha").size()
            evol_diaria = evol_diaria.reindex(rango_fechas, fill_value=0).reset_index()
            evol_diaria.columns = ["fecha", "Detecciones"]
            evol_diaria["fecha_str"] = pd.to_datetime(evol_diaria["fecha"]).dt.strftime("%d/%m")
            
            fig_evol = px.line(evol_diaria, x="fecha_str", y="Detecciones",
                         template="plotly_dark", markers=True)
            fig_evol.update_traces(line_color="#f85149", marker_color="#f85149", marker_size=8)
            fig_evol.update_layout(paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                              margin=dict(t=30, b=10, l=10, r=10), height=280,
                              title=dict(text="Detecciones por día (datos disponibles)", font=dict(size=13, color="#8b949e")),
                              xaxis=dict(title="", tickfont=dict(color="#8b949e")),
                              yaxis=dict(title="Detecciones", tickfont=dict(color="#8b949e"), rangemode="tozero"))
            st.plotly_chart(fig_evol, use_container_width=True)
        
    else:
        st.info("No hay suficientes campañas detectadas para mostrar la distribución.")

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

    st.markdown("""
    <div style="background:#161b22;padding:16px 20px;border-radius:8px;
                border-left:5px solid #1a3a6c;margin-top:12px;margin-bottom:12px;
                box-shadow:0 2px 8px rgba(0,0,0,0.4);">
        <p style="font-size:0.85rem;font-weight:700;color:#1a3a6c;margin:0 0 4px 0">
            Entrenamiento con Dataset Estandar IEEE
        </p>
        <p style="font-size:0.85rem;color:#2c3e50;margin:0">
            Modelo entrenado con CSE-CIC-IDS2018 (University of New Brunswick, Canada) — 
            298.803 eventos de red reales, 5 fases MITRE ATT&CK, <strong>F1 = 1.0</strong>.
            Referencia: Sharafaldin et al., ICISSP 2018.
        </p>
    </div>""", unsafe_allow_html=True)

    ultimo = retrain.get("ultimo")
    if ultimo:
        estado_color = "#27ae60" if "mejora" in ultimo.get("estado","") else "#f39c12"
        st.markdown(f"""
        <div style="background:#161b22;padding:12px 16px;border-radius:8px;
                    border-left:3px solid {estado_color};
                    box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;">
                <span style="font-size:0.85rem;color:#c9d1d9">
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
            <div style="background:#161b22;padding:16px;border-radius:8px;
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
                <p style="font-size:0.85rem;color:#c9d1d9;margin:0 0 6px 0">
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
        "reconnaissance":       "#5d6d7e",
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

    st.markdown('<div class="section-header">Campañas APT Detectadas</div>', unsafe_allow_html=True)
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
        tabla_oscura(df_apt, use_container_width=True, hide_index=True)

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
                plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                margin=dict(l=0, r=0, t=10, b=0), height=350, showlegend=False,
                xaxis=dict(showgrid=True, gridcolor="#f0f0f0"),
                yaxis=dict(showgrid=True, gridcolor="#f0f0f0",
                           categoryorder="array", categoryarray=list(fases_colores.keys())),
            )
            st.plotly_chart(fig_tl, use_container_width=True)
            st.markdown('<p style="font-size:0.75rem;color:#7f8c8d;text-align:center">Cada punto representa una campana APT detectada. El tamano indica la confianza del modelo.</p>', unsafe_allow_html=True)

            st.markdown('<div class="section-header">IPs con Progresion Multi-Fase</div>', unsafe_allow_html=True)
            st.markdown('<p style="font-size:0.8rem;color:#8b949e;margin-bottom:12px">Progresion de fases MITRE detectada por IP individual — solo se muestra cuando una misma IP presenta 2 o mas fases distintas.</p>', unsafe_allow_html=True)
            fases_orden = ["reconnaissance","initial_access","execution","persistence",
                           "privilege_escalation","defense_evasion","credential_access",
                           "discovery","lateral_movement","collection","exfiltration"]
            
            ips_multi_fase = df_timeline.groupby("ip")["fase_mitre"].apply(lambda x: sorted(set(x), key=lambda f: fases_orden.index(f) if f in fases_orden else 99))
            ips_multi_fase = ips_multi_fase[ips_multi_fase.apply(len) >= 2]
            
            if len(ips_multi_fase) > 0:
                items_list = list(ips_multi_fase.items())
                
                html_todas = '<div style="max-height:400px;overflow-y:auto;padding-right:8px;">'
                for ip_camp, fases_ip in items_list:
                    html_todas += f'<p style="font-size:0.8rem;color:#c9d1d9;margin:12px 0 4px 0"><strong>{ip_camp}</strong></p>'
                    html_todas += '<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:10px;background:#161b22;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.4);margin-bottom:12px;">'
                    for i, fase in enumerate(fases_ip):
                        color = fases_colores.get(fase, "#bdc3c7")
                        html_todas += f'<div style="background:{color};color:white;padding:5px 10px;border-radius:6px;font-size:0.7rem;font-weight:600;">{fase.replace("_"," ").upper()}</div>'
                        if i < len(fases_ip) - 1:
                            html_todas += '<span style="color:#bdc3c7;font-size:1rem">→</span>'
                    html_todas += '</div>'
                html_todas += '</div>'
                st.markdown(html_todas, unsafe_allow_html=True)
                
                nivel_max = ips_multi_fase.apply(len).max()
                if nivel_max >= 4:
                    st.error(f"Se han detectado IPs con hasta {nivel_max} fases MITRE progresivas — posibles campañas APT reales, requieren revisión manual.")
                else:
                    st.warning(f"Se han detectado IPs con progresión de hasta {nivel_max} fases MITRE distintas.")
            else:
                st.info("Ninguna IP individual presenta progresión de múltiples fases MITRE en las últimas detecciones — todas las detecciones actuales corresponden a fase única por IP.")

    else:
        st.info("No se han detectado campañas APT todavia. El sistema esta monitorizando activamente.")
        st.markdown("""
        <div style="background:#161b22;padding:16px;border-radius:8px;
                    border-left:3px solid #27ae60;margin-top:8px;">
            <p style="font-size:0.9rem;color:#2c3e50;margin:0">
                El motor LSTM analiza cada alerta recibida y acumula eventos en un buffer
                deslizante de 32 posiciones. Cuando detecta una secuencia consistente con
                una campana APT segun el framework MITRE ATT&CK, registra la campaña aquí
                con su fase, confianza y explicación XAI.
            </p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    st.markdown('<div class="section-header">Explicaciones XAI — Cumplimiento EU AI Act</div>', unsafe_allow_html=True)
    try:
        explicaciones = requests.get("http://localhost:8000/apt/xai", headers=HEADERS, timeout=5).json()
    except:
        explicaciones = []

    if explicaciones:
        vistas = set()
        ejemplos_variados = []
        for exp in reversed(explicaciones):
            fase = exp.get("fase_detectada", exp.get("fase_mitre", ""))
            if fase not in vistas:
                vistas.add(fase)
                ejemplos_variados.append(exp)
            if len(ejemplos_variados) == 3:
                break
        if len(ejemplos_variados) < 3:
            for exp in reversed(explicaciones):
                if exp not in ejemplos_variados:
                    ejemplos_variados.append(exp)
                if len(ejemplos_variados) == 3:
                    break
        for exp in ejemplos_variados:
            nivel_color = {
                "CRITICO": "#e74c3c", "ALTO": "#e67e22",
                "MEDIO": "#f39c12", "BAJO": "#27ae60"
            }.get(exp.get("nivel_riesgo", "BAJO"), "#bdc3c7")
            st.markdown(f"""
            <div style="background:#161b22;padding:16px;border-radius:8px;
                        border-left:4px solid {nivel_color};
                        box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                    <span style="font-weight:600;color:#2c3e50">
                        {exp.get("fase_detectada","").replace("_"," ").upper()}
                    </span>
                    <span style="color:#7f8c8d;font-size:0.85rem">Confianza: {exp.get("confianza",0)}%</span>
                </div>
                <p style="font-size:0.85rem;color:#e6edf3;margin:0 0 8px 0">{exp.get("narrativa","")}</p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    {"".join([
                        f'<span style="background:#161b22;padding:3px 8px;border-radius:4px;font-size:0.75rem;color:#2c3e50">'
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
        fig.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                         margin=dict(l=0,r=0,t=10,b=0), height=300,
                         showlegend=False, coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("La importancia global de features se calculara tras las primeras detecciones APT.")

# ══════════════════════════════════════════════════════════════════════════════
# ANALISIS FORENSE
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Análisis Forense":
    st.markdown("## Análisis Forense de Incidentes")
    st.markdown("Reconstrucción cronológica de incidentes, correlación de evidencias y exportación de informes con cadena de custodia.")
    st.markdown("---")

    # ── Busqueda de incidente ──────────────────────────────────────────────
    st.markdown('<div class="section-header">Busqueda de Incidente</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([4, 1])
    with col1:
        ip_pivot_value = st.session_state.get("ip_forense_pivot", "")
        ip_forense = st.text_input("IP a investigar", 
                                    value=ip_pivot_value,
                                    placeholder="Ej: 185.220.101.45",
                                    key="ip_forense_input")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        buscar = st.button("Investigar IP", type="primary", use_container_width=True, key="btn_investigar_ip")

    if ip_pivot_value:
        buscar = True
        ip_forense = ip_pivot_value
        st.session_state.pop("ip_forense_pivot", None)

    if buscar and ip_forense:
        st.markdown("---")
        st.markdown(f"### Investigación forense: `{ip_forense}`")

        # ── 1. Alertas Wazuh relacionadas ──────────────────────────────────
        st.markdown('<div class="section-header">Eventos Wazuh Detectados</div>', unsafe_allow_html=True)
        df_ip = df[df["ip"] == ip_forense].copy() if not df.empty else pd.DataFrame()
        if not df_ip.empty:
            df_ip["timestamp"] = df_ip["timestamp"].dt.strftime("%d/%m/%Y %H:%M:%S")
            df_ip = df_ip[["timestamp","tipo","nivel","agente","accion"]].copy()
            df_ip.columns = ["Timestamp","Tipo de Evento","Nivel","Agente","Accion"]
            tabla_oscura(df_ip.head(10), use_container_width=True, hide_index=True)
            st.markdown(f"**{len(df_ip)} eventos detectados por Wazuh**")
        else:
            st.info("No se encontraron eventos Wazuh para esta IP.")

        # ── Alertas Suricata relacionadas ──────────────────────────────────
        st.markdown('<div class="section-header">Alertas de Red — Suricata IDS</div>', unsafe_allow_html=True)
        # Busqueda forense en todo el archivo Suricata (sin limite de lineas)
        alertas_sur_ip = []
        try:
            resultado_grep = subprocess.run(
                ["bash", "-c", f"{{ tail -c 50M /var/log/suricata/eve.json; zcat /var/log/suricata/eve.json.*.gz 2>/dev/null; }} | grep '{ip_forense}'"],
                capture_output=True, text=True, errors="ignore",
                timeout=60
            )
            for line in resultado_grep.stdout.splitlines():
                try:
                    e = json.loads(line)
                    if e.get("event_type") == "alert":
                        src = e.get("src_ip", "")
                        dst = e.get("dest_ip", "")
                        if ip_forense in [src, dst]:
                            alertas_sur_ip.append({
                                "timestamp": e.get("timestamp", ""),
                                "src_ip":    src,
                                "dest_ip":   dst,
                                "dest_port": e.get("dest_port", 0),
                                "proto":     e.get("proto", ""),
                                "firma":     e.get("alert", {}).get("signature", ""),
                                "severidad": e.get("alert", {}).get("severity", 3),
                                "direccion": "ENTRANTE" if dst == "91.98.126.215" else "SALIENTE"
                            })
                except:
                    continue
        except:
            pass
        if alertas_sur_ip:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f"""<div class="metric-card" style="border-top:3px solid #f85149;">
                    <p class="metric-label">Alertas de Red</p>
                    <p style="font-size:2rem;font-weight:700;color:#f85149;">{len(alertas_sur_ip)}</p>
                </div>""", unsafe_allow_html=True)
            with col2:
                firmas_unicas = len(set(a.get("firma","") for a in alertas_sur_ip))
                st.markdown(f"""<div class="metric-card" style="border-top:3px solid #d29922;">
                    <p class="metric-label">Firmas Unicas</p>
                    <p style="font-size:2rem;font-weight:700;color:#d29922;">{firmas_unicas}</p>
                </div>""", unsafe_allow_html=True)
            with col3:
                puertos = list(set(a.get("dest_port","") for a in alertas_sur_ip))
                st.markdown(f"""<div class="metric-card" style="border-top:3px solid #388bfd;">
                    <p class="metric-label">Puertos Atacados</p>
                    <p style="font-size:2rem;font-weight:700;color:#388bfd;">{", ".join(str(p) for p in puertos[:5])}</p>
                </div>""", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            df_sur_ip = pd.DataFrame(alertas_sur_ip)
            df_sur_ip["timestamp"] = pd.to_datetime(df_sur_ip["timestamp"]).dt.strftime("%d/%m %H:%M:%S")
            df_sur_ip = df_sur_ip[["timestamp","src_ip","dest_ip","dest_port","proto","firma","severidad","direccion"]].copy()
            df_sur_ip.columns = ["Timestamp","IP Origen","IP Destino","Puerto","Protocolo","Firma Suricata","Severidad","Direccion"]
            tabla_oscura(df_sur_ip.head(50))
        else:
            st.info("No se encontraron alertas de Suricata para esta IP en el período actual.")

        # ── 2. Campanas APT relacionadas ───────────────────────────────────
        st.markdown('<div class="section-header">Campanas APT Asociadas</div>', unsafe_allow_html=True)
        try:
            campanas = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
            campanas_ip = [c for c in campanas if c.get("ip") == ip_forense]
            if campanas_ip:
                df_camp = pd.DataFrame(campanas_ip)
                df_camp["timestamp"] = pd.to_datetime(df_camp["timestamp"]).dt.strftime("%d/%m/%Y %H:%M")
                tabla_oscura(df_camp[["timestamp","fase_mitre","confianza","nivel_riesgo","n_eventos"]], 
                           use_container_width=True, hide_index=True)
            else:
                st.info("No se detectaron campanas APT para esta IP.")
        except:
            st.info("No hay datos de campanas APT disponibles.")

        # ── 3. Movimiento lateral relacionado ──────────────────────────────
        st.markdown('<div class="section-header">Movimiento Lateral Detectado</div>', unsafe_allow_html=True)
        try:
            lateral = requests.get("http://localhost:8000/apt/lateral", headers=HEADERS, timeout=5).json()
            lateral_ip = [l for l in lateral if l.get("ip_origen") == ip_forense]
            if lateral_ip:
                for det in lateral_ip:
                    st.markdown(f"""
                    <div style="background:#161b22;padding:12px 16px;border-radius:8px;
                                border-left:4px solid #e74c3c;box-shadow:0 2px 6px rgba(0,0,0,0.07);margin-bottom:8px;">
                        <p style="font-weight:600;color:#2c3e50;margin:0 0 4px 0">
                            {det.get('patron','').replace('_',' ').upper()} — {det.get('mitre_tecnica','')}
                        </p>
                        <p style="font-size:0.85rem;color:#7f8c8d;margin:0">
                            Agentes afectados: {' → '.join(det.get('agentes_afectados',[]))} | 
                            Severidad: {det.get('severidad','')} | 
                            Confianza: {det.get('confianza',0)}%
                        </p>
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("No se detectó movimiento lateral para esta IP.")
        except:
            st.info("No hay datos de movimiento lateral disponibles.")

        # ── 4. Reputacion AbuseIPDB ────────────────────────────────────────
        st.markdown('<div class="section-header">Inteligencia de Amenazas — AbuseIPDB</div>', unsafe_allow_html=True)
        abuse = consultar_abuseipdb(ip_forense)
        enriq = enriquecer_ip(ip_forense)
        if abuse:
            col1, col2, col3, col4 = st.columns(4)
            score = abuse.get("score", 0)
            color = "#e74c3c" if score >= 80 else "#f39c12" if score >= 40 else "#27ae60"
            with col1:
                st.markdown(f"""
                <div class="metric-card" style="border-top:3px solid {color};">
                    <p class="metric-label">Puntuacion Abuso</p>
                    <p style="font-size:2rem;font-weight:700;color:{color};">{score}%</p>
                </div>""", unsafe_allow_html=True)
            with col2:
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">Pais</p>
                    <p style="font-size:1.5rem;font-weight:700;color:#2c3e50;">{abuse.get("pais","—")}</p>
                </div>""", unsafe_allow_html=True)
            with col3:
                st.markdown(f"""
                <div class="metric-card">
                    <p class="metric-label">Reportes Totales</p>
                    <p style="font-size:1.5rem;font-weight:700;color:#2c3e50;">{abuse.get("reportes",0)}</p>
                </div>""", unsafe_allow_html=True)
            with col4:
                tor = "Sí" if abuse.get("es_tor") else "No"
                color_tor = "#e74c3c" if abuse.get("es_tor") else "#27ae60"
                st.markdown(f"""
                <div class="metric-card" style="border-top:3px solid {color_tor};">
                    <p class="metric-label">Nodo TOR</p>
                    <p style="font-size:1.5rem;font-weight:700;color:{color_tor};">{tor}</p>
                </div>""", unsafe_allow_html=True)

            # Enriquecimiento adicional
            if enriq:
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    dc = "Sí" if enriq.get("es_datacenter") else "No"
                    color_dc = "#e74c3c" if enriq.get("es_datacenter") else "#3fb950"
                    st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color_dc};">
                        <p class="metric-label">Datacenter</p>
                        <p style="font-size:1.5rem;font-weight:700;color:{color_dc};">{dc}</p>
                    </div>""", unsafe_allow_html=True)
                with col2:
                    st.markdown(f"""<div class="metric-card">
                        <p class="metric-label">Ciudad</p>
                        <p style="font-size:1.2rem;font-weight:700;color:#c9d1d9;">{enriq.get("ciudad","—")}, {enriq.get("region","—")}</p>
                    </div>""", unsafe_allow_html=True)
                with col3:
                    st.markdown(f"""<div class="metric-card">
                        <p class="metric-label">ASN</p>
                        <p style="font-size:0.9rem;font-weight:700;color:#c9d1d9;">{enriq.get("asn","—")}</p>
                    </div>""", unsafe_allow_html=True)
                with col4:
                    ptr = enriq.get("ptr","—") or "—"
                    st.markdown(f"""<div class="metric-card">
                        <p class="metric-label">Dominio Inverso (PTR)</p>
                        <p style="font-size:0.85rem;font-weight:700;color:#c9d1d9;">{ptr}</p>
                    </div>""", unsafe_allow_html=True)
                with col5:
                    isp = enriq.get("isp","—") or abuse.get("isp","—")
                    st.markdown(f"""<div class="metric-card">
                        <p class="metric-label">ISP</p>
                        <p style="font-size:0.85rem;font-weight:700;color:#c9d1d9;">{isp}</p>
                    </div>""", unsafe_allow_html=True)
        else:
            st.info("No se pudo obtener información de AbuseIPDB para esta IP.")

        # ── Correlación de IPs — mismo atacante ───────────────────────────
        if enriq and enriq.get("asn"):
            asn_forense = enriq.get("asn", "")
            datos_sur = cargar_suricata()
            ips_correladas = []
            for a in datos_sur.get("alertas", []):
                ip_sur = a.get("src_ip", "")
                if ip_sur and ip_sur != ip_forense and not es_ip_whitelist(ip_sur):
                    enriq_sur = enriquecer_ip(ip_sur)
                    if enriq_sur.get("asn") == asn_forense:
                        ips_correladas.append(ip_sur)
            ips_correladas = list(set(ips_correladas))
            if ips_correladas:
                st.markdown('<div class="section-header">IPs Relacionadas — Mismo Atacante</div>', unsafe_allow_html=True)
                st.markdown(f"Se han detectado **{len(ips_correladas)} IPs adicionales** del mismo ASN `{asn_forense}` atacando el servidor:")
                cols = st.columns(min(len(ips_correladas), 4))
                for i, ip_rel in enumerate(ips_correladas[:4]):
                    with cols[i]:
                        abuse_rel = consultar_abuseipdb(ip_rel)
                        color_rel = "#f85149" if abuse_rel.get("score",0) >= 80 else "#d29922" if abuse_rel.get("score",0) >= 40 else "#3fb950"
                        st.markdown(f"""<div class="metric-card" style="border-top:3px solid {color_rel};">
                            <p class="metric-label">{ip_rel}</p>
                            <p style="font-size:0.9rem;font-weight:700;color:{color_rel};">AbuseIPDB {abuse_rel.get('score',0)}%</p>
                        </div>""", unsafe_allow_html=True)

        # ── 5. Timeline forense ────────────────────────────────────────────
        st.markdown('<div class="section-header">Timeline Forense del Incidente</div>', unsafe_allow_html=True)
        eventos_timeline = []

        # Eventos Wazuh
        if not df_ip.empty:
            for _, row in df[df["ip"] == ip_forense].iterrows():
                eventos_timeline.append({
                    "timestamp":   row["timestamp"],
                    "tipo":        "WAZUH",
                    "descripcion": row["tipo"],
                    "nivel":       row["nivel"],
                    "color":       "#e74c3c" if row["nivel"] >= 12 else "#f39c12" if row["nivel"] >= 10 else "#2980b9"
                })

        # Eventos Suricata
        for a in alertas_sur_ip:
            try:
                eventos_timeline.append({
                    "timestamp":   pd.to_datetime(a["timestamp"]),
                    "tipo":        "IDS",
                    "descripcion": f"{a.get('firma','—')} [{a.get('direccion','—')}]",
                    "nivel":       a.get("severidad", 3),
                    "color":       "#f85149" if a.get("severidad") == 1 else "#d29922" if a.get("severidad") == 2 else "#388bfd"
                })
            except:
                continue

        # Campañas APT
        try:
            campanas = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
            for c in campanas:
                if c.get("ip") == ip_forense:
                    eventos_timeline.append({
                        "timestamp":   pd.to_datetime(c.get("timestamp")),
                        "tipo":        "APT",
                        "descripcion": f"Campaña APT detectada — Fase {c.get('fase_mitre','—')} (confianza {c.get('confianza',0)}%)",
                        "nivel":       12,
                        "color":       "#8b5cf6"
                    })
        except:
            pass

        # Limitar a los 50 eventos mas recientes
        eventos_timeline = sorted(eventos_timeline, key=lambda x: str(x["timestamp"]))[-50:]

        if eventos_timeline:
            eventos_timeline.sort(key=lambda x: str(x["timestamp"]))
            for ev in eventos_timeline:
                ts = ev["timestamp"].strftime("%d/%m/%Y %H:%M:%S") if hasattr(ev["timestamp"], "strftime") else str(ev["timestamp"])
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f0f0f0;">
                    <span style="background:{ev['color']};color:white;padding:2px 8px;
                                border-radius:4px;font-size:0.75rem;font-weight:600;min-width:80px;text-align:center">
                        {ev['tipo']}
                    </span>
                    <span style="color:#7f8c8d;font-size:0.8rem;min-width:140px">{ts}</span>
                    <span style="background:#161b22;padding:2px 6px;border-radius:3px;
                                font-size:0.75rem;color:#1a3a6c;font-weight:600">{ev['tipo']}</span>
                    <span style="color:#2c3e50;font-size:0.85rem">{ev['descripcion']}</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("No hay eventos suficientes para construir el timeline.")


        # ── 6. Exportar informe forense ────────────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-header">Exportar Informe Forense</div>', unsafe_allow_html=True)

        # Generar PDF directamente sin boton intermedio
        if True:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.units import cm
            import io

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4,
                                   rightMargin=2*cm, leftMargin=2*cm,
                                   topMargin=2*cm, bottomMargin=2*cm)

            style_title  = ParagraphStyle('t', fontSize=20, fontName='Helvetica-Bold', textColor=colors.HexColor('#0f1f35'), spaceAfter=6)
            style_h2     = ParagraphStyle('h2', fontSize=13, fontName='Helvetica-Bold', textColor=colors.HexColor('#1a3a6c'), spaceAfter=8, spaceBefore=16)
            style_body   = ParagraphStyle('b', fontSize=10, fontName='Helvetica', textColor=colors.HexColor('#2c3e50'), spaceAfter=6)
            style_small  = ParagraphStyle('s', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#7f8c8d'))

            elements = []
            elements.append(Paragraph("NOCTUA PREDICTIVE", style_title))
            elements.append(Paragraph("Informe Forense de Incidente", ParagraphStyle('st', fontSize=14, fontName='Helvetica', textColor=colors.HexColor('#4a6fa5'), spaceAfter=4)))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a3a6c')))
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph(f"IP investigada: {ip_forense}", style_h2))
            elements.append(Paragraph(f"Fecha del informe: {hora_local().strftime('%d/%m/%Y %H:%M:%S')}", style_small))
            elements.append(Paragraph(f"Analista: {name}", style_small))
            elements.append(Spacer(1, 0.5*cm))

            # Reputacion
            elements.append(Paragraph("Inteligencia de Amenazas", style_h2))
            if abuse:
                data_abuse = [
                    ["Parametro", "Valor"],
                    ["Puntuacion de abuso", f"{abuse.get('score',0)}%"],
                    ["Pais de origen", abuse.get("pais","—")],
                    ["ISP", abuse.get("isp","—")],
                    ["Reportes totales", str(abuse.get("reportes",0))],
                    ["Nodo TOR", "Si" if abuse.get("es_tor") else "No"],
                ]
                tabla = Table(data_abuse, colWidths=[6*cm, 9*cm])
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

            # Eventos Wazuh
            elements.append(Paragraph("Eventos Wazuh Detectados", style_h2))
            if not df_ip.empty:
                data_ev = [["Timestamp", "Tipo", "Nivel", "Accion"]]
                for _, row in df[df["ip"] == ip_forense].head(20).iterrows():
                    data_ev.append([
                        str(row["timestamp"])[:16],
                        row["tipo"][:50],
                        str(row["nivel"]),
                        row["accion"]
                    ])
                tabla_ev = Table(data_ev, colWidths=[3.5*cm, 8*cm, 2*cm, 2.5*cm])
                tabla_ev.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3a6c')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f5f6fa'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e0e0e0')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                elements.append(tabla_ev)
            else:
                elements.append(Paragraph("No se encontraron eventos Wazuh.", style_body))

            # Campanas APT en el PDF
            elements.append(Paragraph("Campanas APT Detectadas", style_h2))
            try:
                campanas_pdf = requests.get("http://localhost:8000/apt/campanas", headers=HEADERS, timeout=5).json()
                campanas_ip_pdf = [c for c in campanas_pdf if c.get("ip") == ip_forense]
                if campanas_ip_pdf:
                    data_apt = [["Timestamp", "Fase MITRE", "Confianza", "Riesgo"]]
                    for c in campanas_ip_pdf:
                        data_apt.append([
                            str(c.get("timestamp",""))[:16].replace("T"," "),
                            c.get("fase_mitre","").replace("_"," ").upper(),
                            f"{c.get('confianza',0)}%",
                            c.get("nivel_riesgo","")
                        ])
                    tabla_apt = Table(data_apt, colWidths=[4*cm, 5*cm, 3*cm, 3*cm])
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
                    elements.append(Paragraph("No se detectaron campanas APT.", style_body))
            except:
                elements.append(Paragraph("No hay datos de campanas APT.", style_body))

            elements.append(Spacer(1, 1*cm))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0')))
            elements.append(Paragraph(f"Noctua Predictive — Informe Forense | {hora_local().strftime('%d/%m/%Y')}", style_small))

            doc.build(elements)
            buffer.seek(0)
            st.success("Informe forense generado.")
            st.download_button(
                label="Descargar Informe Forense PDF",
                data=buffer,
                file_name=f"forense_{ip_forense.replace('.','_')}_{hora_local().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                type="primary"
            )

# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Threat Hunting":
    st.markdown("## Threat Hunting — Búsqueda Proactiva de Amenazas")
    st.markdown("---")
    
    tab_hunt, tab_search = st.tabs(["Consultas Predefinidas", "Búsqueda Libre"])
    
    with tab_hunt:
        st.markdown("Consultas predefinidas para detectar amenazas que no han disparado alertas automáticas.")
        consultas = {
            "IPs con AbuseIPDB > 50% no bloqueadas": "abuse_no_bloqueadas",
            "IPs que atacaron más de 3 puertos distintos": "multi_puerto",
            "IPs activas entre 00:00 y 06:00": "horario_nocturno",
            "Países con más de 100 alertas Suricata hoy": "top_paises",
            "ASNs con más de 2 IPs distintas atacando": "asn_coordinado",
            "IPs con más de 1000 alertas Suricata hoy": "alto_volumen",
        }

        col1, col2 = st.columns([3, 1])
        with col1:
            consulta_sel = st.selectbox("Selecciona una hipótesis de hunting", list(consultas.keys()))
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            ejecutar = st.button("Ejecutar búsqueda", type="primary", use_container_width=True)

        if ejecutar:
            tipo = consultas[consulta_sel]
            datos_sur = cargar_suricata()
            alertas_sur = datos_sur.get("alertas", [])
            ips_bloq = set(ips_bloqueadas)

            with st.spinner("Buscando..."):
                if tipo == "abuse_no_bloqueadas":
                    st.markdown('<div class="section-header">IPs con AbuseIPDB > 50% no bloqueadas</div>', unsafe_allow_html=True)
                    ips_unicas = list(set(a.get("src_ip","") for a in alertas_sur if a.get("src_ip") and not es_ip_whitelist(a.get("src_ip",""))))
                    rows = []
                    for ip in ips_unicas[:50]:
                        if ip not in ips_bloq:
                            abuse = consultar_abuseipdb(ip)
                            if abuse.get("score", 0) >= 50:
                                rows.append({"IP": ip, "Score AbuseIPDB": f"{abuse.get('score',0)}%", "País": abuse.get("pais","—"), "ISP": abuse.get("isp","—")})
                    if rows:
                        tabla_oscura(pd.DataFrame(rows), hide_index=True)
                    else:
                        st.success("No se encontraron IPs sospechosas sin bloquear.")

                elif tipo == "multi_puerto":
                    st.markdown('<div class="section-header">IPs atacando múltiples puertos</div>', unsafe_allow_html=True)
                    from collections import defaultdict
                    ip_puertos = defaultdict(set)
                    for a in alertas_sur:
                        ip = a.get("src_ip","")
                        puerto = a.get("dest_port","")
                        if ip and puerto and not es_ip_whitelist(ip):
                            ip_puertos[ip].add(puerto)
                    rows = [{"IP": ip, "Puertos Distintos": len(puertos), "Puertos": ", ".join(str(p) for p in list(puertos)[:5])}
                            for ip, puertos in ip_puertos.items() if len(puertos) >= 2]
                    rows.sort(key=lambda x: x["Puertos Distintos"], reverse=True)
                    if rows:
                        tabla_oscura(pd.DataFrame(rows[:20]), hide_index=True)
                    else:
                        st.info("No se encontraron IPs atacando múltiples puertos.")

                elif tipo == "horario_nocturno":
                    st.markdown('<div class="section-header">IPs activas entre 00:00 y 06:00</div>', unsafe_allow_html=True)
                    from collections import Counter
                    ips_nocturnas = []
                    for a in alertas_sur:
                        try:
                            hora = pd.to_datetime(a.get("timestamp","")).hour
                            if 0 <= hora < 6:
                                ip = a.get("src_ip","")
                                if ip and not es_ip_whitelist(ip):
                                    ips_nocturnas.append(ip)
                        except: pass
                    rows = [{"IP": ip, "Alertas nocturnas": n} for ip, n in Counter(ips_nocturnas).most_common(20)]
                    if rows:
                        tabla_oscura(pd.DataFrame(rows), hide_index=True)
                    else:
                        st.info("No se encontró actividad nocturna sospechosa.")

                elif tipo == "top_paises":
                    st.markdown('<div class="section-header">Países con más alertas Suricata</div>', unsafe_allow_html=True)
                    from collections import Counter
                    paises = []
                    for ip in set(a.get("src_ip","") for a in alertas_sur if a.get("src_ip")):
                        if not es_ip_whitelist(ip):
                            enriq = enriquecer_ip(ip)
                            if enriq.get("pais"):
                                paises.append(enriq.get("pais"))
                    rows = [{"País": p, "IPs distintas": n} for p, n in Counter(paises).most_common(10) if n >= 1]
                    if rows:
                        tabla_oscura(pd.DataFrame(rows), hide_index=True)
                    else:
                        st.info("No hay suficientes datos de geolocalización.")

                elif tipo == "asn_coordinado":
                    st.markdown('<div class="section-header">ASNs con múltiples IPs atacando</div>', unsafe_allow_html=True)
                    from collections import defaultdict
                    asn_ips = defaultdict(set)
                    for ip in set(a.get("src_ip","") for a in alertas_sur if a.get("src_ip")):
                        if not es_ip_whitelist(ip):
                            enriq = enriquecer_ip(ip)
                            asn = enriq.get("asn","")
                            if asn:
                                asn_ips[asn].add(ip)
                    rows = [{"ASN": asn, "IPs distintas": len(ips), "IPs": ", ".join(list(ips)[:3])}
                            for asn, ips in asn_ips.items() if len(ips) >= 2]
                    rows.sort(key=lambda x: x["IPs distintas"], reverse=True)
                    if rows:
                        tabla_oscura(pd.DataFrame(rows[:15]), hide_index=True)
                    else:
                        st.info("No se detectaron ASNs coordinados.")

                elif tipo == "alto_volumen":
                    st.markdown('<div class="section-header">IPs con alto volumen de alertas</div>', unsafe_allow_html=True)
                    from collections import Counter
                    conteo = Counter(a.get("src_ip","") for a in alertas_sur if a.get("src_ip") and not es_ip_whitelist(a.get("src_ip","")))
                    rows = [{"IP": ip, "Alertas": n, "Bloqueada": "Sí" if ip in ips_bloq else "No"}
                            for ip, n in conteo.most_common(20) if n >= 5]
                    if rows:
                        tabla_oscura(pd.DataFrame(rows), hide_index=True)
                    else:
                        st.info("No hay IPs con alto volumen de alertas.")
    
    with tab_search:
        st.markdown("Busca en todos los eventos de Wazuh y Suricata usando texto libre.")
        st.markdown("""
        <style>
        .search-input textarea, .search-input input {
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
            font-size: 1rem !important;
            background: #0d1117 !important;
            color: #79c0ff !important;
            border: 1px solid #388bfd !important;
        }
        </style>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns([5, 1])
        with col1:
            query = st.text_area("", placeholder="Buscar: IP, firma, descripción... Ej: 'SSH' o '45.148.10.183'",
                                  key="hunt_search_query", label_visibility="collapsed", height=80)
        with col2:
            fuente = st.selectbox("Fuente", ["Ambas", "Wazuh", "Suricata"], key="hunt_fuente", label_visibility="collapsed")
            buscar = st.button("Buscar", type="primary", use_container_width=True, key="btn_hunt_search")
        
        if buscar and query:
            resultados_wazuh = pd.DataFrame()
            resultados_suricata = []
            
            if fuente in ["Ambas", "Wazuh"]:
                resultados_wazuh = df[
                    df["tipo"].str.contains(query, case=False, na=False) |
                    df["ip"].str.contains(query, case=False, na=False) |
                    df["id_regla"].astype(str).str.contains(query, case=False, na=False)
                ].copy()
            
            if fuente in ["Ambas", "Suricata"]:
                datos_sur = cargar_suricata()
                alertas_sur = datos_sur.get("alertas", [])
                resultados_suricata = [a for a in alertas_sur if
                    query.lower() in str(a.get("firma","")).lower() or
                    query.lower() in str(a.get("src_ip","")).lower() or
                    query.lower() in str(a.get("dest_ip","")).lower()]
            
            total = len(resultados_wazuh) + len(resultados_suricata)
            st.markdown(f"**{total} resultados encontrados para: `{query}`**")
            
            if fuente in ["Ambas", "Wazuh"] and len(resultados_wazuh) > 0:
                st.markdown('<div class="section-header">Resultados Wazuh</div>', unsafe_allow_html=True)
                df_show = resultados_wazuh[["timestamp","tipo","ip","nivel","agente","accion"]].copy()
                df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m/%Y %H:%M")
                df_show.columns = ["Timestamp","Tipo","IP","Nivel","Agente","Estado"]
                tabla_oscura(df_show.head(50), use_container_width=True, hide_index=True)
            
            if fuente in ["Ambas", "Suricata"] and len(resultados_suricata) > 0:
                st.markdown('<div class="section-header">Resultados Suricata</div>', unsafe_allow_html=True)
                df_sur = pd.DataFrame(resultados_suricata[:50])
                if not df_sur.empty:
                    df_sur = df_sur[["timestamp","src_ip","firma","dest_port","severidad"]].copy()
                    df_sur.columns = ["Timestamp","IP Origen","Firma","Puerto","Severidad"]
                    tabla_oscura(df_sur, use_container_width=True, hide_index=True)
            
            if total == 0:
                st.info(f"No se encontraron resultados para '{query}'.")


# ══════════════════════════════════════════════════════════════════════════════
# GESTION DE INCIDENTES
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Gestión de Incidentes":
    st.markdown("## Gestión de Incidentes")
    st.markdown("Sistema de tickets integrado con el motor LSTM, XAI y AbuseIPDB.")
    st.markdown("---")

    # ── Metricas globales ──────────────────────────────────────────────────
    try:
        metricas = requests.get("http://localhost:8000/tickets/metricas/resumen",
                                headers=HEADERS, timeout=5).json()
    except:
        metricas = {}

    col1, col2, col3, col4, col4b, col5 = st.columns(6)
    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #388bfd;">
            <p class="metric-label">Total Tickets</p>
            <p class="metric-value">{metricas.get("total", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        n = metricas.get("abiertos", 0)
        color = "#f85149" if n > 0 else "#3fb950"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Abiertos</p>
            <p class="metric-value" style="color:{color}">{n}</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        n = metricas.get("investigando", 0)
        color = "#d29922" if n > 0 else "#8b949e"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Investigando</p>
            <p class="metric-value" style="color:{color}">{n}</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #3fb950;">
            <p class="metric-label">Resueltos</p>
            <p class="metric-value" style="color:#3fb950">{metricas.get("resueltos", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col4b:
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #388bfd;">
            <p class="metric-label">Contenidos</p>
            <p class="metric-value" style="color:#388bfd">{metricas.get("contenidos", 0)}</p>
        </div>""", unsafe_allow_html=True)
    with col5:
        mttr = metricas.get("mttr_horas", 0)
        color = "#3fb950" if mttr <= 24 else "#d29922" if mttr <= 48 else "#f85149"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">MTTR (horas)</p>
            <p class="metric-value" style="color:{color}">{mttr}</p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["Tickets", "Nuevo Ticket", "Metricas"])

    # ── TAB 1: Lista de tickets ────────────────────────────────────────────
    with tab1:
        col1, col2, col3 = st.columns(3)
        with col1:
            filtro_estado = st.selectbox("Estado", ["Abierto", "Investigando", "Todos",
                                                     "Contenido", "Resuelto", "Cerrado"])
        with col2:
            filtro_prioridad = st.selectbox("Prioridad", ["Todas", "CRITICA", "ALTA",
                                                            "MEDIA", "BAJA"])
        with col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Actualizar", key="btn_actualizar_tickets"):
                st.rerun()

        try:
            params = {}
            if filtro_estado != "Todos":
                params["estado"] = filtro_estado
            if filtro_prioridad != "Todas":
                params["prioridad"] = filtro_prioridad
            tickets = requests.get("http://localhost:8000/tickets",
                                   headers=HEADERS, params=params, timeout=5).json()
        except:
            tickets = []

        if not tickets:
            st.info("No hay tickets que coincidan con los filtros.")
        else:
            for t in tickets:
                color_estado = {
                    "Abierto":      "#f85149",
                    "Investigando": "#d29922",
                    "Contenido":    "#388bfd",
                    "Resuelto":     "#3fb950",
                    "Cerrado":      "#8b949e",
                }.get(t["estado"], "#8b949e")
                color_prioridad = {
                    "CRITICA": "#f85149",
                    "ALTA":    "#d29922",
                    "MEDIA":   "#388bfd",
                    "BAJA":    "#3fb950",
                }.get(t["prioridad"], "#8b949e")
                ts = t["creado_en"][:16].replace("T", " ")
                with st.expander(f"{t['id']} — {t['titulo']} | {t['estado']} | {t['prioridad']}"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.markdown(f"""
                        <div style="background:#161b22;padding:16px;border-radius:8px;
                                    border-left:4px solid {color_estado};">
                            <div style="display:flex;gap:12px;margin-bottom:8px;">
                                <span style="background:{color_estado};color:white;padding:2px 8px;
                                            border-radius:4px;font-size:0.75rem;font-weight:600">
                                    {t['estado']}
                                </span>
                                <span style="background:{color_prioridad};color:white;padding:2px 8px;
                                            border-radius:4px;font-size:0.75rem;font-weight:600">
                                    {t['prioridad']}
                                </span>
                                <span style="color:#8b949e;font-size:0.8rem">{ts}</span>
                                <span style="color:#8b949e;font-size:0.8rem">
                                    Origen: {t.get('origen','manual')}
                                </span>
                            </div>
                            <p style="color:#c9d1d9;font-size:0.9rem;margin:0 0 8px 0">
                                {t['descripcion']}
                            </p>
                            <div style="display:flex;gap:16px;font-size:0.8rem;color:#8b949e;">
                                <span>IP: <strong style="color:#c9d1d9">{t.get('ip','—')}</strong></span>
                                <span>Fase MITRE: <strong style="color:#c9d1d9">
                                    {t.get('fase_mitre','—')}</strong></span>
                                <span>Confianza LSTM: <strong style="color:#c9d1d9">
                                    {t.get('confianza',0)}%</strong></span>
                                <span>AbuseIPDB: <strong style="color:#c9d1d9">
                                    {t.get('abuse_score',0)}%</strong></span>
                            </div>
                        </div>""", unsafe_allow_html=True)
                        with col2:
                            ip_ticket = t.get('ip', '')
                            if ip_ticket and ip_ticket != '—':
                                st.markdown("<br>", unsafe_allow_html=True)
                                st.markdown(f"""
                                <div style="background:#0d1117;border:1px solid #388bfd;
                                            border-radius:4px;padding:6px 10px;text-align:center;
                                            font-family:monospace;font-size:0.85rem;
                                            color:#79c0ff;font-weight:600;">
                                    {ip_ticket}
                                </div>""", unsafe_allow_html=True)
                                if st.button("Investigar en Forense", key=f"pivot_forense_{t['id']}", use_container_width=True):
                                    st.session_state.pagina = "Análisis Forense"
                                    st.session_state.ip_forense_pivot = ip_ticket
                                    st.rerun()
                                cache_local = set(json.load(open("/root/asoar/blocked_ips_cache.json"))) if os.path.exists("/root/asoar/blocked_ips_cache.json") else set()
                                if ip_ticket not in ips_bloqueadas and ip_ticket not in cache_local:
                                    if st.button("Bloquear IP", key=f"bloquear_ticket_{t['id']}", use_container_width=True, type="primary"):
                                        try:
                                            r = requests.post(f"http://localhost:8000/bloquear/{ip_ticket}", headers=HEADERS, timeout=10)
                                            if r.json().get("status") == "ok":
                                                st.success(f"IP {ip_ticket} bloqueada correctamente")
                                                # Actualizar ticket a Contenido
                                                requests.post(f"http://localhost:8000/tickets/{t['id']}/estado",
                                                    headers=HEADERS,
                                                    json={"estado": "Contenido", "nota": f"IP {ip_ticket} bloqueada manualmente desde el ticket."},
                                                    timeout=5)
                                                st.info("Cerrando ticket...")
                                                import time
                                                time.sleep(2)
                                                st.rerun()
                                            else:
                                                st.warning(f"IP {ip_ticket} ya estaba bloqueada.")
                                                requests.post(f"http://localhost:8000/tickets/{t['id']}/estado",
                                                    headers=HEADERS,
                                                    json={"estado": "Contenido", "nota": f"IP {ip_ticket} ya estaba bloqueada en Hetzner."},
                                                    timeout=5)
                                                st.info("Cerrando ticket...")
                                                import time
                                                time.sleep(2)
                                                st.rerun()
                                        except Exception as e:
                                            st.error(f"Error: {e}")
                                else:
                                    st.info("IP ya bloqueada en Hetzner")

                        if t.get("xai_narrativa"):
                            st.markdown(f"""
                            <div style="background:#0d2d6b;padding:12px;border-radius:6px;
                                        margin-top:8px;border-left:3px solid #388bfd;">
                                <p style="font-size:0.75rem;color:#79c0ff;font-weight:600;
                                          margin:0 0 4px 0">EXPLICACION XAI — SHAP</p>
                                <p style="font-size:0.85rem;color:#c9d1d9;margin:0">
                                    {t['xai_narrativa']}</p>
                            </div>""", unsafe_allow_html=True)

                        if t.get("notas"):
                            st.markdown('<p style="font-size:0.75rem;color:#388bfd;'
                                       'font-weight:600;margin:8px 0 4px 0">NOTAS</p>',
                                       unsafe_allow_html=True)
                            for nota in t["notas"]:
                                st.markdown(f"""
                                <div style="background:#161b22;padding:8px 12px;
                                            border-radius:6px;margin-bottom:4px;
                                            border-left:2px solid #30363d;">
                                    <span style="font-size:0.75rem;color:#8b949e">
                                        {nota['timestamp'][:16].replace('T',' ')}
                                    </span>
                                    <p style="font-size:0.85rem;color:#c9d1d9;margin:2px 0 0 0">
                                        {nota['texto']}</p>
                                </div>""", unsafe_allow_html=True)

                        if t.get("historial"):
                            st.markdown('<p style="font-size:0.75rem;color:#388bfd;'
                                       'font-weight:600;margin:8px 0 4px 0">HISTORIAL</p>',
                                       unsafe_allow_html=True)
                            for h in t["historial"]:
                                st.markdown(f"""
                                <div style="display:flex;gap:12px;padding:4px 0;
                                            border-bottom:1px solid #21262d;
                                            font-size:0.8rem;">
                                    <span style="color:#8b949e">
                                        {h['timestamp'][:16].replace('T',' ')}</span>
                                    <span style="color:#388bfd;font-weight:600">
                                        {h['estado']}</span>
                                    <span style="color:#c9d1d9">{h['nota']}</span>
                                </div>""", unsafe_allow_html=True)

                    with col2:
                        st.markdown("<br>", unsafe_allow_html=True)
                        nuevo_estado = st.selectbox("Cambiar estado",
                            ["Abierto", "Investigando", "Contenido", "Resuelto", "Cerrado"],
                            key=f"estado_{t['id']}",
                            index=["Abierto","Investigando","Contenido",
                                   "Resuelto","Cerrado"].index(t["estado"]))
                        nota_estado = st.text_input("Nota", key=f"nota_{t['id']}",
                                                     placeholder="Opcional")
                        if st.button("Actualizar estado", key=f"btn_estado_{t['id']}",
                                     use_container_width=True, type="secondary"):
                            try:
                                requests.post(
                                    f"http://localhost:8000/tickets/{t['id']}/estado",
                                    headers=HEADERS,
                                    json={"estado": nuevo_estado, "nota": nota_estado},
                                    timeout=5)
                                st.success("Estado actualizado")
                                st.rerun()
                            except Exception as ex:
                                st.error(f"Error: {ex}")
                        st.markdown("---")
                        ticket_id = t['id']
                        nota_counter = st.session_state.get(f"nota_counter_{ticket_id}", 0)
                        nota_key = f"nueva_nota_{ticket_id}_{nota_counter}"
                        nueva_nota = st.text_area("Anadir nota", key=nota_key,
                                                   placeholder="Escribe una nota...",
                                                   height=80)
                        if st.button("Guardar nota", key=f"btn_nota_{t['id']}",
                                     use_container_width=True, type="secondary"):
                            if nueva_nota:
                                try:
                                    requests.post(
                                        f"http://localhost:8000/tickets/{t['id']}/nota",
                                        headers=HEADERS,
                                        json={"nota": nueva_nota},
                                        timeout=5)
                                    st.success("Nota guardada")
                                    st.session_state[f"nota_counter_{t['id']}"] = st.session_state.get(f"nota_counter_{t['id']}", 0) + 1
                                    st.rerun()
                                except Exception as ex:
                                    st.error(f"Error: {ex}")

    # ── TAB 2: Nuevo ticket manual ─────────────────────────────────────────
    with tab2:
        st.markdown("### Crear Ticket Manual")
        col1, col2 = st.columns(2)
        with col1:
            titulo = st.text_input("Titulo del incidente", placeholder="Ej: SSH Brute Force detectado")
            ip_ticket = st.text_input("IP origen", placeholder="Ej: 47.80.59.241")
            fase = st.selectbox("Fase MITRE", [
                "initial_access", "execution", "persistence",
                "privilege_escalation", "defense_evasion", "credential_access",
                "discovery", "lateral_movement", "collection", "exfiltration", "unknown"
            ])
        with col2:
            prioridad = st.selectbox("Prioridad", ["CRITICA", "ALTA", "MEDIA", "BAJA"], index=1)
            descripcion = st.text_area("Descripcion", placeholder="Describe el incidente...",
                                        height=120)

        if st.button("Crear Ticket", type="primary", key="btn_crear_ticket"):
            if titulo and descripcion:
                try:
                    abuse = consultar_abuseipdb(ip_ticket) if ip_ticket else {}
                    r = requests.post("http://localhost:8000/tickets",
                        headers=HEADERS,
                        json={
                            "titulo":      titulo,
                            "descripcion": descripcion,
                            "ip":          ip_ticket,
                            "fase_mitre":  fase,
                            "prioridad":   prioridad,
                            "origen":      "manual",
                            "abuse_score": abuse.get("score", 0),
                            "abuse_pais":  abuse.get("pais", ""),
                            "abuse_isp":   abuse.get("isp", ""),
                            "narrativa": (
                                f"El motor LSTM detectó actividad maliciosa en fase {fase.upper()} "
                                f"desde la IP {ip} ({abuse_isp}, {abuse_pais}) "
                                f"con una confianza del {confianza}% y nivel de riesgo {nivel_riesgo}. "
                                f"La reputación AbuseIPDB confirma actividad maliciosa con un score del {abuse_score_detector}%. "
                                f"El sistema activó automáticamente el Playbook IP Maliciosa: "
                                f"la IP fue bloqueada en el firewall Hetzner Cloud "
                                f"sin intervención del analista."
                            ),                            
                        }, timeout=5)
                    nuevo = r.json()
                    st.success(f"Ticket {nuevo['id']} creado correctamente — ve a la pestaña 'Tickets' para verlo")
                    st.session_state.ticket_creado = nuevo['id']
                except Exception as ex:
                    st.error(f"Error: {ex}")
            else:
                st.warning("Titulo y descripcion son obligatorios")

# ── TAB 3: Metricas ────────────────────────────────────────────────────
    with tab3:
        st.markdown("### Metricas de Gestion de Incidentes")
        if not metricas or metricas.get("total", 0) == 0:
            st.info("No hay tickets suficientes para generar metricas.")
        else:
            # SLA fuera de columnas
            sla = metricas.get("sla_24h_pct", 0)
            color_sla = "#3fb950" if sla >= 80 else "#d29922" if sla >= 50 else "#f85149"
            st.markdown(f"""
            <div class="metric-card" style="border-top:3px solid {color_sla};">
                <p class="metric-label">SLA — Resueltos en menos de 24h</p>
                <p class="metric-value" style="color:{color_sla}">{sla}%</p>
            </div>""", unsafe_allow_html=True)

            col1, col2 = st.columns(2)
            with col1:
                if metricas.get("por_prioridad"):
                    st.markdown('<div class="section-header">Tickets por Prioridad</div>',
                               unsafe_allow_html=True)
                    df_prio = pd.DataFrame(list(metricas["por_prioridad"].items()),
                                          columns=["Prioridad", "Tickets"])
                    colores_prio = {"CRITICA": "#f85149", "ALTA": "#d29922",
                                   "MEDIA": "#388bfd", "BAJA": "#3fb950"}
                    fig = px.pie(df_prio, values="Tickets", names="Prioridad",
                                hole=0.6,
                                color="Prioridad",
                                color_discrete_map=colores_prio)
                    fig.update_traces(
                        textposition="inside",
                        textinfo="label+percent",
                        textfont=dict(color="#ffffff", size=10),
                        marker=dict(line=dict(color="#0d1117", width=2))
                    )
                    fig.update_layout(
                        plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                        margin=dict(l=30,r=30,t=30,b=30), height=280,
                        showlegend=True,
                        legend=dict(
                            font=dict(color="#c9d1d9", size=11),
                            bgcolor="rgba(0,0,0,0)",
                            orientation="h",
                            yanchor="bottom", y=-0.2,
                            xanchor="center", x=0.5
                        ),
                        annotations=[dict(
                            text=f"<b>{df_prio['Tickets'].sum()}</b><br>tickets",
                            x=0.5, y=0.5, font=dict(size=16, color="#e6edf3"),
                            showarrow=False
                        )]
                    )
                    st.plotly_chart(fig, use_container_width=True)

            with col2:
                if metricas.get("por_fase"):
                    st.markdown('<div class="section-header">Tickets por Fase MITRE</div>',
                               unsafe_allow_html=True)
                    df_fase = pd.DataFrame(list(metricas["por_fase"].items()),
                                          columns=["Fase", "Tickets"])
                    df_fase = df_fase.sort_values("Tickets", ascending=True)
                    df_fase["Fase"] = df_fase["Fase"].str.replace("_", " ").str.upper()
                    fig2 = go.Figure(go.Bar(
                        x=df_fase["Tickets"],
                        y=df_fase["Fase"],
                        orientation="h",
                        marker=dict(
                            color=df_fase["Tickets"],
                            colorscale=[[0, "#1f6feb"], [1, "#79c0ff"]],
                            line=dict(color="#0d1117", width=1)
                        ),
                        text=df_fase["Tickets"],
                        textposition="outside",
                        textfont=dict(color="#c9d1d9", size=12),
                    ))
                    fig2.update_layout(
                        plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                        margin=dict(l=0,r=40,t=10,b=10), height=280,
                        xaxis=dict(showgrid=True, gridcolor="#21262d",
                                  color="#8b949e", showticklabels=False),
                        yaxis=dict(color="#c9d1d9", tickfont=dict(size=11)),
                    )
                    st.plotly_chart(fig2, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TRAFICO DE RED — SURICATA IDS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "Tráfico de Red":
    st.markdown("## Tráfico de Red — Suricata IDS")
    st.markdown("Monitorización de tráfico de red en tiempo real mediante Suricata 7.0.3 con 52.534 reglas activas.")
    st.markdown("---")

    datos_suricata = cargar_suricata()
    from collections import Counter
    alertas_sur = datos_suricata.get("alertas", [])
    flows_sur   = datos_suricata.get("flows", [])

    # ── Métricas globales ──────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    ips_atacantes = [a["src_ip"] for a in alertas_sur if a["src_ip"] and not es_ip_whitelist(a["src_ip"])]    
    with col1:
        n = len(alertas_sur)
        color = "#f85149" if n > 0 else "#8b949e"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Alertas de Red</p>
            <p class="metric-value" style="color:{color}">{n}</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        n = len(set(ips_atacantes))
        color = "#d29922" if n > 0 else "#8b949e"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">IPs Atacantes Unicas</p>
            <p class="metric-value" style="color:{color}">{n}</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        n = len(flows_sur)
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid #388bfd;">
            <p class="metric-label">Flujos Monitorizados</p>
            <p class="metric-value" style="color:#388bfd">{n}</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        criticas = len([a for a in alertas_sur if a["severidad"] == 1])
        color = "#f85149" if criticas > 0 else "#3fb950"
        st.markdown(f"""
        <div class="metric-card" style="border-top:3px solid {color};">
            <p class="metric-label">Alertas Criticas</p>
            <p class="metric-value" style="color:{color}">{criticas}</p>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    if alertas_sur:
        from collections import Counter

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-header">Top IPs Atacantes</div>', unsafe_allow_html=True)
            top_ips = Counter(ips_atacantes).most_common(10)
            if top_ips:
                df_ips = pd.DataFrame(top_ips, columns=["IP", "Alertas"])
                fig = px.bar(df_ips, x="Alertas", y="IP", orientation="h",
                            color="Alertas", color_continuous_scale=["#1f6feb", "#f85149"])
                fig.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                                 margin=dict(l=0,r=0,t=10,b=0), height=320,
                                 showlegend=False, coloraxis_showscale=False)
                fig.update_xaxes(color="#8b949e", gridcolor="#21262d")
                fig.update_yaxes(color="#c9d1d9")
                st.plotly_chart(fig, use_container_width=True)
            else: 
                st.info("No hay IPs atacantes activas actualmente.")

        with col2:
            st.markdown('<div class="section-header">Top Firmas Detectadas</div>', unsafe_allow_html=True)
            firmas = [a["firma"] for a in alertas_sur if a["firma"]]
            top_firmas = Counter(firmas).most_common(8)
            if top_firmas:
                df_firmas = pd.DataFrame(top_firmas, columns=["Firma", "Count"])
                df_firmas["Firma"] = df_firmas["Firma"].str[:40]
                fig2 = px.bar(df_firmas, x="Count", y="Firma", orientation="h",
                             color="Count", color_continuous_scale=["#0d2d6b", "#388bfd"])
                fig2.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                                  margin=dict(l=0,r=0,t=10,b=0), height=320,
                                  showlegend=False, coloraxis_showscale=False)
                fig2.update_xaxes(color="#8b949e", gridcolor="#21262d")
                fig2.update_yaxes(color="#c9d1d9")
                st.plotly_chart(fig2, use_container_width=True)

        col3, col4 = st.columns(2)
        with col3:
            st.markdown('<div class="section-header">Puertos mas Atacados</div>', unsafe_allow_html=True)
            puertos = [a["dest_port"] for a in alertas_sur if a["dest_port"]]
            top_puertos = Counter(puertos).most_common(8)
            if top_puertos:
                df_puertos = pd.DataFrame(top_puertos, columns=["Puerto", "Ataques"])
                df_puertos["Puerto"] = df_puertos["Puerto"].astype(str)
                servicios_conocidos = {
                    "22": "22 — SSH", "80": "80 — HTTP", "443": "443 — HTTPS",
                    "3389": "3389 — RDP", "8080": "8080 — HTTP-Alt",
                    "21": "21 — FTP", "25": "25 — SMTP", "3306": "3306 — MySQL",
                    "5432": "5432 — PostgreSQL", "6379": "6379 — Redis",
                    "8443": "8443 — HTTPS-Alt", "23": "23 — Telnet"
                }
                df_puertos["Puerto"] = df_puertos["Puerto"].map(
                    lambda x: servicios_conocidos.get(x, x))
                fig3 = px.pie(df_puertos, values="Ataques", names="Puerto",
                             hole=0.5,
                             color_discrete_sequence=["#388bfd","#1f6feb","#79c0ff",
                                                       "#f85149","#d29922","#3fb950",
                                                       "#8b949e","#58a6ff"])
                fig3.update_traces(
                    textposition="outside",
                    textinfo="label+percent",
                    textfont=dict(color="#c9d1d9", size=10),
                    marker=dict(line=dict(color="#0d1117", width=2))
                )
                fig3.update_layout(
                    plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                    margin=dict(l=10,r=10,t=10,b=10), height=320,
                    showlegend=False,
                    annotations=[dict(
                        text="<b>Puertos</b>",
                        x=0.5, y=0.5, font=dict(size=13, color="#e6edf3"),
                        showarrow=False
                    )]
                )
                st.plotly_chart(fig3, use_container_width=True)

        with col4:
            st.markdown('<div class="section-header">Actividad por Hora</div>', unsafe_allow_html=True)
            df_time = pd.DataFrame(alertas_sur)
            df_time["hora"] = pd.to_datetime(df_time["timestamp"]).dt.hour
            timeline = df_time.groupby("hora").size().reset_index(name="Alertas")
            timeline.columns = ["Hora", "Alertas"]
            # Mostrar solo el rango de horas con datos reales
            hora_min = int(timeline["Hora"].min())
            hora_max = int(timeline["Hora"].max())
            todas_horas = pd.DataFrame({"Hora": range(hora_min, hora_max + 1)})
            timeline = todas_horas.merge(timeline, on="Hora", how="left").fillna(0)
            timeline["Hora"] = timeline["Hora"].astype(int).astype(str).str.zfill(2) + ":00"
            fig4 = px.bar(timeline, x="Hora", y="Alertas",
                         color="Alertas",
                         color_continuous_scale=["#0d2d6b", "#388bfd", "#79c0ff"])
            fig4.update_layout(
                plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
                margin=dict(l=0,r=0,t=10,b=0), height=320,
                showlegend=False, coloraxis_showscale=False,
                xaxis_title="", yaxis_title="Alertas",
            )
            fig4.update_xaxes(color="#8b949e", tickangle=45)
            fig4.update_yaxes(color="#8b949e", gridcolor="#21262d")
            st.plotly_chart(fig4, use_container_width=True)

        st.markdown('<div class="section-header">Ultimas Alertas de Red</div>', unsafe_allow_html=True)
        df_alertas = pd.DataFrame(alertas_sur[-50:])
        df_alertas["timestamp"] = pd.to_datetime(df_alertas["timestamp"]).dt.strftime("%d/%m %H:%M:%S")
        df_alertas = df_alertas[["timestamp","src_ip","dest_port","proto","firma","severidad"]].copy()
        df_alertas.columns = ["Timestamp","IP Origen","Puerto Destino","Protocolo","Firma","Severidad"]
        df_alertas = df_alertas.sort_values("Timestamp", ascending=False)
        
        # Pivoting — investigar IP directamente
        st.markdown("**Investigar IP desde la tabla:**")
        ips_tabla = list(set(df_alertas["IP Origen"].dropna().tolist() + list(set(ips_atacantes))))
        ips_tabla = [ip for ip in ips_tabla if ip and not es_ip_whitelist(ip)]
        ips_tabla.sort()
        col_piv1, col_piv2 = st.columns([3, 1])
        with col_piv1:
            ip_pivot = st.selectbox("Selecciona IP", ips_tabla, key="ip_pivot_trafico")
        with col_piv2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Investigar en Forense", key="btn_pivot_trafico", type="primary", use_container_width=True):
                st.session_state.pagina = "Análisis Forense"
                st.session_state.ip_forense_pivot = ip_pivot
                st.rerun()
        
        tabla_oscura(df_alertas)
        
    else:
        st.info("Suricata activo — esperando alertas de red. Los datos aparecerán en cuanto se detecte tráfico sospechoso.")


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
                <strong>Noctua Predictive</strong> es una plataforma SOC autónoma de código abierto 
                para la detección de Amenazas Persistentes Avanzadas (APT) desplegada en producción real. 
                Integra un motor LSTM bidireccional con atención entrenado con el dataset CSE-CIC-IDS2018, 
                Federated Learning con FedAvg para aprendizaje colaborativo preservando la privacidad, 
                y XAI basado en SHAP para la auditabilidad de decisiones conforme al EU AI Act 2024.
                <br><br>
                El sistema captura tráfico de red en tiempo real mediante Suricata IDS (52.534 reglas activas) 
                integrado con el SIEM Wazuh, resolviendo el feature mismatch entre el dominio de entrenamiento 
                (CICIDS2018) y el entorno de producción. Las alertas de Suricata alimentan directamente el motor 
                LSTM con features de red reales equivalentes a las del dataset de entrenamiento.
                <br><br>
                La plataforma incluye un agente EDR propio para endpoints Windows que reporta telemetría 
                de seguridad en tiempo real (puertos, procesos, actualizaciones) con capacidad de respuesta 
                bidireccional — el analista puede matar procesos o bloquear IPs directamente desde el dashboard. 
                Adicionalmente, el agente Wazuh oficial instalado en el endpoint Windows permite la correlación 
                de eventos entre el servidor Linux y el endpoint para detección de movimiento lateral real.
                <br><br>
                Desplegado en un VPS Hetzner CPX32 expuesto a internet real, el sistema ha procesado más de 
                129.000 alertas de Wazuh y detectado miles de alertas de red con Suricata, demostrando su 
                viabilidad en producción real — algo ausente en la práctica totalidad de trabajos académicos 
                similares publicados en IEEE Xplore y ACM Digital Library.
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
        {"Componente": "Wazuh SIEM", "Capa": "Detección", "Descripcion": "SIEM/XDR open source de nivel enterprise. Monitoriza eventos de red, sistema y endpoints en tiempo real.", "Tecnologia": "Python / C"},
        {"Componente": "Ollama / phi3", "Capa": "Analisis autonomo", "Descripcion": "LLM local para clasificacion autonoma de alertas individuales sin dependencia de servicios externos.", "Tecnologia": "LLM 3.8B"},
        {"Componente": "LSTM Bidireccional", "Capa": "Prediccion APT", "Descripcion": "Modelo de series temporales que detecta campañas APT completas analizando secuencias de 6h, 24h y 7 dias.", "Tecnologia": "PyTorch"},
        {"Componente": "Federated Learning", "Capa": "Aprendizaje colaborativo", "Descripcion": "Entrena el modelo LSTM entre multiples nodos sin compartir datos. Cada organizacion mantiene su privacidad.", "Tecnologia": "Flower / FedAvg"},
        {"Componente": "Detector Lateral", "Capa": "Correlacion", "Descripcion": "Correlaciona eventos entre agentes para detectar movimiento lateral entre sistemas de la red.", "Tecnologia": "Python"},
        {"Componente": "XAI / SHAP", "Capa": "Explicabilidad", "Descripcion": "Genera explicaciones auditables de cada decision del modelo. Cumple el Reglamento Europeo de IA.", "Tecnologia": "SHAP"},
        {"Componente": "FastAPI", "Capa": "Orquestacion", "Descripcion": "API REST que coordina todos los modulos con autenticacion, rate limiting y validacion de inputs.", "Tecnologia": "Python"},
        {"Componente": "AbuseIPDB", "Capa": "Threat Intelligence", "Descripcion": "Enriquece cada IP bloqueada con informacion de reputacion global — puntuacion de abuso, pais, ISP y si es nodo TOR.", "Tecnologia": "REST API"},
        {"Componente": "Fail2ban", "Capa": "Defensa perimetral", "Descripcion": "Bloquea automaticamente IPs con multiples intentos de login fallidos. Primera linea de defensa complementaria a Noctua.", "Tecnologia": "Python"},
        {"Componente": "CICIDS2018", "Capa": "Entrenamiento", "Descripcion": "Dataset estandar CSE-CIC-IDS2018 de la Universidad de New Brunswick con 15 tipos de ataque reales. Usado para entrenar el modelo LSTM con F1=1.0. Referencia: Sharafaldin et al., ICISSP 2018.", "Tecnologia": "CSV / AWS S3"},
        {"Componente": "Hetzner API", "Capa": "Respuesta", "Descripcion": "Ejecuta bloqueos automaticos en el firewall cloud cuando se detecta una amenaza confirmada.", "Tecnologia": "REST API"},
        {"Componente": "Suricata IDS", "Capa": "Deteccion de red", "Descripcion": "Motor de analisis de trafico de red en tiempo real con 52.534 reglas activas. Captura metricas de flujo equivalentes a CICIDS2018 que alimentan el motor LSTM, resolviendo el feature mismatch entre entrenamiento y produccion.", "Tecnologia": "Suricata 7.0.3"},
        {"Componente": "Agente Wazuh Windows", "Capa": "Monitorizacion endpoint", "Descripcion": "Agente Wazuh oficial instalado en WORKSTATION-ALEJANDRA. Permite correlacion de eventos entre servidor Linux y endpoint Windows para deteccion de movimiento lateral real.", "Tecnologia": "Wazuh 4.11.2"},
        {"Componente": "Agente PowerShell", "Capa": "Monitorizacion endpoint", "Descripcion": "Agente propio desarrollado en PowerShell que reporta a FastAPI el estado de seguridad del endpoint Windows: actualizaciones pendientes, puertos en escucha, procesos sospechosos y puntuacion de seguridad.", "Tecnologia": "PowerShell"},
    ]    
    
    for comp in componentes:
        with st.expander(f"{comp['Componente']} — {comp['Capa']}"):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"<p style='color:#c9d1d9;font-size:0.9rem'>{comp['Descripcion']}</p>", unsafe_allow_html=True)
            with col2:
                st.markdown(f"<span style='background:#161b22;padding:4px 8px;border-radius:4px;font-size:0.8rem;color:#1a3a6c;font-weight:600'>{comp['Tecnologia']}</span>", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown('<div class="section-header">Framework MITRE ATT&CK — Fases Detectadas</div>', unsafe_allow_html=True)
    fases = [
        {"Fase": "Reconocimiento", "Tecnica MITRE": "T1595, T1596", "Descripcion": "Recopilacion de informacion sobre el objetivo antes del ataque"},
        {"Fase": "Acceso Inicial", "Tecnica MITRE": "T1190, T1078", "Descripcion": "Primera entrada no autorizada al sistema objetivo"},
        {"Fase": "Persistencia", "Tecnica MITRE": "T1053, T1547", "Descripcion": "Mecanismos para mantener el acceso tras reinicios"},
        {"Fase": "Movimiento Lateral", "Tecnica MITRE": "T1021, T1550", "Descripcion": "Desplazamiento entre sistemas buscando activos de valor"},
        {"Fase": "Exfiltracion", "Tecnica MITRE": "T1041, T1048", "Descripcion": "Extraccion de datos sensibles del entorno comprometido"},
    ]
    tabla_oscura(pd.DataFrame(fases), use_container_width=True, hide_index=True)
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
        tabla_oscura(pd.DataFrame(refs), use_container_width=True, hide_index=True)