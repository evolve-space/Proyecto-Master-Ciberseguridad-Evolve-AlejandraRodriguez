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
    <div style="overflow-x:auto;border-radius:8px;border:1px solid #21262d;margin-bottom:16px;">
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


@st.cache_data(ttl=30)
def cargar_alertas_wazuh():
    try:
        result = subprocess.run(
            ["bash", "-c", "find /var/ossec/logs/alerts/2026/Aug -name '*.json.gz' -exec zcat {} \\; 2>/dev/null; find /var/ossec/logs/alerts/2026/Jul -name '*.json.gz' -exec zcat {} \\; 2>/dev/null; cat /var/ossec/logs/alerts/alerts.json 2>/dev/null"],
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

df = cargar_alertas_wazuh()
ips_bloqueadas = cargar_ips_hetzner()

with st.sidebar:
    with open("/root/asoar/static/noctua_logo.svg", "r") as f:
        logo_svg = f.read()
    st.markdown(logo_svg, unsafe_allow_html=True)
    st.markdown("---")
    opciones = [
        "Panel General", "Alertas y Eventos", "IPs Bloqueadas",
        "Endpoints", "Normativas", "Detección APT",
        "Simulador de Ataques", "Informes", "Estado del Sistema", "Análisis Forense", "Gestión de Incidentes", "About"
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
                st.session_state.pagina = "Deteccóon APT"; st.rerun()
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
        tabla_oscura(df_show, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# IPs BLOQUEADAS
# ══════════════════════════════════════════════════════════════════════════════
elif pagina == "IPs Bloqueadas":
    st.markdown("## IPs Bloqueadas en Hetzner Firewall")
    st.markdown("---")
    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(f'<div class="metric-card danger"><p class="metric-label">IPs Bloqueadas Activas</p><p class="metric-value">{len(ips_bloqueadas)}</p></div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">IPs Bloqueadas — Noctua Predictive</div>', unsafe_allow_html=True)
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
            rows.append({
                "IP":        ip,
                "Reputacion": str(score) + "%",
                "Pais":      abuse.get("pais", "—"),
                "ISP":       abuse.get("isp", "—"),
                "Reportes":  str(abuse.get("reportes", 0)),
                "TOR":       "Si" if abuse.get("es_tor") else "No"
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
        if "desbloqueada_en" in df_hist.columns:
            df_hist["desbloqueada_en"] = pd.to_datetime(df_hist["desbloqueada_en"], errors="coerce").dt.strftime("%d/%m/%Y %H:%M")
        df_hist.columns = [c.replace("_", " ").title() for c in df_hist.columns]
        tabla_oscura(df_hist, use_container_width=True, hide_index=True)
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

    servicios = {
        "ASOAR API (FastAPI)":  check_service("http://localhost:8000/apt/estado"),
        "Ollama / phi3":        check_service("http://localhost:11434/api/tags"),
        "Wazuh Manager":        True,
        "Wazuh Dashboard":      True,
        "Hetzner Firewall":     len(ips_bloqueadas) >= 0,
        "Fail2ban":             check_fail2ban(),
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
        "Componente":  ["Wazuh SIEM", "FastAPI", "Ollama phi3", "LSTM PyTorch", "Federated Learning", "XAI SHAP", "Detector Lateral", "Reentrenamiento", "AbuseIPDB", "Fail2ban", "CICIDS2018", "Hetzner API", "Streamlit"],
        "Capa":        ["Deteccion", "Orquestacion", "Analisis IA", "Prediccion APT", "Aprendizaje FL", "Explicabilidad", "Correlacion", "Mejora continua", "Threat Intelligence", "Defensa perimetral", "Entrenamiento", "Respuesta", "Visualizacion"],
        "Estado":      [
            "Activo" if servicios["Wazuh Manager"] else "Inactivo",
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
        mfa_toggle = st.toggle("", value=activo_mfa, key="toggle_mfa")
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
                        tabla_oscura(pd.DataFrame({"Puerto": [str(p) for p in puertos]}), use_container_width=True, hide_index=True)
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
            with st.expander(f"Software instalado ({len(seg.get('software_instalado', []))})"):
                software = seg.get("software_instalado", [])
                if software:
                    df_sw = pd.DataFrame(software)
                    if not df_sw.empty:
                        df_sw = df_sw.rename(columns={"nombre": "Nombre", "version": "Version", "publisher": "Publisher", "fecha_instalacion": "Fecha instalacion"})
                        df_sw["Fecha instalacion"] = pd.to_datetime(df_sw["Fecha instalacion"], format="%Y%m%d", errors="coerce").dt.strftime("%d/%m/%Y")
                        tabla_oscura(df_sw, use_container_width=True, hide_index=True)
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
            "Informe de Detección APT"
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

        if "Fase Mitre" in df_apt.columns:
            st.markdown('<div class="section-header">Distribucion de Fases APT</div>', unsafe_allow_html=True)
            conteo = df_apt["Fase Mitre"].value_counts().reset_index()
            conteo.columns = ["Fase", "Count"]
            fig = px.bar(conteo, x="Fase", y="Count", color="Count", color_continuous_scale="Reds")
            fig.update_layout(plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
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
                plot_bgcolor="#0d1117", paper_bgcolor="#0d1117",
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
                html_prog = '<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:12px;background:#161b22;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.4);">'
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
        for exp in explicaciones[-3:]:
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
        ip_forense = st.text_input("IP a investigar", placeholder="Ej: 185.220.101.45")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        buscar = st.button("Investigar IP", type="primary", use_container_width=True)

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
            tabla_oscura(df_ip, use_container_width=True, hide_index=True)
            st.markdown(f"**{len(df_ip)} eventos detectados por Wazuh**")
        else:
            st.info("No se encontraron eventos Wazuh para esta IP.")

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
            st.markdown(f"**ISP:** {abuse.get('isp','—')}")
        else:
            st.info("No se pudo obtener información de AbuseIPDB para esta IP.")

        # ── 5. Timeline forense ────────────────────────────────────────────
        st.markdown('<div class="section-header">Timeline Forense del Incidente</div>', unsafe_allow_html=True)
        eventos_timeline = []

        if not df_ip.empty:
            for _, row in df[df["ip"] == ip_forense].iterrows():
                eventos_timeline.append({
                    "timestamp": row["timestamp"],
                    "tipo":      "Wazuh",
                    "descripcion": row["tipo"],
                    "nivel":     row["nivel"],
                    "color":     "#e74c3c" if row["nivel"] >= 12 else "#f39c12" if row["nivel"] >= 10 else "#2980b9"
                })

        if eventos_timeline:
            eventos_timeline.sort(key=lambda x: x["timestamp"])
            for ev in eventos_timeline:
                ts = ev["timestamp"].strftime("%d/%m/%Y %H:%M:%S") if hasattr(ev["timestamp"], "strftime") else str(ev["timestamp"])
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f0f0f0;">
                    <span style="background:{ev['color']};color:white;padding:2px 8px;
                                border-radius:4px;font-size:0.75rem;font-weight:600;min-width:60px;text-align:center">
                        N{ev['nivel']}
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

    col1, col2, col3, col4, col5 = st.columns(5)
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
            filtro_estado = st.selectbox("Estado", ["Todos", "Abierto", "Investigando",
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
                        nueva_nota = st.text_area("Anadir nota", key=f"nueva_nota_{t['id']}",
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
                        }, timeout=5)
                    nuevo = r.json()
                    st.success(f"Ticket {nuevo['id']} creado correctamente")
                    st.rerun()
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
                <strong>Noctua Predictive</strong> es un SOC autonomo de detección, analisis
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
                combina LSTM, Federated Learning, SIEM real y XAI para detección de APTs,
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