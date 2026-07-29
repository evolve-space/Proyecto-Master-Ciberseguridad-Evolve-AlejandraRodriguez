from fastapi import FastAPI, Request, Depends, HTTPException, status, Security
from fastapi.responses import FileResponse
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, validator
from typing import Optional
import requests
import numpy as np
import json
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()

# Importar detector APT
try:
    from apt_detector import detector_apt
    APT_DISPONIBLE = True
except Exception as e:
    print(f"[WARN] Detector APT no disponible: {e}")
    APT_DISPONIBLE = False

# Importar explicador XAI
try:
    from apt_xai import obtener_explicador
    XAI_DISPONIBLE = True
except Exception as e:
    print(f"[WARN] XAI no disponible: {e}")
    XAI_DISPONIBLE = False

# Detector de movimiento lateral — correlaciona eventos entre agentes para
# identificar cuando un atacante se desplaza entre sistemas de la red
try:
    from apt_lateral import detector_lateral
    LATERAL_DISPONIBLE = True
except Exception as e:
    print(f"[WARN] Detector lateral no disponible: {e}")
    LATERAL_DISPONIBLE = False



# ── API Key ────────────────────────────────────────────────────────────────────
HETZNER_TOKEN = os.getenv("HETZNER_TOKEN")
HETZNER_FIREWALL_ID = os.getenv("HETZNER_FIREWALL_ID")
API_KEY = os.getenv("API_KEY")

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verificar_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key invalida o no proporcionada"
        )
    return api_key

# ── Rate Limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Modelos Pydantic ───────────────────────────────────────────────────────────
class AlertaWazuh(BaseModel):
    rule: dict
    data: Optional[dict] = {}

    @validator('rule')
    def validar_rule(cls, v):
        if 'level' not in v:
            raise ValueError('El campo level es obligatorio')
        if not isinstance(v['level'], (int, float)):
            raise ValueError('El nivel debe ser un numero')
        if v['level'] < 0 or v['level'] > 15:
            raise ValueError('El nivel debe estar entre 0 y 15')
        return v

class DatosAgente(BaseModel):
    hostname: str
    ip: Optional[str] = "N/A"
    os: Optional[str] = "N/A"
    usuario: Optional[str] = "N/A"
    timestamp: Optional[str] = ""
    seguridad: Optional[dict] = {}
    rendimiento: Optional[dict] = {}
    puntuacion_seguridad: Optional[int] = 0

    @validator('hostname')
    def validar_hostname(cls, v):
        if len(v) > 50:
            raise ValueError('Hostname demasiado largo')
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Hostname contiene caracteres no permitidos')
        return v

    @validator('puntuacion_seguridad')
    def validar_puntuacion(cls, v):
        if v < 0 or v > 100:
            raise ValueError('Puntuacion debe estar entre 0 y 100')
        return v

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Noctua ASOAR", version="1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Variables ──────────────────────────────────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/api/generate"
AGENTES_FILE = "/root/asoar/agentes.json"

# ── Funciones auxiliares ───────────────────────────────────────────────────────
def preguntar_ollama(alerta: dict) -> str:
    prompt = f"""
    Eres un experto en ciberseguridad. Analiza esta alerta de Wazuh y responde SOLO con 'BLOQUEAR' o 'IGNORAR'.
    Alerta: {json.dumps(alerta, indent=2)}
    Responde únicamente con BLOQUEAR si es un ataque real, o IGNORAR si es falso positivo.
    """
    response = requests.post(OLLAMA_URL, json={
        "model": "phi3",
        "prompt": prompt,
        "stream": False
    })
    return response.json().get("response", "IGNORAR").strip()

def bloquear_ip_hetzner(ip: str):
    headers = {
        "Authorization": f"Bearer {HETZNER_TOKEN}",
        "Content-Type": "application/json"
    }
    r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers)
    reglas_actuales = r.json().get("firewall", {}).get("rules", [])
    nueva_regla = {
        "direction": "in",
        "protocol": "tcp",
        "source_ips": [f"{ip}/32"],
        "port": "any",
        "description": f"ASOAR-blocked-{ip}"
    }
    reglas_actuales.append(nueva_regla)
    r = requests.post(
        f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}/actions/set_rules",
        headers=headers,
        json={"rules": reglas_actuales}
    )
    print(f"[HETZNER] IP {ip} bloqueada - Status: {r.status_code}")

     # Guardar histórico
    historico_file = "/root/asoar/historico_ips.json"
    historico = []
    if os.path.exists(historico_file):
        try:
            with open(historico_file, "r") as f:
                historico = json.load(f)
        except:
            historico = []

    historico.append({
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "accion": "BLOQUEADA"
    })

    with open(historico_file, "w") as f:
        json.dump(historico, f, indent=2)



    # Guardar notificación pendiente
    notif_file = "/root/asoar/notificaciones.json"
    notifs = []
    if os.path.exists(notif_file):
        try:
            with open(notif_file, "r") as f:
                notifs = json.load(f)
        except:
            notifs = []

    notifs.append({
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "leida": False
    })

    with open(notif_file, "w") as f:
        json.dump(notifs, f, indent=2)
    return r.status_code == 201

def cargar_agentes():
    if os.path.exists(AGENTES_FILE):
        try:
            with open(AGENTES_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {}

def guardar_agentes(agentes: dict):
    with open(AGENTES_FILE, "w") as f:
        json.dump(agentes, f, indent=2, default=str)

# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.post("/alerta")
@limiter.limit("10/minute")
async def recibir_alerta(request: Request, alerta: AlertaWazuh, api_key: str = Depends(verificar_api_key)):
    ip_atacante = alerta.data.get("srcip", "desconocida")
    nivel = alerta.rule.get("level", 0)
    descripcion = alerta.rule.get("description", "")
    print(f"[ALERTA] Nivel {nivel} - {descripcion} - IP: {ip_atacante}")

    # Analisis APT con LSTM — siempre antes de cualquier return
    apt_resultado = {}
    if APT_DISPONIBLE:
        try:
            apt_resultado = detector_apt.procesar_alerta({
                "rule_id": str(alerta.rule.get("id", "0")),
                "nivel":   nivel,
                "ip":      ip_atacante,
                "agente":  "master",
            })
        except Exception as e:
            print(f"[APT] Error en detector: {e}")
    
    # Explicacion XAI si hay deteccion APT activa
    xai_resultado = {}
    if XAI_DISPONIBLE and apt_resultado.get("apt_activo"):
        try:
            explicador = obtener_explicador()
            if explicador:
                ventana = np.array(list(detector_apt.buffer), dtype=np.float32)
                if len(ventana) < 32:
                    pad = np.zeros((32 - len(ventana), 9), dtype=np.float32)
                    ventana = np.vstack([pad, ventana])
                xai_resultado = explicador.explicar_ventana(
                    ventana=ventana,
                    fase_predicha=apt_resultado.get("fase_mitre", "unknown"),
                    confianza=apt_resultado.get("confianza", 0),
                    contexto={"ip": ip_atacante, "agente": "master"}
                )
        except Exception as e:
            print(f"[XAI] Error: {e}")

    # Deteccion de movimiento lateral
    lateral_resultado = {}
    if LATERAL_DISPONIBLE:
        try:
            lateral_resultado = detector_lateral.registrar_evento({
                "ip":      ip_atacante,
                "agente":  "master",
                "rule_id": str(alerta.rule.get("id", "0")),
                "nivel":   nivel,
            })
        except Exception as e:
            print(f"[LATERAL] Error: {e}")

    if nivel >= 10:
        decision = preguntar_ollama(alerta.dict())
        print(f"[OLLAMA] Decision: {decision}")
        if "BLOQUEAR" in decision and ip_atacante != "desconocida":
            bloquear_ip_hetzner(ip_atacante)
            return {"accion": "BLOQUEADA", "ip": ip_atacante, "decision": decision, "apt": apt_resultado, "xai": xai_resultado, "lateral": lateral_resultado}

    return {"accion": "IGNORADA", "nivel": nivel, "descripcion": descripcion, "apt": apt_resultado, "xai": xai_resultado, "lateral": lateral_resultado}

@app.post("/agente")
@limiter.limit("20/minute")
async def recibir_datos_agente(request: Request, datos: DatosAgente, api_key: str = Depends(verificar_api_key)):
    print(f"[AGENTE] Datos recibidos de {datos.hostname} ({datos.ip})")
    agentes = cargar_agentes()
    agentes[datos.hostname] = {
        "ultima_conexion": datetime.now().isoformat(),
        "datos": datos.dict()
    }
    guardar_agentes(agentes)
    return {"status": "ok", "hostname": datos.hostname}

@app.get("/agentes")
@limiter.limit("30/minute")
async def listar_agentes(request: Request, api_key: str = Depends(verificar_api_key)):
    return cargar_agentes()

@app.get("/agente_asoar.ps1")
async def descargar_agente():
    return FileResponse("/root/asoar/agente_asoar.ps1",
                       media_type="text/plain",
                       filename="agente_asoar.ps1")

@app.get("/cumplimiento/{hostname}")
async def calcular_cumplimiento(hostname: str, api_key: str = Depends(verificar_api_key)):
    agentes = cargar_agentes()
    if hostname not in agentes:
        return {"error": f"Agente {hostname} no encontrado"}

    datos = agentes[hostname].get("datos", {})
    seg = datos.get("seguridad", {})

    defender = seg.get("defender_activo", False)
    firewall = seg.get("firewall_activo", False)
    actualizaciones_criticas = seg.get("actualizaciones_criticas", 1)
    actualizaciones_pendientes = seg.get("actualizaciones_pendientes", 1)
    usuarios_admin = seg.get("usuarios_admin", [])
    puertos = seg.get("puertos_escucha", [])

    iso27001 = [
        {"control": "A.8.7", "nombre": "Proteccion contra malware", "cumple": defender, "detalle": "Windows Defender activo" if defender else "Windows Defender inactivo"},
        {"control": "A.8.20", "nombre": "Seguridad en redes", "cumple": firewall, "detalle": "Firewall activo" if firewall else "Firewall inactivo"},
        {"control": "A.8.8", "nombre": "Gestion de vulnerabilidades tecnicas", "cumple": actualizaciones_criticas == 0, "detalle": f"{actualizaciones_criticas} actualizaciones criticas pendientes"},
        {"control": "A.5.15", "nombre": "Control de acceso", "cumple": len(usuarios_admin) <= 2, "detalle": f"{len(usuarios_admin)} administradores locales"},
        {"control": "A.8.21", "nombre": "Seguridad de servicios de red", "cumple": len(puertos) <= 20, "detalle": f"{len(puertos)} puertos en escucha"},
        {"control": "A.8.19", "nombre": "Gestion de software en sistemas", "cumple": actualizaciones_pendientes == 0, "detalle": f"{actualizaciones_pendientes} actualizaciones pendientes"}
    ]

    nis2 = [
        {"control": "Art.21.2.e", "nombre": "Seguridad en adquisicion y mantenimiento", "cumple": actualizaciones_criticas == 0, "detalle": f"{actualizaciones_criticas} actualizaciones criticas pendientes"},
        {"control": "Art.21.2.b", "nombre": "Gestion de incidentes", "cumple": defender, "detalle": "Proteccion antivirus activa" if defender else "Sin proteccion antivirus"},
        {"control": "Art.21.2.i", "nombre": "Control de accesos y gestion de activos", "cumple": len(usuarios_admin) <= 2, "detalle": f"{len(usuarios_admin)} administradores locales"},
        {"control": "Art.21.2.j", "nombre": "Uso de autenticacion y comunicaciones seguras", "cumple": firewall, "detalle": "Firewall activo" if firewall else "Firewall inactivo"}
    ]

    ens = [
        {"control": "op.exp.5", "nombre": "Gestion de cambios", "cumple": actualizaciones_pendientes == 0, "detalle": f"{actualizaciones_pendientes} actualizaciones pendientes"},
        {"control": "mp.sw.1", "nombre": "Desarrollo de aplicaciones", "cumple": actualizaciones_criticas == 0, "detalle": f"{actualizaciones_criticas} criticas pendientes"},
        {"control": "op.acc.4", "nombre": "Proceso de gestion de derechos de acceso", "cumple": len(usuarios_admin) <= 2, "detalle": f"{len(usuarios_admin)} administradores"},
        {"control": "op.exp.3", "nombre": "Gestion de la configuracion", "cumple": firewall and defender, "detalle": "Firewall y Defender activos" if firewall and defender else "Configuracion incompleta"},
        {"control": "mp.com.1", "nombre": "Perimetro seguro", "cumple": firewall, "detalle": "Firewall activo" if firewall else "Firewall inactivo"}
    ]

    def calcular_score(controles):
        if not controles:
            return 0
        return round(sum(1 for c in controles if c["cumple"]) / len(controles) * 100)

    return {
        "hostname": hostname,
        "iso27001": {"score": calcular_score(iso27001), "controles": iso27001},
        "nis2": {"score": calcular_score(nis2), "controles": nis2},
        "ens": {"score": calcular_score(ens), "controles": ens},
        "score_global": round((calcular_score(iso27001) + calcular_score(nis2) + calcular_score(ens)) / 3)
    }

@app.get("/historico")
async def obtener_historico(request: Request, api_key: str = Depends(verificar_api_key)):
    historico_file = "/root/asoar/historico_ips.json"
    if os.path.exists(historico_file):
        with open(historico_file, "r") as f:
            return json.load(f)
    return []

@app.delete("/desbloquear/{ip}")
async def desbloquear_ip(ip: str, api_key: str = Depends(verificar_api_key)):
    headers = {
        "Authorization": f"Bearer {HETZNER_TOKEN}",
        "Content-Type": "application/json"
    }
    r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers)
    reglas = r.json().get("firewall", {}).get("rules", [])
    reglas_filtradas = [reg for reg in reglas if f"ASOAR-blocked-{ip}" not in reg.get("description", "")]
    
    r = requests.post(
        f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}/actions/set_rules",
        headers=headers,
        json={"rules": reglas_filtradas}
    )
    
    # Actualizar histórico
    historico_file = "/root/asoar/historico_ips.json"
    if os.path.exists(historico_file):
        with open(historico_file, "r") as f:
            historico = json.load(f)
        for h in historico:
            if h["ip"] == ip:
                h["accion"] = "DESBLOQUEADA"
                h["desbloqueada_en"] = datetime.now().isoformat()
        with open(historico_file, "w") as f:
            json.dump(historico, f, indent=2)
    
    return {"status": "ok", "ip": ip, "accion": "DESBLOQUEADA"}

@app.get("/apt/campanas")
async def obtener_campanas_apt(request: Request, api_key: str = Depends(verificar_api_key)):
    if not APT_DISPONIBLE:
        return []
    return detector_apt.obtener_campanas(ultimas_n=50)

@app.get("/apt/estado")
async def obtener_estado_apt(request: Request, api_key: str = Depends(verificar_api_key)):
    if not APT_DISPONIBLE:
        return {"modelo_cargado": False}
    return detector_apt.obtener_estado()

@app.get("/apt/xai")
async def obtener_explicaciones_xai(request: Request, api_key: str = Depends(verificar_api_key)):
    if not XAI_DISPONIBLE:
        return []
    explicador = obtener_explicador()
    if not explicador:
        return []
    return explicador.obtener_explicaciones(ultimas_n=20)

@app.get("/apt/importancia")
async def obtener_importancia_global(request: Request, api_key: str = Depends(verificar_api_key)):
    if not XAI_DISPONIBLE:
        return {}
    explicador = obtener_explicador()
    if not explicador:
        return {}
    return explicador.resumen_importancia_global()

@app.get("/apt/lateral")
async def obtener_movimiento_lateral(request: Request, api_key: str = Depends(verificar_api_key)):
    if not LATERAL_DISPONIBLE:
        return []
    return detector_lateral.obtener_detecciones(ultimas_n=20)

@app.get("/apt/lateral/estado")
async def obtener_estado_lateral(request: Request, api_key: str = Depends(verificar_api_key)):
    if not LATERAL_DISPONIBLE:
        return {"disponible": False}
    return detector_lateral.obtener_estado()

@app.get("/")
def health():
    return {"status": "Noctua ASOAR funcionando", "version": "1.0"}
