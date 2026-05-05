from fastapi import FastAPI, Request
import requests
import json

from fastapi.responses import FileResponse

from datetime import datetime
import os

app = FastAPI()

OLLAMA_URL = "http://localhost:11434/api/generate"
HETZNER_TOKEN = "klNXgMgVkkhNB0jzJHlDdjsAro0vAMWNB44oOpKRoYiFSuRZjhssYdonWG8J3VKy"  # Reemplaza con tu token
HETZNER_FIREWALL_ID = "10850215"  # Lo obtendremos después

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
    
    # Obtener reglas actuales
    r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers)
    reglas_actuales = r.json().get("firewall", {}).get("rules", [])
    
    # Añadir nueva regla de bloqueo
    nueva_regla = {
        "direction": "in",
        "protocol": "tcp",
        "source_ips": [f"{ip}/32"],
        "port": "any",
        "description": f"ASOAR-blocked-{ip}"
    }
    reglas_actuales.append(nueva_regla)
    
    # Aplicar reglas actualizadas
    payload = {"rules": reglas_actuales}
    r = requests.post(
        f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}/actions/set_rules",
        headers=headers,
        json=payload
    )
    
    print(f"[HETZNER] IP {ip} bloqueada - Status: {r.status_code}")
    return r.status_code == 201

@app.post("/alerta")
async def recibir_alerta(request: Request):
    alerta = await request.json()
    
    ip_atacante = alerta.get("data", {}).get("srcip", "desconocida")
    nivel = alerta.get("rule", {}).get("level", 0)
    descripcion = alerta.get("rule", {}).get("description", "")
    
    print(f"[ALERTA] Nivel {nivel} - {descripcion} - IP: {ip_atacante}")
    
    # Solo analizar alertas de nivel 10 o superior
    if nivel >= 10:
        decision = preguntar_ollama(alerta)
        print(f"[OLLAMA] Decision: {decision}")
        
        if "BLOQUEAR" in decision and ip_atacante != "desconocida":
            bloquear_ip_hetzner(ip_atacante)
            return {"accion": "BLOQUEADA", "ip": ip_atacante, "decision": decision}
    
    return {"accion": "IGNORADA", "nivel": nivel, "descripcion": descripcion}

@app.post("/agente")
async def recibir_datos_agente(request: Request):
    datos = await request.json()
    
    hostname = datos.get("hostname", "desconocido")
    ip = datos.get("ip", "desconocida")
    
    print(f"[AGENTE] Datos recibidos de {hostname} ({ip})")
    
    # Guardar datos del agente en un archivo JSON
    import os
    agentes_file = "/root/asoar/agentes.json"
    
    agentes = {}
    if os.path.exists(agentes_file):
        try:
            with open(agentes_file, "r") as f:
                agentes = json.load(f)
        except:
            agentes = {}
    
    agentes[hostname] = {
        "ultima_conexion": datetime.now().isoformat(),
        "datos": datos
    }
    
    with open(agentes_file, "w") as f:
        json.dump(agentes, f, indent=2)
    
    return {"status": "ok", "hostname": hostname}


@app.get("/agentes")
async def listar_agentes():
    import os
    agentes_file = "/root/asoar/agentes.json"
    if os.path.exists(agentes_file):
        with open(agentes_file, "r") as f:
            return json.load(f)
    return {}

@app.get("/agente_asoar.ps1")
async def descargar_agente():
    return FileResponse("/root/asoar/agente_asoar.ps1", 
                       media_type="text/plain",
                       filename="agente_asoar.ps1")


@app.get("/cumplimiento/{hostname}")
async def calcular_cumplimiento(hostname: str):
    agentes_file = "/root/asoar/agentes.json"
    if not os.path.exists(agentes_file):
        return {"error": "No hay datos de agentes"}
    
    with open(agentes_file, "r") as f:
        agentes = json.load(f)
    
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
    
    # ── ISO 27001 ──────────────────────────────────────────
    iso27001 = [
        {
            "control": "A.8.7",
            "nombre": "Proteccion contra malware",
            "cumple": defender,
            "detalle": "Windows Defender activo" if defender else "Windows Defender inactivo"
        },
        {
            "control": "A.8.20",
            "nombre": "Seguridad en redes",
            "cumple": firewall,
            "detalle": "Firewall activo" if firewall else "Firewall inactivo"
        },
        {
            "control": "A.8.8",
            "nombre": "Gestion de vulnerabilidades tecnicas",
            "cumple": actualizaciones_criticas == 0,
            "detalle": f"{actualizaciones_criticas} actualizaciones criticas pendientes"
        },
        {
            "control": "A.5.15",
            "nombre": "Control de acceso",
            "cumple": len(usuarios_admin) <= 2,
            "detalle": f"{len(usuarios_admin)} administradores locales"
        },
        {
            "control": "A.8.21",
            "nombre": "Seguridad de servicios de red",
            "cumple": len(puertos) <= 20,
            "detalle": f"{len(puertos)} puertos en escucha"
        },
        {
            "control": "A.8.19",
            "nombre": "Gestion de software en sistemas",
            "cumple": actualizaciones_pendientes == 0,
            "detalle": f"{actualizaciones_pendientes} actualizaciones pendientes"
        }
    ]
    
    # ── NIS2 ───────────────────────────────────────────────
    nis2 = [
        {
            "control": "Art.21.2.e",
            "nombre": "Seguridad en adquisicion y mantenimiento",
            "cumple": actualizaciones_criticas == 0,
            "detalle": f"{actualizaciones_criticas} actualizaciones criticas pendientes"
        },
        {
            "control": "Art.21.2.b",
            "nombre": "Gestion de incidentes",
            "cumple": defender,
            "detalle": "Proteccion antivirus activa" if defender else "Sin proteccion antivirus"
        },
        {
            "control": "Art.21.2.i",
            "nombre": "Control de accesos y gestion de activos",
            "cumple": len(usuarios_admin) <= 2,
            "detalle": f"{len(usuarios_admin)} administradores locales"
        },
        {
            "control": "Art.21.2.j",
            "nombre": "Uso de autenticacion y comunicaciones seguras",
            "cumple": firewall,
            "detalle": "Firewall activo" if firewall else "Firewall inactivo"
        }
    ]
    
    # ── ENS ────────────────────────────────────────────────
    ens = [
        {
            "control": "op.exp.5",
            "nombre": "Gestion de cambios",
            "cumple": actualizaciones_pendientes == 0,
            "detalle": f"{actualizaciones_pendientes} actualizaciones pendientes"
        },
        {
            "control": "mp.sw.1",
            "nombre": "Desarrollo de aplicaciones",
            "cumple": actualizaciones_criticas == 0,
            "detalle": f"{actualizaciones_criticas} criticas pendientes"
        },
        {
            "control": "op.acc.4",
            "nombre": "Proceso de gestion de derechos de acceso",
            "cumple": len(usuarios_admin) <= 2,
            "detalle": f"{len(usuarios_admin)} administradores"
        },
        {
            "control": "op.exp.3",
            "nombre": "Gestion de la configuracion",
            "cumple": firewall and defender,
            "detalle": "Firewall y Defender activos" if firewall and defender else "Configuracion incompleta"
        },
        {
            "control": "mp.com.1",
            "nombre": "Perimetro seguro",
            "cumple": firewall,
            "detalle": "Firewall activo" if firewall else "Firewall inactivo"
        }
    ]
    
    def calcular_score(controles):
        if not controles:
            return 0
        return round(sum(1 for c in controles if c["cumple"]) / len(controles) * 100)
    
    return {
        "hostname": hostname,
        "iso27001": {
            "score": calcular_score(iso27001),
            "controles": iso27001
        },
        "nis2": {
            "score": calcular_score(nis2),
            "controles": nis2
        },
        "ens": {
            "score": calcular_score(ens),
            "controles": ens
        },
        "score_global": round((calcular_score(iso27001) + calcular_score(nis2) + calcular_score(ens)) / 3)
    }


@app.get("/")
def health():
    return {"status": "ASOAR funcionando", "version": "1.0"}
