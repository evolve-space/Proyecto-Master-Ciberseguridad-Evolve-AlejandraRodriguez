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
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# IPs conocidas que no son amenazas reales
IPS_WHITELIST = {
    "47.62.74.87",       # IP propia - acceso al dashboard
    "66.132.0.0/16",     # Censys - escaner de investigacion
    "66.133.0.0/16",     # Censys
    "162.142.125.0/24",  # Shodan
    "198.20.69.0/24",    # Shodan
}

def es_ip_whitelist_main(ip: str) -> bool:
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
    simulacion: bool = False

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
app = FastAPI(title="Noctua Predictive", version="1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Variables ──────────────────────────────────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/api/generate"
AGENTES_FILE = "/root/asoar/agentes.json"
ABUSE_CACHE_FILE = "/root/asoar/abuse_cache.json"
BLOCKED_IPS_FILE = "/root/asoar/blocked_ips_cache.json"

def cargar_ips_bloqueadas_cache() -> set:
    """Carga la caché local de IPs bloqueadas."""
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            return set(json.load(f))
    except:
        return set()

def guardar_ips_bloqueadas_cache(ips: set):
    """Guarda la caché local de IPs bloqueadas."""
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(list(ips), f, indent=2)


def consultar_abuseipdb(ip: str) -> dict:
    """Consulta AbuseIPDB con caché persistente de 24 horas."""
    try:
        cache = {}
        if os.path.exists(ABUSE_CACHE_FILE):
            with open(ABUSE_CACHE_FILE, "r") as f:
                cache = json.load(f)
        if ip in cache:
            cached_time = datetime.fromisoformat(cache[ip]["timestamp"])
            if (datetime.now() - cached_time).seconds < 86400:
                return cache[ip]["data"]
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            result = {"score": data.get("abuseConfidenceScore", 0)}
            cache[ip] = {"timestamp": datetime.now().isoformat(), "data": result}
            with open(ABUSE_CACHE_FILE, "w") as f:
                json.dump(cache, f, indent=2, default=str)
            return result
    except:
        pass
    return {"score": 0}

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

def ip_esta_bloqueada(ip: str) -> bool:
    """Comprueba si una IP está bloqueada usando caché local."""
    ips_cache = cargar_ips_bloqueadas_cache()
    if ip in ips_cache:
        print(f"[CACHE] IP {ip} bloqueada (caché local)")
        return True
    try:
        headers = {"Authorization": f"Bearer {HETZNER_TOKEN}"}
        r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers, timeout=5)
        reglas = r.json().get("firewall", {}).get("rules", [])
        bloqueada = any(f"ASOAR-blocked-{ip}" in reg.get("description", "") for reg in reglas)
        if bloqueada:
            print(f"[BLOQUEADA] IP {ip} en Hetzner — añadiendo a caché")
            ips_cache.add(ip)
            guardar_ips_bloqueadas_cache(ips_cache)
        return bloqueada
    except Exception as e:
        print(f"[BLOQUEADA] Error verificando {ip}: {e}")
        return False

def bloquear_ip_hetzner(ip: str):
    headers = {
        "Authorization": f"Bearer {HETZNER_TOKEN}",
        "Content-Type": "application/json"
    }
    r = requests.get(f"https://api.hetzner.cloud/v1/firewalls/{HETZNER_FIREWALL_ID}", headers=headers)
    reglas_actuales = r.json().get("firewall", {}).get("rules", [])
    
    # PROTECCION: garantizar que siempre existan las reglas de acceso esenciales
    descripciones_actuales = [reg.get("description","") for reg in reglas_actuales]
    if "ALLOW-dashboard-8443" not in descripciones_actuales:
        reglas_actuales.insert(0, {
            "direction": "in", "protocol": "tcp", "port": "8443",
            "source_ips": ["0.0.0.0/0", "::/0"],
            "description": "ALLOW-dashboard-8443"
        })
        print("[HETZNER] PROTECCION: regla ALLOW-dashboard-8443 restaurada")
    if "ALLOW-ssh-22" not in descripciones_actuales:
        reglas_actuales.insert(0, {
            "direction": "in", "protocol": "tcp", "port": "22",
            "source_ips": ["0.0.0.0/0", "::/0"],
            "description": "ALLOW-ssh-22"
        })
        print("[HETZNER] PROTECCION: regla ALLOW-ssh-22 restaurada")
    
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
    # Actualizar caché local
    ips_cache = cargar_ips_bloqueadas_cache()
    ips_cache.add(ip)
    guardar_ips_bloqueadas_cache(ips_cache)
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

    # Ticket automatico por bloqueo
    try:
        from apt_tickets import crear_ticket, _cargar
        data = _cargar()
        tickets_activos = [t for t in data.get("tickets", [])
                          if t.get("ip") == ip
                          and t.get("estado") in ["Abierto", "Investigando"]
                          and (datetime.now() - datetime.fromisoformat(t["creado_en"].replace("Z","").split("+")[0])).total_seconds() < 7200]
        if not ip_esta_bloqueada(ip) and not tickets_activos:
            crear_ticket(
                titulo=f"IP bloqueada automáticamente — {ip}",
                descripcion=f"El sistema ha bloqueado automáticamente la IP {ip} "
                           f"en el firewall de Hetzner Cloud por actividad maliciosa detectada. "
                           f"Requiere revisión del analista para confirmar el bloqueo.",
                prioridad="ALTA",
                ip=ip,
                origen="bloqueo_automatico"
            )
            print(f"[TICKET] Ticket creado por bloqueo automático de {ip}")
    except Exception as e:
        print(f"[TICKET] Error creando ticket de bloqueo: {e}")

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
    ip_atacante = alerta.data.get("srcip", "") or alerta.data.get("src_ip", "")
    nivel = alerta.rule.get("level", 0)
    descripcion = alerta.rule.get("description", "")
    print(f"[ALERTA] Nivel {nivel} - {descripcion} - IP: {ip_atacante}")

    # Analisis APT con LSTM — solo si hay IP externa real
    apt_resultado = {}
    if APT_DISPONIBLE and ip_atacante and ip_atacante not in ["", "desconocida", "127.0.0.1", "0.0.0.0"] and not es_ip_whitelist_main(ip_atacante):        
        try:
            # Consultar AbuseIPDB antes de procesar
            abuse_score = consultar_abuseipdb(ip_atacante).get("score", 0)
            
            # Amenazas oportunistas confirmadas por reputacion externa
            # (aunque no acumulen suficiente contexto para el LSTM)
            if abuse_score >= 90 and not ip_esta_bloqueada(ip_atacante):
                try:
                    from apt_tickets import crear_ticket, _cargar
                    data_tickets = _cargar()
                    tickets_activos_ip = [t for t in data_tickets.get("tickets", [])
                                          if t.get("ip") == ip_atacante
                                          and t.get("estado") in ["Abierto", "Investigando"]]
                    if not tickets_activos_ip:
                        abuse_data = consultar_abuseipdb(ip_atacante)
                        crear_ticket(
                            titulo=f"IP maliciosa confirmada (AbuseIPDB) — {ip_atacante}",
                            descripcion=f"La IP {ip_atacante} tiene una reputacion de {abuse_score}% en AbuseIPDB "
                                       f"(amenaza confirmada por fuente externa), pero no ha generado "
                                       f"suficiente volumen de eventos locales para ser evaluada por el motor LSTM. "
                                       f"Pais: {abuse_data.get('pais','')} | ISP: {abuse_data.get('isp','')} | "
                                       f"Reportes: {abuse_data.get('reportes',0)}.",
                            prioridad="ALTA",
                            ip=ip_atacante,
                            fase_mitre="unknown",
                            confianza=0,
                            abuse_score=abuse_score,
                            abuse_pais=abuse_data.get("pais",""),
                            abuse_isp=abuse_data.get("isp","")
                        )
                        print(f"[ABUSEIPDB] Ticket creado para {ip_atacante} por reputacion externa ({abuse_score}%)")
                        # Bloqueo automatico — mismo umbral de confianza que el playbook LSTM
                        try:
                            bloquear_ip_hetzner(ip_atacante)
                            from apt_tickets import _cargar as _cargar2, _guardar as _guardar2
                            data_tk = _cargar2()
                            for t in data_tk.get("tickets", []):
                                if t.get("ip") == ip_atacante and t.get("estado") == "Abierto":
                                    t["estado"] = "Contenido"
                                    t.setdefault("notas", []).append({
                                        "timestamp": datetime.now().isoformat(),
                                        "texto": f"Bloqueado automaticamente por reputacion AbuseIPDB {abuse_score}%."
                                    })
                            _guardar2(data_tk)
                            print(f"[ABUSEIPDB] IP {ip_atacante} bloqueada automaticamente ({abuse_score}%)")
                        except Exception as e_block:
                            print(f"[ABUSEIPDB] Error bloqueando: {e_block}")
                except Exception as e_abuse:
                    print(f"[ABUSEIPDB] Error creando ticket: {e_abuse}")
            
            # Firmas de malware conocido — bloqueo por conocimiento tecnico independiente de reputacion externa
            firmas_malware_conocido = ["mirai", "jaws", "shell command execution", "webshell", "remote code execution"]
            descripcion_lower = descripcion.lower()
            es_firma_critica = nivel >= 12 and any(f in descripcion_lower for f in firmas_malware_conocido)
            
            if es_firma_critica and not ip_esta_bloqueada(ip_atacante):
                try:
                    from apt_tickets import crear_ticket, _cargar
                    data_tickets2 = _cargar()
                    tickets_activos_ip2 = [t for t in data_tickets2.get("tickets", [])
                                          if t.get("ip") == ip_atacante
                                          and t.get("estado") in ["Abierto", "Investigando"]]
                    if not tickets_activos_ip2:
                        abuse_data2 = consultar_abuseipdb(ip_atacante)
                        crear_ticket(
                            titulo=f"Firma de malware conocido detectada — {ip_atacante}",
                            descripcion=f"Suricata ha detectado una firma critica de malware/exploit conocido "
                                       f"(\"{descripcion}\") desde la IP {ip_atacante}, nivel Wazuh {nivel}. "
                                       f"Esta deteccion se basa en el conocimiento tecnico de la firma, "
                                       f"independientemente de la reputacion externa (AbuseIPDB: {abuse_data2.get('score',0)}%). "
                                       f"Pais: {abuse_data2.get('pais','')} | ISP: {abuse_data2.get('isp','')}.",
                            prioridad="CRITICA",
                            ip=ip_atacante,
                            fase_mitre="initial_access",
                            confianza=0,
                            abuse_score=abuse_data2.get("score", 0),
                            abuse_pais=abuse_data2.get("pais",""),
                            abuse_isp=abuse_data2.get("isp","")
                        )
                        print(f"[FIRMA] Ticket creado para {ip_atacante} por firma de malware conocido: {descripcion}")
                except Exception as e_firma:
                    print(f"[FIRMA] Error creando ticket: {e_firma}")

            if abuse_score < 20:
                print(f"[APT] IP {ip_atacante} AbuseIPDB {abuse_score}% < 20% — omitiendo")
            else:
                apt_resultado = detector_apt.procesar_alerta({
                    "rule_id":     str(alerta.rule.get("id", "0")),
                    "nivel":       nivel,
                    "ip":          ip_atacante,
                    "agente":      "master",
                    "flow":        alerta.data.get("flow", {}),
                    "tcp":         alerta.data.get("tcp", {}),
                    "abuse_score": abuse_score,
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

    # Ticket automatico para alertas criticas Wazuh (nivel 12+)
    if nivel >= 12 and ip_atacante and ip_atacante not in ["", "desconocida", "127.0.0.1", "0.0.0.0"]:
        try:
            from apt_tickets import crear_ticket, _cargar
            data = _cargar()
            tickets_activos = [t for t in data.get("tickets", [])
                              if t.get("ip") == ip_atacante
                              and t.get("estado") in ["Abierto", "Investigando"]
                              and (datetime.now() - datetime.fromisoformat(t["creado_en"].replace("Z","").split("+")[0])).total_seconds() < 7200]
            if not ip_esta_bloqueada(ip) and not tickets_activos:
                crear_ticket(
                    titulo=f"Alerta crítica Wazuh — Nivel {nivel} desde {ip_atacante}",
                    descripcion=f"Wazuh ha detectado una alerta de nivel crítico ({nivel}) "
                               f"desde la IP {ip_atacante}. "
                               f"Descripción: {descripcion}. "
                               f"Requiere revisión inmediata del analista.",
                    prioridad="CRITICA",
                    ip=ip_atacante,
                    origen="wazuh_critico"
                )
                print(f"[TICKET] Ticket crítico creado para IP {ip_atacante} nivel {nivel}")
        except Exception as e:
            print(f"[TICKET] Error creando ticket critico: {e}")

    # Trigger automatico playbook SSH Brute Force
    if nivel >= 10 and ip_atacante and ip_atacante not in ["", "desconocida", "127.0.0.1", "0.0.0.0"]:
        if any(kw in descripcion.lower() for kw in ["ssh", "brute", "authentication failed", "login failed"]):
            try:
                abuse = consultar_abuseipdb(ip_atacante)
                if abuse.get("score", 0) >= 90 and not ip_esta_bloqueada(ip_atacante):
                    import requests as req
                    req.post(
                        "http://localhost:8000/playbooks/ejecutar",
                        headers={"X-API-Key": API_KEY},
                        json={"playbook": "ssh_brute_force", "ip": ip_atacante},
                        timeout=30
                    )
                    print(f"[PLAYBOOK] SSH Brute Force lanzado automáticamente para {ip_atacante}")
            except Exception as ep:
                print(f"[PLAYBOOK] Error SSH brute force: {ep}")

    # En modo simulacion saltamos Ollama para mayor velocidad
    if alerta.simulacion and nivel >= 10:
        decision = "BLOQUEAR"
        if "BLOQUEAR" in decision and ip_atacante != "desconocida":
            bloquear_ip_hetzner(ip_atacante)
            print(f"[SIMULACION] Bloqueo real en Hetzner para IP: {ip_atacante}")
            return {"accion": "BLOQUEADA", "ip": ip_atacante, "decision": decision,
                    "apt": apt_resultado, "xai": xai_resultado, "lateral": lateral_resultado,
                    "simulacion": True}
    elif nivel >= 10:
        decision = preguntar_ollama(alerta.dict())

    if nivel >= 10:
        decision = preguntar_ollama(alerta.dict())
        print(f"[OLLAMA] Decision: {decision}")
        if "BLOQUEAR" in decision and ip_atacante != "desconocida":
            abuse = consultar_abuseipdb(ip_atacante)
            if abuse.get("score", 0) >= 50:
                bloquear_ip_hetzner(ip_atacante)
                return {"accion": "BLOQUEADA", "ip": ip_atacante, "decision": decision, "apt": apt_resultado, "xai": xai_resultado, "lateral": lateral_resultado}
            else:
                print(f"[OLLAMA] Bloqueo cancelado para {ip_atacante} — AbuseIPDB {abuse.get('score',0)}% < 50%")
    # Trigger automatico playbook Port Scan
    if ip_atacante and ip_atacante not in ["", "desconocida", "127.0.0.1", "0.0.0.0"] and not es_ip_whitelist_main(ip_atacante):
        if any(kw in descripcion.lower() for kw in ["scan", "port scan", "nmap", "zmap"]):
            try:
                abuse = consultar_abuseipdb(ip_atacante)
                if abuse.get("score", 0) >= 90 and not ip_esta_bloqueada(ip_atacante):
                    import requests as req
                    req.post(
                        "http://localhost:8000/playbooks/ejecutar",
                        headers={"X-API-Key": API_KEY},
                        json={"playbook": "port_scan", "ip": ip_atacante},
                        timeout=30
                    )
                    print(f"[PLAYBOOK] Port Scan lanzado automáticamente para {ip_atacante}")
            except Exception as ep:
                print(f"[PLAYBOOK] Error Port Scan: {ep}")
    return {"accion": "IGNORADA", "nivel": nivel, "descripcion": descripcion, "apt": apt_resultado, "xai": xai_resultado, "lateral": lateral_resultado}

@app.post("/agente")
@limiter.limit("20/minute")
async def recibir_datos_agente(request: Request, datos: DatosAgente, api_key: str = Depends(verificar_api_key)):
    print(f"[AGENTE] Datos recibidos de {datos.hostname} ({datos.ip})")
    agentes = cargar_agentes()
    
    # ── Analisis de comportamiento — comparar con snapshot anterior ───────────
    cambios = []
    anterior = agentes.get(datos.hostname, {}).get("datos", {})
    if anterior:
        seg_ant = anterior.get("seguridad", {})
        seg_new = datos.dict().get("seguridad", {})
        
        # Procesos nuevos
        procs_ant = set(p.get("nombre","") for p in seg_ant.get("procesos_sospechosos", []))
        procs_new = set(p.get("nombre","") for p in seg_new.get("procesos_sospechosos", []))
        for proc in procs_new - procs_ant:
            cambios.append({"tipo": "proceso_nuevo", "detalle": f"Nuevo proceso sospechoso: {proc}", "severidad": "ALTO"})
        
        # Puertos nuevos
        puertos_ant = set()
        puertos_new = set()
        for p in seg_ant.get("puertos_escucha", []):
            puertos_ant.add(p.get("puerto", p) if isinstance(p, dict) else p)
        for p in seg_new.get("puertos_escucha", []):
            puertos_new.add(p.get("puerto", p) if isinstance(p, dict) else p)
        for puerto in puertos_new - puertos_ant:
            proc_name = next((p.get("proceso","?") for p in seg_new.get("puertos_escucha",[]) 
                            if isinstance(p, dict) and p.get("puerto") == puerto), "?")
            cambios.append({"tipo": "puerto_nuevo", "detalle": f"Nuevo puerto abierto: {puerto} ({proc_name})", "severidad": "MEDIO"})
        
        # Nuevo admin
        admins_ant = set(seg_ant.get("usuarios_admin", []))
        admins_new = set(seg_new.get("usuarios_admin", []))
        for admin in admins_new - admins_ant:
            cambios.append({"tipo": "nuevo_admin", "detalle": f"Nuevo usuario administrador: {admin}", "severidad": "CRITICO"})
        
        # Pico de CPU
        rend_ant = anterior.get("rendimiento", {})
        rend_new = datos.dict().get("rendimiento", {})
        cpu_ant = rend_ant.get("cpu_porcentaje", 0)
        cpu_new = rend_new.get("cpu_porcentaje", 0)
        if cpu_new - cpu_ant > 40:
            cambios.append({"tipo": "pico_cpu", "detalle": f"Pico de CPU: {cpu_ant}% → {cpu_new}%", "severidad": "ALTO"})
        
        if cambios:
            print(f"[AGENTE] {len(cambios)} cambios detectados en {datos.hostname}")

    agentes[datos.hostname] = {
        "ultima_conexion": datetime.now().isoformat(),
        "datos": datos.dict(),
        "cambios": cambios,
        "ultimo_analisis": datetime.now().isoformat()
    }
    guardar_agentes(agentes)
    return {"status": "ok", "hostname": datos.hostname, "cambios_detectados": len(cambios)}

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

    eu_ai_act = [
        {"control": "Art.13", "nombre": "Transparencia del sistema", "cumple": APT_DISPONIBLE, "detalle": "Motor LSTM con explicabilidad XAI activa"},
        {"control": "Art.14", "nombre": "Supervision humana", "cumple": True, "detalle": "Dashboard con control manual y desbloqueo de IPs"},
        {"control": "Art.15", "nombre": "Precision y robustez", "cumple": APT_DISPONIBLE, "detalle": f"Modelo LSTM con reentrenamiento automatico activo"},
        {"control": "Art.17", "nombre": "Sistema de gestion de calidad", "cumple": True, "detalle": "Historial de versiones y backup automatico del modelo"},
        {"control": "Art.64", "nombre": "Registros y trazabilidad", "cumple": XAI_DISPONIBLE, "detalle": "Explicaciones XAI auditables guardadas en xai_explicaciones.json"},
        {"control": "Anexo III", "nombre": "Sistema de alto riesgo", "cumple": True, "detalle": "Sistema de ciberseguridad clasificado como alto riesgo bajo EU AI Act"},
    ]

    return {
        "hostname": hostname,
        "iso27001": {"score": calcular_score(iso27001), "controles": iso27001},
        "nis2": {"score": calcular_score(nis2), "controles": nis2},
        "ens": {"score": calcular_score(ens), "controles": ens},
        "eu_ai_act":{"score": calcular_score(eu_ai_act), "controles": eu_ai_act},
        "score_global": round((calcular_score(iso27001) + calcular_score(nis2) + calcular_score(ens)) / 3)
    }

@app.get("/historico")
async def obtener_historico(request: Request, api_key: str = Depends(verificar_api_key)):
    historico_file = "/root/asoar/historico_ips.json"
    if os.path.exists(historico_file):
        with open(historico_file, "r") as f:
            return json.load(f)
    return []

from fastapi import BackgroundTasks

@app.post("/bloquear/{ip}")
async def bloquear_ip_manual(ip: str, background_tasks: BackgroundTasks, api_key: str = Depends(verificar_api_key)):
    ip = ip.strip()
    try:
        background_tasks.add_task(bloquear_ip_hetzner, ip)
        # Guardar en historial inmediatamente
        hist_file = "/root/asoar/ips_manual.json"
        try:
            with open(hist_file, "r") as f:
                hist = json.load(f)
        except:
            hist = []
        hist.append({
            "ip": ip,
            "accion": "BLOQUEADA",
            "timestamp": datetime.now().isoformat(),
            "origen": "manual"
        })
        with open(hist_file, "w") as f:
            json.dump(hist, f, indent=2, default=str)
        return {"status": "ok", "ip": ip, "accion": "BLOQUEADA"}
    except Exception as e:
        return {"status": "error", "ip": ip, "error": str(e)}

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
    
    # Guardar en historial manual
    hist_file = "/root/asoar/ips_manual.json"
    try:
        with open(hist_file, "r") as f:
            hist = json.load(f)
    except:
        hist = []
    hist.append({
        "ip": ip,
        "accion": "DESBLOQUEADA",
        "timestamp": datetime.now().isoformat(),
        "origen": "manual"
    })
    with open(hist_file, "w") as f:
        json.dump(hist, f, indent=2, default=str)
    
    return {"status": "ok", "ip": ip, "accion": "DESBLOQUEADA"}

@app.get("/apt/campanas")
async def obtener_campanas_apt(request: Request, api_key: str = Depends(verificar_api_key)):
    if not APT_DISPONIBLE:
        return []
    return detector_apt.obtener_campanas(ultimas_n=500)

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
    return explicador.obtener_explicaciones(ultimas_n=200)

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

@app.get("/apt/retrain/estado")
async def obtener_estado_retrain(request: Request, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_retrain import obtener_estado_retrain
        return obtener_estado_retrain()
    except Exception as e:
        return {"error": str(e)}

@app.post("/apt/retrain/forzar")
async def forzar_reentrenamiento(request: Request, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_retrain import reentrenar
        return reentrenar(forzar=True)
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
def health():
    return {"status": "Noctua Predictive funcionando", "version": "1.0"}


# ══════════════════════════════════════════════════════════════════════════════
# PLAYBOOKS
# ══════════════════════════════════════════════════════════════════════════════
PLAYBOOKS_FILE = "/root/asoar/playbooks.json"

def cargar_playbooks():
    try:
        with open(PLAYBOOKS_FILE, "r") as f:
            return json.load(f)
    except:
        return {"ejecuciones": []}

def guardar_playbooks(data):
    with open(PLAYBOOKS_FILE, "w") as f:
        json.dump(data, f, indent=2, default=str)

def actualizar_ticket_por_ip(ip: str, playbook: str, ejecucion: dict):
    """Busca y actualiza el ticket activo para una IP."""
    try:
        from apt_tickets import _cargar, _guardar
        tickets_data = _cargar()
        for t in tickets_data.get("tickets", []):
            if t.get("ip") == ip and t.get("estado") in ["Abierto", "Investigando"]:
                t["estado"] = "Contenido"
                t.setdefault("notas", []).append({
                    "timestamp": datetime.now().isoformat(),
                    "texto": f"Playbook {playbook} ejecutado automáticamente. IP {ip} bloqueada en Hetzner."
                })
                ejecucion["acciones"].append({
                    "accion": "ACTUALIZAR_TICKET",
                    "estado": "OK",
                    "timestamp": datetime.now().isoformat(),
                    "ticket": t["id"]
                })
        _guardar(tickets_data)
    except Exception as e:
        ejecucion["acciones"].append({"accion": "ACTUALIZAR_TICKET", "estado": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()})

@app.post("/playbooks/ejecutar")
async def ejecutar_playbook(request: Request, api_key: str = Depends(verificar_api_key)):
    body = await request.json()
    playbook = body.get("playbook")
    ip = body.get("ip", "")
    ticket_id = body.get("ticket_id", "")
    
    data = cargar_playbooks()
    ejecucion = {
        "id": f"PB-{len(data['ejecuciones'])+1:04d}",
        "playbook": playbook,
        "ip": ip,
        "ticket_id": ticket_id,
        "timestamp": datetime.now().isoformat(),
        "estado": "EJECUTANDO",
        "acciones": []
    }
    
    try:
        if playbook == "ssh_brute_force":
            bloquear_ip_hetzner(ip)
            ejecucion["acciones"].append({"accion": "BLOQUEAR_HETZNER", "estado": "OK", "timestamp": datetime.now().isoformat()})
            actualizar_ticket_por_ip(ip, playbook, ejecucion)
            ejecucion["estado"] = "COMPLETADO"

        elif playbook == "ip_maliciosa":
            bloquear_ip_hetzner(ip)
            ejecucion["acciones"].append({"accion": "BLOQUEAR_HETZNER", "estado": "OK", "timestamp": datetime.now().isoformat()})
            actualizar_ticket_por_ip(ip, playbook, ejecucion)
            ejecucion["estado"] = "COMPLETADO"

        elif playbook == "port_scan":
            bloquear_ip_hetzner(ip)
            ejecucion["acciones"].append({"accion": "BLOQUEAR_HETZNER", "estado": "OK", "timestamp": datetime.now().isoformat()})
            actualizar_ticket_por_ip(ip, playbook, ejecucion)
            ejecucion["estado"] = "COMPLETADO"

    except Exception as e:
        ejecucion["estado"] = "ERROR"
        ejecucion["error"] = str(e)
    
    data["ejecuciones"].append(ejecucion)
    guardar_playbooks(data)
    return ejecucion

@app.get("/playbooks/historial")
async def historial_playbooks(api_key: str = Depends(verificar_api_key)):
    data = cargar_playbooks()
    return data["ejecuciones"]

@app.get("/iocs/stix")
async def exportar_stix(api_key: str = Depends(verificar_api_key)):
    try:
        import stix2
        from datetime import datetime as dt
        
        # Cargar IPs bloqueadas
        try:
            with open("/root/asoar/blocked_ips_cache.json") as f:
                ips_bloqueadas = json.load(f)
        except:
            ips_bloqueadas = []
        
        # Cargar cache AbuseIPDB
        try:
            with open("/root/asoar/abuse_cache.json") as f:
                abuse_cache = json.load(f)
        except:
            abuse_cache = {}
        
        objetos = []
        
        # Identidad de Noctua
        identidad = stix2.Identity(
            name="Noctua Predictive SOC",
            identity_class="system",
            description="Autonomous Security Operations Platform — UPM PFG 2026"
        )
        objetos.append(identidad)
        
        # Crear indicadores por cada IP bloqueada
        for ip in ips_bloqueadas:
            abuse = abuse_cache.get(ip, {}).get("data", {})
            score = abuse.get("score", 0)
            pais = abuse.get("pais", "")
            isp = abuse.get("isp", "")
            
            indicador = stix2.Indicator(
                name=f"Malicious IP: {ip}",
                description=f"IP bloqueada por Noctua Predictive. AbuseIPDB: {score}%. Pais: {pais}. ISP: {isp}.",
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=dt.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                labels=["malicious-activity"],
                confidence=score,
                created_by_ref=identidad.id,
            )
            objetos.append(indicador)
        
        bundle = stix2.Bundle(objects=objetos)
        return json.loads(bundle.serialize())
        
    except Exception as e:
        return {"error": str(e)}

# ── TICKETS ───────────────────────────────────────────────────────────────────
@app.get("/tickets")
async def listar_tickets(
    estado: str = None,
    prioridad: str = None,
    api_key: str = Depends(verificar_api_key)
):
    try:
        from apt_tickets import listar_tickets as _listar
        return _listar(estado=estado, prioridad=prioridad)
    except Exception as e:
        return {"error": str(e)}

@app.post("/tickets")
async def crear_ticket(request: Request, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_tickets import crear_ticket as _crear
        body = await request.json()
        return _crear(**body)
    except Exception as e:
        return {"error": str(e)}

@app.get("/tickets/{ticket_id}")
async def obtener_ticket(ticket_id: str, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_tickets import obtener_ticket as _obtener
        t = _obtener(ticket_id)
        if not t:
            return {"error": "Ticket no encontrado"}
        return t
    except Exception as e:
        return {"error": str(e)}

@app.post("/tickets/{ticket_id}/estado")
async def actualizar_estado(ticket_id: str, request: Request, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_tickets import actualizar_estado as _actualizar
        body = await request.json()
        t = _actualizar(ticket_id, body.get("estado"), body.get("nota", ""))
        if not t:
            return {"error": "Ticket no encontrado o estado invalido"}
        return t
    except Exception as e:
        return {"error": str(e)}

@app.post("/tickets/{ticket_id}/nota")
async def anadir_nota(ticket_id: str, request: Request, api_key: str = Depends(verificar_api_key)):
    try:
        from apt_tickets import anadir_nota as _nota
        body = await request.json()
        t = _nota(ticket_id, body.get("nota", ""))
        if not t:
            return {"error": "Ticket no encontrado"}
        return t
    except Exception as e:
        return {"error": str(e)}

@app.get("/tickets/metricas/resumen")
async def metricas_tickets(api_key: str = Depends(verificar_api_key)):
    try:
        from apt_tickets import metricas_tickets as _metricas
        return _metricas()
    except Exception as e:
        return {"error": str(e)}

# ── COMANDOS BIDIRECCIONALES PARA AGENTE WINDOWS ──────────────────────────────
COMANDOS_FILE = "/root/asoar/comandos_agente.json"

def cargar_comandos():
    if os.path.exists(COMANDOS_FILE):
        try:
            with open(COMANDOS_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {}

def guardar_comandos(comandos: dict):
    with open(COMANDOS_FILE, "w") as f:
        json.dump(comandos, f, indent=2, default=str)

@app.post("/agente/comando/{hostname}")
async def enviar_comando(hostname: str, request: Request, api_key: str = Depends(verificar_api_key)):
    """Envia un comando pendiente al agente Windows."""
    try:
        body = await request.json()
        tipo    = body.get("tipo", "")
        params  = body.get("params", {})
        comandos = cargar_comandos()
        if hostname not in comandos:
            comandos[hostname] = []
        comandos[hostname].append({
            "id":        datetime.now().strftime("%Y%m%d%H%M%S"),
            "tipo":      tipo,
            "params":    params,
            "estado":    "pendiente",
            "creado_en": datetime.now().isoformat(),
            "ejecutado_en": None,
            "resultado": None
        })
        guardar_comandos(comandos)
        return {"status": "ok", "mensaje": f"Comando {tipo} encolado para {hostname}"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/agente/comandos/{hostname}")
async def obtener_comandos(hostname: str, api_key: str = Depends(verificar_api_key)):
    """El agente Windows consulta si tiene comandos pendientes."""
    comandos = cargar_comandos()
    pendientes = [c for c in comandos.get(hostname, []) if c["estado"] == "pendiente"]
    return {"comandos": pendientes}

@app.post("/agente/comando/{hostname}/{comando_id}/resultado")
async def reportar_resultado(hostname: str, comando_id: str, request: Request, api_key: str = Depends(verificar_api_key)):
    """El agente reporta el resultado de un comando ejecutado."""
    try:
        body = await request.json()
        comandos = cargar_comandos()
        for c in comandos.get(hostname, []):
            if c["id"] == comando_id:
                c["estado"]       = "ejecutado"
                c["ejecutado_en"] = datetime.now().isoformat()
                c["resultado"]    = body.get("resultado", "")
                c["exito"]        = body.get("exito", False)
                break
        guardar_comandos(comandos)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/agente/comandos/{hostname}/historial")
async def historial_comandos(hostname: str, api_key: str = Depends(verificar_api_key)):
    """Historial de todos los comandos ejecutados en un agente."""
    comandos = cargar_comandos()
    return {"comandos": comandos.get(hostname, [])}
