"""
apt_tickets.py — Sistema de Gestion de Incidentes SOC
Noctua Predictive — Tickets integrados con LSTM, XAI y AbuseIPDB
"""
import json
import os
from datetime import datetime, timezone
from typing import Optional

TICKETS_FILE = "/root/asoar/tickets.json"

PRIORIDADES = ["CRITICA", "ALTA", "MEDIA", "BAJA"]
ESTADOS = ["Abierto", "Investigando", "Contenido", "Resuelto", "Cerrado"]

def _cargar():
    if os.path.exists(TICKETS_FILE):
        try:
            with open(TICKETS_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {"tickets": [], "contador": 0}

def _guardar(data):
    with open(TICKETS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _ahora():
    return datetime.now(timezone.utc).isoformat()

def crear_ticket(
    titulo: str,
    descripcion: str,
    ip: str = "",
    fase_mitre: str = "",
    confianza: float = 0.0,
    prioridad: str = "MEDIA",
    origen: str = "manual",
    xai_narrativa: str = "",
    xai_features: list = None,
    abuse_score: int = 0,
    abuse_pais: str = "",
    abuse_isp: str = "",
    campana_id: str = "",
) -> dict:
    data = _cargar()
    data["contador"] += 1
    ticket_id = f"NTC-{data['contador']:04d}"
    ahora = _ahora()

    ticket = {
        "id":            ticket_id,
        "titulo":        titulo,
        "descripcion":   descripcion,
        "estado":        "Abierto",
        "prioridad":     prioridad,
        "ip":            ip,
        "fase_mitre":    fase_mitre,
        "confianza":     confianza,
        "origen":        origen,
        "xai_narrativa": xai_narrativa,
        "xai_features":  xai_features or [],
        "abuse_score":   abuse_score,
        "abuse_pais":    abuse_pais,
        "abuse_isp":     abuse_isp,
        "campana_id":    campana_id,
        "notas":         [],
        "historial":     [{"estado": "Abierto", "timestamp": ahora, "nota": "Ticket creado"}],
        "creado_en":     ahora,
        "actualizado_en": ahora,
        "resuelto_en":   None,
    }

    data["tickets"].append(ticket)
    _guardar(data)
    return ticket

def listar_tickets(estado: str = None, prioridad: str = None, limit: int = 100) -> list:
    data = _cargar()
    tickets = data["tickets"]
    if estado:
        tickets = [t for t in tickets if t["estado"] == estado]
    if prioridad:
        tickets = [t for t in tickets if t["prioridad"] == prioridad]
    return sorted(tickets, key=lambda x: x["creado_en"], reverse=True)[:limit]

def obtener_ticket(ticket_id: str) -> Optional[dict]:
    data = _cargar()
    for t in data["tickets"]:
        if t["id"] == ticket_id:
            return t
    return None

def actualizar_estado(ticket_id: str, nuevo_estado: str, nota: str = "") -> Optional[dict]:
    if nuevo_estado not in ESTADOS:
        return None
    data = _cargar()
    ahora = _ahora()
    for t in data["tickets"]:
        if t["id"] == ticket_id:
            t["estado"] = nuevo_estado
            t["actualizado_en"] = ahora
            if nuevo_estado in ["Resuelto", "Cerrado"]:
                t["resuelto_en"] = ahora
            t["historial"].append({
                "estado":    nuevo_estado,
                "timestamp": ahora,
                "nota":      nota or f"Estado cambiado a {nuevo_estado}"
            })
            _guardar(data)
            return t
    return None

def anadir_nota(ticket_id: str, nota: str) -> Optional[dict]:
    data = _cargar()
    ahora = _ahora()
    for t in data["tickets"]:
        if t["id"] == ticket_id:
            t["notas"].append({"texto": nota, "timestamp": ahora})
            t["actualizado_en"] = ahora
            _guardar(data)
            return t
    return None

def metricas_tickets() -> dict:
    data = _cargar()
    tickets = data["tickets"]
    if not tickets:
        return {
            "total": 0, "abiertos": 0, "investigando": 0,
            "contenidos": 0, "resueltos": 0, "cerrados": 0,
            "mttr_horas": 0, "sla_24h_pct": 0,
            "por_fase": {}, "por_prioridad": {}
        }

    abiertos     = [t for t in tickets if t["estado"] == "Abierto"]
    investigando = [t for t in tickets if t["estado"] == "Investigando"]
    contenidos   = [t for t in tickets if t["estado"] == "Contenido"]
    resueltos    = [t for t in tickets if t["estado"] in ["Resuelto", "Cerrado"]]

    # MTTR
    tiempos = []
    sla_ok  = 0
    for t in resueltos:
        if t.get("resuelto_en") and t.get("creado_en"):
            try:
                creado   = datetime.fromisoformat(t["creado_en"])
                resuelto = datetime.fromisoformat(t["resuelto_en"])
                horas    = (resuelto - creado).total_seconds() / 3600
                tiempos.append(horas)
                if horas <= 24:
                    sla_ok += 1
            except:
                pass

    mttr = round(sum(tiempos) / len(tiempos), 1) if tiempos else 0
    sla_pct = round((sla_ok / len(resueltos)) * 100, 1) if resueltos else 0

    # Por fase MITRE
    por_fase = {}
    for t in tickets:
        fase = t.get("fase_mitre", "unknown") or "unknown"
        por_fase[fase] = por_fase.get(fase, 0) + 1

    # Por prioridad
    por_prioridad = {}
    for t in tickets:
        p = t.get("prioridad", "MEDIA")
        por_prioridad[p] = por_prioridad.get(p, 0) + 1

    return {
        "total":        len(tickets),
        "abiertos":     len(abiertos),
        "investigando": len(investigando),
        "contenidos":   len(contenidos),
        "resueltos":    len(resueltos),
        "mttr_horas":   mttr,
        "sla_24h_pct":  sla_pct,
        "por_fase":     por_fase,
        "por_prioridad": por_prioridad,
    }

def ticket_desde_campana(campana: dict, xai: dict = None, abuse: dict = None) -> dict:
    """Crea un ticket automaticamente desde una deteccion APT del LSTM."""
    fase     = campana.get("fase_mitre", "unknown")
    conf     = campana.get("confianza", 0)
    ip       = campana.get("ip", "")
    riesgo   = campana.get("nivel_riesgo", "MEDIO")

    prioridad_map = {"CRITICO": "CRITICA", "ALTO": "ALTA", "MEDIO": "MEDIA", "BAJO": "BAJA"}
    prioridad = prioridad_map.get(riesgo, "MEDIA")

    titulo = f"APT Detectada — {fase.replace('_',' ').upper()} desde {ip}"
    descripcion = (
        f"El motor LSTM de Noctua Predictive ha detectado una campana APT activa. "
        f"Fase MITRE: {fase} | Confianza: {conf}% | IP origen: {ip} | "
        f"Nivel de riesgo: {riesgo}. Se requiere investigacion inmediata."
    )

    xai_narrativa = xai.get("narrativa", "") if xai else ""
    xai_features  = xai.get("top_features", []) if xai else []
    abuse_score   = abuse.get("score", 0) if abuse else 0
    abuse_pais    = abuse.get("pais", "") if abuse else ""
    abuse_isp     = abuse.get("isp", "") if abuse else ""

    return crear_ticket(
        titulo=titulo,
        descripcion=descripcion,
        ip=ip,
        fase_mitre=fase,
        confianza=conf,
        prioridad=prioridad,
        origen="automatico_lstm",
        xai_narrativa=xai_narrativa,
        xai_features=xai_features,
        abuse_score=abuse_score,
        abuse_pais=abuse_pais,
        abuse_isp=abuse_isp,
        campana_id=campana.get("id", ""),
    )
