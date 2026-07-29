"""
Noctua Predictive — Deteccion de Movimiento Lateral
Modulo 6: Correlacion entre agentes para deteccion de APT en red

Detecta cuando un atacante se mueve entre sistemas de la red analizando
patrones de comportamiento correlacionados entre multiples agentes/endpoints.

Indicadores de Movimiento Lateral (MITRE T1021, T1047, T1078):
- Mismo origen intentando acceder a multiples sistemas en corto tiempo
- Autenticacion exitosa seguida de acceso a recursos compartidos
- Ejecucion de comandos de reconocimiento interno (net view, whoami, ipconfig)
- Transferencia de ficheros entre sistemas internos en horario inusual
- Uso de credenciales en multiples sistemas en ventana de tiempo corta
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

LATERAL_LOG = "/root/asoar/lateral_movement.json"
CORRELACION_VENTANA_MIN = 30  # ventana de correlacion en minutos

# Reglas Wazuh que indican posible movimiento lateral
REGLAS_MOVIMIENTO_LATERAL = {
    # Autenticacion remota
    "5501": "acceso_remoto",
    "5502": "acceso_remoto",
    "5503": "acceso_remoto",
    # Acceso a recursos compartidos
    "5301": "recurso_compartido",
    "5302": "recurso_compartido",
    # Escalada de privilegios
    "5401": "escalada_privilegios",
    "5402": "escalada_privilegios",
    # Ejecucion remota
    "5601": "ejecucion_remota",
    "5602": "ejecucion_remota",
    # Autenticacion exitosa tras fallos
    "5710": "brute_force_exitoso",
    "5711": "brute_force_exitoso",
    "5712": "brute_force_exitoso",
}

# Patrones de movimiento lateral conocidos (secuencias de eventos)
PATRONES_LATERAL = {
    "pass_the_hash": {
        "descripcion": "Posible Pass-the-Hash: autenticacion con hash NTLM en multiples sistemas",
        "severidad": "CRITICO",
        "mitre": "T1550.002",
    },
    "lateral_smb": {
        "descripcion": "Movimiento lateral via SMB: acceso a recursos compartidos desde sistema comprometido",
        "severidad": "ALTO",
        "mitre": "T1021.002",
    },
    "credential_reuse": {
        "descripcion": "Reutilizacion de credenciales: mismas credenciales usadas en multiples sistemas",
        "severidad": "ALTO",
        "mitre": "T1078",
    },
    "internal_recon": {
        "descripcion": "Reconocimiento interno: escaneo de red desde sistema comprometido",
        "severidad": "MEDIO",
        "mitre": "T1046",
    },
}


class DetectorMovimientoLateral:
    """
    Detecta movimiento lateral correlacionando eventos entre multiples agentes.

    Mantiene un buffer temporal de eventos por IP origen y detecta cuando
    una misma IP interactua con multiples agentes en una ventana de tiempo.
    """

    def __init__(self):
        # Buffer: ip_origen -> lista de (timestamp, agente, tipo_evento)
        self.buffer_ip = defaultdict(lambda: deque(maxlen=50))
        # Buffer: agente -> lista de (timestamp, ip, tipo_evento)
        self.buffer_agente = defaultdict(lambda: deque(maxlen=100))
        # Detecciones registradas
        self.detecciones = []
        self._cargar_detecciones()

    def _cargar_detecciones(self):
        if os.path.exists(LATERAL_LOG):
            try:
                with open(LATERAL_LOG, "r") as f:
                    self.detecciones = json.load(f)
            except Exception:
                self.detecciones = []

    def _guardar_detecciones(self):
        with open(LATERAL_LOG, "w") as f:
            json.dump(self.detecciones[-100:], f, indent=2, default=str)

    def registrar_evento(self, alerta: dict) -> dict:
        """
        Registra un nuevo evento y evalua si hay movimiento lateral.

        alerta: dict con ip, agente, rule_id, nivel, timestamp
        Retorna: dict con resultado del analisis de movimiento lateral
        """
        ip      = alerta.get("ip", "0.0.0.0")
        agente  = alerta.get("agente", "master")
        rule_id = str(alerta.get("rule_id", "0"))
        nivel   = int(alerta.get("nivel", 0))
        ahora   = datetime.now()

        tipo_evento = REGLAS_MOVIMIENTO_LATERAL.get(rule_id, "generico")

        evento = {
            "timestamp": ahora,
            "agente":    agente,
            "ip":        ip,
            "rule_id":   rule_id,
            "nivel":     nivel,
            "tipo":      tipo_evento,
        }

        # Registrar en buffers
        self.buffer_ip[ip].append(evento)
        self.buffer_agente[agente].append(evento)

        # Analizar patrones
        resultado = self._analizar_movimiento_lateral(ip, agente, ahora)
        return resultado

    def _analizar_movimiento_lateral(self, ip: str, agente_actual: str,
                                      ahora: datetime) -> dict:
        """
        Analiza si hay indicios de movimiento lateral para una IP dada.
        """
        ventana = timedelta(minutes=CORRELACION_VENTANA_MIN)
        eventos_recientes = [
            e for e in self.buffer_ip[ip]
            if ahora - e["timestamp"] <= ventana
        ]

        if not eventos_recientes:
            return {"movimiento_lateral": False}

        # ── Criterio 1: misma IP en multiples agentes ─────────────────────────
        agentes_afectados = list(set(e["agente"] for e in eventos_recientes))
        n_agentes = len(agentes_afectados)

        if n_agentes < 2:
            return {
                "movimiento_lateral": False,
                "n_agentes":          n_agentes,
                "agentes":            agentes_afectados,
            }

        # ── Criterio 2: tipos de eventos que indican movimiento lateral ────────
        tipos_detectados = list(set(e["tipo"] for e in eventos_recientes))
        nivel_max = max(e["nivel"] for e in eventos_recientes)

        # Determinar patron
        patron = "internal_recon"
        if "brute_force_exitoso" in tipos_detectados and n_agentes >= 2:
            patron = "credential_reuse"
        if "recurso_compartido" in tipos_detectados:
            patron = "lateral_smb"
        if "acceso_remoto" in tipos_detectados and n_agentes >= 3:
            patron = "pass_the_hash"

        info_patron = PATRONES_LATERAL[patron]
        severidad   = info_patron["severidad"]

        # ── Criterio 3: calcular confianza ────────────────────────────────────
        confianza = min(100, (
            (n_agentes * 20) +
            (nivel_max * 3) +
            (len(tipos_detectados) * 10) +
            (20 if "brute_force_exitoso" in tipos_detectados else 0)
        ))

        deteccion = {
            "timestamp":         ahora.isoformat(),
            "ip_origen":         ip,
            "agentes_afectados": agentes_afectados,
            "n_agentes":         n_agentes,
            "patron":            patron,
            "descripcion":       info_patron["descripcion"],
            "severidad":         severidad,
            "mitre_tecnica":     info_patron["mitre"],
            "confianza":         confianza,
            "tipos_eventos":     tipos_detectados,
            "nivel_max":         nivel_max,
            "n_eventos":         len(eventos_recientes),
            "movimiento_lateral": True,
        }

        # Registrar si supera umbral de confianza
        if confianza >= 40:
            self.detecciones.append(deteccion)
            self._guardar_detecciones()
            print(f"[MOVIMIENTO LATERAL] IP: {ip} | Agentes: {agentes_afectados} | "
                  f"Patron: {patron} | Confianza: {confianza}%")

        return deteccion

    def obtener_detecciones(self, ultimas_n: int = 20) -> list:
        """Devuelve las ultimas N detecciones de movimiento lateral."""
        return self.detecciones[-ultimas_n:]

    def obtener_estado(self) -> dict:
        """Estado actual del detector de movimiento lateral."""
        ahora = datetime.now()
        recientes_24h = [
            d for d in self.detecciones
            if datetime.fromisoformat(d["timestamp"]) > ahora - timedelta(hours=24)
        ]
        ips_activas = len(self.buffer_ip)
        return {
            "detecciones_totales": len(self.detecciones),
            "detecciones_24h":     len(recientes_24h),
            "ips_monitorizadas":   ips_activas,
            "ultima_deteccion":    self.detecciones[-1] if self.detecciones else None,
        }

    def limpiar_buffers_antiguos(self):
        """Elimina eventos del buffer mas antiguos que la ventana de correlacion."""
        ahora = datetime.now()
        ventana = timedelta(minutes=CORRELACION_VENTANA_MIN * 2)
        for ip in list(self.buffer_ip.keys()):
            self.buffer_ip[ip] = deque(
                [e for e in self.buffer_ip[ip] if ahora - e["timestamp"] <= ventana],
                maxlen=50
            )
        for agente in list(self.buffer_agente.keys()):
            self.buffer_agente[agente] = deque(
                [e for e in self.buffer_agente[agente] if ahora - e["timestamp"] <= ventana],
                maxlen=100
            )


# Instancia global
detector_lateral = DetectorMovimientoLateral()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Detector de Movimiento Lateral")
    print("="*60)

    # Simular secuencia de movimiento lateral
    print("\n[Test] Simulando movimiento lateral desde 10.0.0.100...")

    ip_atacante = "10.0.0.100"
    agentes = ["servidor-web", "servidor-bbdd", "workstation-01"]

    eventos_simulados = [
        {"ip": ip_atacante, "agente": agentes[0], "rule_id": "5712", "nivel": 10},
        {"ip": ip_atacante, "agente": agentes[0], "rule_id": "5502", "nivel": 8},
        {"ip": ip_atacante, "agente": agentes[1], "rule_id": "5301", "nivel": 9},
        {"ip": ip_atacante, "agente": agentes[1], "rule_id": "5502", "nivel": 8},
        {"ip": ip_atacante, "agente": agentes[2], "rule_id": "5401", "nivel": 11},
    ]

    for i, evento in enumerate(eventos_simulados):
        print(f"\n  Evento {i+1}: IP {evento['ip']} -> Agente {evento['agente']} (regla {evento['rule_id']})")
        resultado = detector_lateral.registrar_evento(evento)
        if resultado.get("movimiento_lateral"):
            print(f"  DETECCION: {resultado['descripcion']}")
            print(f"  Severidad: {resultado['severidad']} | Confianza: {resultado['confianza']}%")
            print(f"  MITRE: {resultado['mitre_tecnica']} | Agentes: {resultado['agentes_afectados']}")

    print("\n[Test] Estado del detector:")
    estado = detector_lateral.obtener_estado()
    for k, v in estado.items():
        if k != "ultima_deteccion":
            print(f"  {k}: {v}")

    print("\n" + "="*60)
    print("Test completado")
    print("="*60)
