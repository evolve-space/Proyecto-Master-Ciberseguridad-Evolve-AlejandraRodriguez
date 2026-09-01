"""
Noctua Predictive — Detector de Campanas APT
Modulo 3: Integra el LSTM con FastAPI para deteccion en tiempo real

Este modulo mantiene un buffer de eventos recientes y cada vez que llega
una nueva alerta de Wazuh evalua si la secuencia acumulada corresponde
a una campana APT activa.
"""

import numpy as np
import torch
import pickle
import json
import os
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path
from apt_lstm import NoctuaLSTM, MITRE_PHASES, predecir_ventana

MODELS_PATH = "/root/asoar/models"
APT_LOG     = "/root/asoar/apt_campanas.json"
SEQ_LEN     = 32

# Fases que indican una campana APT activa y su nivel de riesgo
FASE_RIESGO = {
    "reconnaissance":      "BAJO",
    "initial_access":      "MEDIO",
    "execution":           "MEDIO",
    "persistence":         "ALTO",
    "privilege_escalation":"CRITICO",
    "defense_evasion":     "ALTO",
    "credential_access":   "ALTO",
    "discovery":           "MEDIO",
    "lateral_movement":    "CRITICO",
    "collection":          "ALTO",
    "exfiltration":        "CRITICO",
    "unknown":             "BAJO",
}

# Orden de progresion APT (de menor a mayor gravedad)
PROGRESION_APT = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
]

BUFFER_PATH = "/root/asoar/apt_buffer.json"

class DetectorAPT:
    """
    Detector de campanas APT en tiempo real.
    Mantiene un buffer deslizante de eventos y evalua cada nueva alerta.
    """

    def _guardar_buffer(self):
        """Persiste el buffer en disco para sobrevivir reinicios."""
        try:
            with open(BUFFER_PATH, "w") as f:
                json.dump([v.tolist() for v in self.buffer], f)
        except Exception:
            pass

    def _cargar_buffer(self):
        """Carga el buffer desde disco al arrancar."""
        if os.path.exists(BUFFER_PATH):
            try:
                with open(BUFFER_PATH, "r") as f:
                    datos = json.load(f)
                for v in datos:
                    self.buffer.append(np.array(v, dtype=np.float32))
                print(f"[APT Detector] Buffer restaurado: {len(self.buffer)} eventos")
            except Exception:
                pass

    def __init__(self):
        self.modelo    = None
        self.scaler    = None
        self.encoders  = None
        self.buffer    = deque(maxlen=SEQ_LEN)
        self.campanas  = []
        self.cargado   = False
        self._cargar_modelo()
        self._cargar_campanas()
        self._cargar_buffer()

    def _cargar_modelo(self):
        """Carga el modelo LSTM y los preprocesadores desde disco."""
        modelo_path  = f"{MODELS_PATH}/lstm_noctua.pt"
        scaler_path  = f"{MODELS_PATH}/scaler.pkl"
        encoder_path = f"{MODELS_PATH}/label_encoders.pkl"

        if not os.path.exists(modelo_path):
            print("[APT Detector] Modelo no encontrado. Ejecuta apt_lstm.py primero.")
            return

        try:
            checkpoint = torch.load(modelo_path, map_location="cpu")
            self.modelo = NoctuaLSTM(
                n_features=checkpoint["n_features"],
                hidden_size=checkpoint["hidden_size"],
                n_layers=checkpoint["n_layers"],
                n_classes=checkpoint["n_classes"],
            )
            self.modelo.load_state_dict(checkpoint["model_state"])
            self.modelo.eval()

            if os.path.exists(scaler_path):
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)

            if os.path.exists(encoder_path):
                with open(encoder_path, "rb") as f:
                    self.encoders = pickle.load(f)

            self.cargado = True
            print("[APT Detector] Modelo LSTM cargado correctamente.")

        except Exception as e:
            print(f"[APT Detector] Error cargando modelo: {e}")

    def _cargar_campanas(self):
        """Carga el historial de campanas APT detectadas."""
        if os.path.exists(APT_LOG):
            try:
                with open(APT_LOG, "r") as f:
                    self.campanas = json.load(f)
            except Exception:
                self.campanas = []

    def _guardar_campanas(self):
        """Persiste el historial de campanas."""
        with open(APT_LOG, "w") as f:
            json.dump(self.campanas[-500:], f, indent=2, default=str)

    def _alerta_a_vector(self, alerta: dict) -> np.ndarray:
        """
        Convierte una alerta en un vector de 9 features.
        Si la alerta tiene datos de Suricata (features de red reales),
        usa el mismo espacio de features que CICIDS2018.
        Si no, usa features de metadatos de Wazuh como fallback.
        """
        # ── Detectar si es alerta de Suricata con datos de red ───────────────
        flow     = alerta.get("flow", {})
        tiene_flow = bool(flow and flow.get("pkts_toserver") is not None)

        if tiene_flow:
            # ── Features de red reales (equivalente a CICIDS2018) ─────────────
            pkts_toserver   = float(flow.get("pkts_toserver", 0))
            pkts_toclient   = float(flow.get("pkts_toclient", 0))
            bytes_toserver  = float(flow.get("bytes_toserver", 0))
            bytes_toclient  = float(flow.get("bytes_toclient", 0))

            # Duracion del flujo en segundos
            try:
                from datetime import datetime as dt
                start = dt.fromisoformat(flow.get("start","").replace("Z","+00:00"))
                end   = dt.fromisoformat(flow.get("end", flow.get("start","")).replace("Z","+00:00"))
                duracion = max((end - start).total_seconds(), 0.001)
            except Exception:
                duracion = 1.0

            # Bytes por segundo
            flow_byts_s = (bytes_toserver + bytes_toclient) / duracion
            flow_pkts_s = (pkts_toserver + pkts_toclient) / duracion

            # Flags TCP
            tcp         = alerta.get("tcp", {})
            syn_cnt     = 1.0 if tcp.get("syn") else 0.0
            ack_cnt     = 1.0 if tcp.get("ack") else 0.0

            # Tamano medio de paquete
            total_pkts  = pkts_toserver + pkts_toclient
            total_bytes = bytes_toserver + bytes_toclient
            pkt_size_avg = total_bytes / total_pkts if total_pkts > 0 else 0.0

            # IAT aproximado (duracion / paquetes)
            iat_mean = duracion / total_pkts if total_pkts > 0 else 0.0

            # Normalizar — mismos rangos que CICIDS2018
            vector = np.array([
                min(duracion / 120.0, 1.0),          # Flow Duration norm (max 2 min)
                min(pkts_toserver / 1000.0, 1.0),    # Tot Fwd Pkts norm
                min(pkts_toclient / 1000.0, 1.0),    # Tot Bwd Pkts norm
                min(flow_byts_s / 1000000.0, 1.0),   # Flow Byts/s norm (max 1MB/s)
                min(flow_pkts_s / 10000.0, 1.0),     # Flow Pkts/s norm
                syn_cnt,                              # SYN Flag Cnt
                ack_cnt,                              # ACK Flag Cnt
                min(pkt_size_avg / 1500.0, 1.0),     # Pkt Size Avg norm (max MTU)
                min(iat_mean / 10.0, 1.0),            # Flow IAT Mean norm
            ], dtype=np.float32)

        else:
            # ── Fallback: features de metadatos Wazuh ────────────────────────
            rule_id    = str(alerta.get("rule_id", "0"))
            nivel      = float(alerta.get("nivel", 0))
            ip         = alerta.get("ip", "0.0.0.0")
            agente     = alerta.get("agente", "master")
            try:
                partes = ip.split(".")
                ip_num = int(partes[3]) + int(partes[2]) * 256 if len(partes) == 4 else 0
            except Exception:
                ip_num = 0
            ahora       = datetime.now()
            hora_dia    = ahora.hour
            dia_semana  = ahora.weekday()
            es_nocturno = 1 if 0 <= hora_dia <= 6 else 0
            from apt_pipeline import RULE_TO_MITRE, MITRE_PHASES as MP
            fase     = RULE_TO_MITRE.get(rule_id, "unknown")
            fase_idx = MP.index(fase) if fase in MP else len(MP) - 1
            agente_idx = 0
            if self.encoders:
                try:
                    le_agente = self.encoders["agente"]
                    if agente in le_agente.classes_:
                        agente_idx = int(le_agente.transform([agente])[0])
                except Exception:
                    pass
            vector = np.array([
                nivel / 15.0,
                fase_idx,
                agente_idx,
                ip_num / 65535.0,
                hora_dia / 23.0,
                dia_semana / 6.0,
                es_nocturno,
                1.0 if nivel >= 12 else 0.0,
                1.0 if nivel >= 10 else 0.0,
            ], dtype=np.float32)

        # Aplicar scaler CICIDS2018 solo si tiene features de red reales
        if self.scaler and tiene_flow:
            try:
                vector = self.scaler.transform(vector.reshape(1, -1))[0]
            except Exception:
                pass

        return vector

    def procesar_alerta(self, alerta: dict) -> dict:
        """
        Procesa una nueva alerta y evalua si forma parte de una campana APT.

        alerta: dict con rule_id, nivel, ip, agente
        Retorna: dict con resultado del analisis APT
        """
        if not self.cargado:
            return {"apt_activo": False, "motivo": "Modelo no cargado"}

        # Anadir al buffer
        vector = self._alerta_a_vector(alerta)
        self.buffer.append(vector)
        self._guardar_buffer()

        # Necesitamos al menos 8 eventos para una prediccion significativa
        if len(self.buffer) < 8:
            return {
                "apt_activo":  False,
                "motivo":      f"Acumulando eventos ({len(self.buffer)}/{SEQ_LEN})",
                "n_eventos":   len(self.buffer),
            }

        # Construir secuencia con padding si es necesario
        secuencia = list(self.buffer)
        if len(secuencia) < SEQ_LEN:
            pad = [np.zeros(9, dtype=np.float32)] * (SEQ_LEN - len(secuencia))
            secuencia = pad + secuencia
        ventana = np.array(secuencia, dtype=np.float32)

        # Prediccion LSTM
        resultado = predecir_ventana(self.modelo, ventana)
        fase       = resultado["fase_mitre"]
        confianza  = resultado["confianza"]
        nivel_riesgo = FASE_RIESGO.get(fase, "BAJO")

        # Determinar si es una campana APT activa
        apt_activo = (
            fase not in ["unknown", "reconnaissance"] and
            confianza > 5.0
        ) or (
            fase in ["lateral_movement", "exfiltration", "privilege_escalation"] and
            confianza > 15.0
        )

        analisis = {
            "apt_activo":    apt_activo,
            "fase_mitre":    fase,
            "confianza":     confianza,
            "nivel_riesgo":  nivel_riesgo,
            "n_eventos":     len(self.buffer),
            "timestamp":     datetime.now().isoformat(),
            "ip":            alerta.get("ip", ""),
            "agente":        alerta.get("agente", ""),
        }

        # Registrar campana si es activa
        if apt_activo:
            self.campanas.append(analisis)
            self._guardar_campanas()
            print(f"[APT DETECTADO] Fase: {fase} | Confianza: {confianza}% | Riesgo: {nivel_riesgo}")
            # Crear ticket SOC automaticamente — solo si no hay uno activo para esta IP
            try:
                from apt_tickets import crear_ticket, _cargar
                ip = alerta.get("ip", "")
                if ip and ip not in ["", "desconocida", "0.0.0.0"]:
                    data = _cargar()
                    tickets_activos = [t for t in data.get("tickets", [])
                                      if t.get("ip") == ip
                                      and t.get("estado") in ["Abierto", "Investigando"]
                                      and (datetime.now() - datetime.fromisoformat(t["creado_en"].replace("Z","").split("+")[0])).seconds < 7200]
                    abuse_score_detector = alerta.get("abuse_score", 0)
                    if not tickets_activos and abuse_score_detector >= 50:
                        # Enriquecer con AbuseIPDB
                        abuse_score = 0
                        abuse_pais = ""
                        abuse_isp = ""
                        try:
                            import requests as req
                            r = req.get(
                                "https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": open('/root/asoar/.env').read().split('ABUSEIPDB_API_KEY=')[1].split('\n')[0], "Accept": "application/json"},
                                params={"ipAddress": ip, "maxAgeInDays": 90},
                                timeout=5
                            )
                            if r.status_code == 200:
                                d = r.json().get("data", {})
                                abuse_score = d.get("abuseConfidenceScore", 0)
                                abuse_pais = d.get("countryCode", "")
                                abuse_isp = d.get("isp", "")
                        except:
                            pass
                        crear_ticket(
                            titulo=f"Campaña APT detectada — {fase.upper()} desde {ip}",
                            descripcion=f"El motor LSTM ha detectado una campaña APT en fase {fase} "
                                       f"con confianza del {confianza}% desde la IP {ip}. "
                                       f"Nivel de riesgo: {nivel_riesgo}. "
                                       f"Secuencia de {len(self.buffer)} eventos analizados. "
                                       f"Reputación AbuseIPDB: {abuse_score}% | País: {abuse_pais} | ISP: {abuse_isp}",
                            prioridad="CRITICA" if nivel_riesgo == "CRITICO" else "ALTA" if nivel_riesgo == "ALTO" else "MEDIA",
                            ip=ip,
                            fase_mitre=fase,
                            confianza=confianza,
                            abuse_score=abuse_score,
                            abuse_pais=abuse_pais,
                            abuse_isp=abuse_isp
                        )
                        print(f"[TICKET] Ticket SOC creado para IP {ip}")
                        # Lanzar playbook automáticamente si AbuseIPDB >= 90%
                        if abuse_score_detector >= 90:
                            try:
                                import requests as req
                                ticket_creado = _cargar()
                                ticket_id_nuevo = ""
                                for t in ticket_creado.get("tickets", []):
                                    if t.get("ip") == ip and t.get("estado") == "Abierto":
                                        ticket_id_nuevo = t.get("id", "")
                                        break
                                import sys
                                sys.path.insert(0, '/root/asoar')
                                from main import bloquear_ip_hetzner, actualizar_ticket_por_ip, cargar_playbooks, guardar_playbooks
                                from datetime import datetime as dt
                                ejecucion_pb = {
                                    "id": f"PB-AUTO-{ip}",
                                    "playbook": "apt_campaign",
                                    "ip": ip,
                                    "timestamp": dt.now().isoformat(),
                                    "estado": "EJECUTANDO",
                                    "acciones": []
                                }
                                bloquear_ip_hetzner(ip)
                                ejecucion_pb["acciones"].append({"accion": "BLOQUEAR_HETZNER", "estado": "OK", "timestamp": dt.now().isoformat()})
                                actualizar_ticket_por_ip(ip, "apt_campaign", ejecucion_pb)
                                ejecucion_pb["estado"] = "COMPLETADO"
                                pb_data = cargar_playbooks()
                                pb_data["ejecuciones"].append(ejecucion_pb)
                                guardar_playbooks(pb_data)
                                print(f"[PLAYBOOK] Playbook apt_campaign lanzado automáticamente para {ip}")
                            except Exception as ep:
                                print(f"[PLAYBOOK] Error lanzando playbook: {ep}")
                    else:
                        print(f"[TICKET] Ya existe ticket activo para IP {ip} — omitiendo")
            except Exception as e:
                print(f"[TICKET] Error creando ticket: {e}")

        return analisis

    def obtener_estado(self) -> dict:
        """Devuelve el estado actual del detector."""
        campanas_recientes = [
            c for c in self.campanas
            if datetime.fromisoformat(c["timestamp"]) >
               datetime.now() - timedelta(hours=24)
        ]
        return {
            "modelo_cargado":     self.cargado,
            "eventos_en_buffer":  len(self.buffer),
            "campanas_totales":   len(self.campanas),
            "campanas_24h":       len(campanas_recientes),
            "ultima_campana":     self.campanas[-1] if self.campanas else None,
        }

    def obtener_campanas(self, ultimas_n: int = 20) -> list:
        """Devuelve las ultimas N campanas APT detectadas."""
        return self.campanas[-ultimas_n:]

    def limpiar_buffer(self):
        """Limpia el buffer de eventos (util para tests)."""
        self.buffer.clear()


# Instancia global del detector
detector_apt = DetectorAPT()


if __name__ == "__main__":
    print("\n[Test] Estado del detector:")
    estado = detector_apt.obtener_estado()
    for k, v in estado.items():
        print(f"  {k}: {v}")

    print("\n[Test] Procesando alerta simulada de movimiento lateral...")
    alerta_test = {
        "rule_id": "5301",
        "nivel":   12,
        "ip":      "185.220.101.45",
        "agente":  "master",
    }

    # Simular varios eventos para llenar el buffer
    for i in range(10):
        alerta_test["nivel"] = 10 + (i % 3)
        resultado = detector_apt.procesar_alerta(alerta_test)

    print(f"\n[Test] Resultado final:")
    for k, v in resultado.items():
        print(f"  {k}: {v}")
