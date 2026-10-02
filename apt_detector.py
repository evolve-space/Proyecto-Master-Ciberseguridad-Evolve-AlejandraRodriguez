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

ZEEK_CONN_LOG = "/opt/zeek/logs/current/conn.log"

def buscar_conexion_zeek(ip: str, timestamp_alerta: str = None, ventana_segundos: int = 30) -> dict:
    """
    Busca una conexion de Zeek correlacionada con una IP dentro de una ventana
    temporal cercana a la alerta. Devuelve los campos relevantes si la encuentra,
    o un diccionario vacio si no hay match (fallback a Suricata/Wazuh).
    """
    try:
        if not os.path.exists(ZEEK_CONN_LOG):
            return {}
        with open(ZEEK_CONN_LOG, "r") as f:
            lineas = f.readlines()
        # Buscar de las mas recientes hacia atras (mas probable el match)
        for linea in reversed(lineas[-2000:]):
            if linea.startswith("#") or not linea.strip():
                continue
            campos = linea.strip().split("\t")
            if len(campos) < 21:
                continue
            orig_h = campos[2]
            resp_h = campos[4]
            if ip not in (orig_h, resp_h):
                continue
            duration_raw = campos[8]
            orig_bytes_raw = campos[9]
            resp_bytes_raw = campos[10]
            orig_pkts_raw = campos[16]
            resp_pkts_raw = campos[18]
            history = campos[15]
            return {
                "duration":    float(duration_raw) if duration_raw != "-" else 0.0,
                "orig_bytes":  float(orig_bytes_raw) if orig_bytes_raw != "-" else 0.0,
                "resp_bytes":  float(resp_bytes_raw) if resp_bytes_raw != "-" else 0.0,
                "orig_pkts":   float(orig_pkts_raw) if orig_pkts_raw != "-" else 0.0,
                "resp_pkts":   float(resp_pkts_raw) if resp_pkts_raw != "-" else 0.0,
                "history":     history if history != "-" else "",
            }
    except Exception:
        pass
    return {}

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
BUFFERS_POR_IP_PATH = "/root/asoar/apt_buffers_por_ip.json"

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
    
    def _guardar_buffers_por_ip(self):
        """Persiste los buffers por IP, actividad y fases en disco."""
        try:
            datos = {
                "buffers": {ip: [v.tolist() for v in vectores] for ip, vectores in self.buffers_por_ip.items()},
                "ultima_actividad": {ip: ts.isoformat() for ip, ts in self.ultima_actividad_ip.items()},
                "fases_por_ip": {ip: list(fases) for ip, fases in self.fases_por_ip.items()},
            }
            with open(BUFFERS_POR_IP_PATH, "w") as f:
                json.dump(datos, f)
        except Exception as e:
            print(f"[APT Detector] Error guardando buffers por IP: {e}")

    def _cargar_buffers_por_ip(self):
        """Carga los buffers por IP, actividad y fases desde disco al arrancar."""
        if os.path.exists(BUFFERS_POR_IP_PATH):
            try:
                with open(BUFFERS_POR_IP_PATH, "r") as f:
                    datos = json.load(f)
                for ip, vectores in datos.get("buffers", {}).items():
                    self.buffers_por_ip[ip] = [np.array(v, dtype=np.float32) for v in vectores]
                for ip, ts in datos.get("ultima_actividad", {}).items():
                    self.ultima_actividad_ip[ip] = datetime.fromisoformat(ts)
                for ip, fases in datos.get("fases_por_ip", {}).items():
                    self.fases_por_ip[ip] = set(fases)
                print(f"[APT Detector] Buffers por IP restaurados: {len(self.buffers_por_ip)} IPs")
            except Exception as e:
                print(f"[APT Detector] Error cargando buffers por IP: {e}")


    def __init__(self):
        self.modelo    = None
        self.scaler    = None
        self.encoders  = None
        self.buffer    = deque(maxlen=SEQ_LEN)
        self.buffers_por_ip = {}  # {ip: [vectores]} — sin limite, sequencia real por IP
        self.ultima_actividad_ip = {}  # {ip: timestamp} — para limpieza de buffers inactivos
        self.campanas  = []
        self.cargado   = False
        self.fases_por_ip = {}  # Registro de fases detectadas por IP
        self._cargar_modelo()
        self._cargar_campanas()
        self._cargar_buffer()
        self._cargar_buffers_por_ip()

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
        Prioridad de fuentes: 1) Zeek (mas preciso), 2) Suricata flow, 3) Wazuh metadatos.
        """
        ip = alerta.get("ip", "")

        # ── Prioridad 1: Buscar datos de Zeek (mas precisos) ─────────────────
        datos_zeek = buscar_conexion_zeek(ip) if ip else {}

        # ── Detectar si es alerta de Suricata con datos de red ───────────────
        flow     = alerta.get("flow", {})
        tiene_flow = bool(flow and flow.get("pkts_toserver") is not None)
        tiene_zeek = bool(datos_zeek)

        if tiene_zeek:
            # ── Features desde Zeek (fuente mas precisa disponible) ───────────
            duracion       = max(datos_zeek.get("duration", 0.0), 0.001)
            pkts_toserver  = datos_zeek.get("orig_pkts", 0.0)
            pkts_toclient  = datos_zeek.get("resp_pkts", 0.0)
            bytes_toserver = datos_zeek.get("orig_bytes", 0.0)
            bytes_toclient = datos_zeek.get("resp_bytes", 0.0)
            history        = datos_zeek.get("history", "")

            flow_byts_s = (bytes_toserver + bytes_toclient) / duracion
            flow_pkts_s = (pkts_toserver + pkts_toclient) / duracion
            syn_cnt     = 1.0 if "S" in history else 0.0
            ack_cnt     = 1.0 if "A" in history else 0.0

            total_pkts  = pkts_toserver + pkts_toclient
            total_bytes = bytes_toserver + bytes_toclient
            pkt_size_avg = total_bytes / total_pkts if total_pkts > 0 else 0.0
            iat_mean = duracion / total_pkts if total_pkts > 0 else 0.0

            vector = np.array([
                min(duracion / 120.0, 1.0),
                min(pkts_toserver / 1000.0, 1.0),
                min(pkts_toclient / 1000.0, 1.0),
                min(flow_byts_s / 1000000.0, 1.0),
                min(flow_pkts_s / 10000.0, 1.0),
                syn_cnt,
                ack_cnt,
                min(pkt_size_avg / 1500.0, 1.0),
                min(iat_mean / 10.0, 1.0),
            ], dtype=np.float32)
            return vector

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
        Usa buffer independiente por IP, sin limite fijo ni padding artificial.
        """
        if not self.cargado:
            return {"apt_activo": False, "motivo": "Modelo no cargado"}
        
        ip = alerta.get("ip", "")
        vector = self._alerta_a_vector(alerta)
        
        # Buffer independiente por IP — sin padding, secuencia real
        if ip not in self.buffers_por_ip:
            self.buffers_por_ip[ip] = []
        self.buffers_por_ip[ip].append(vector)
        self.ultima_actividad_ip[ip] = datetime.now()
        self._guardar_buffers_por_ip()
        
        # Tambien mantenemos el buffer global para compatibilidad (uso interno/legacy)
        self.buffer.append(vector)
        self._guardar_buffer()
        
        secuencia_ip = self.buffers_por_ip[ip]
        n_eventos_ip = len(secuencia_ip)
        
        # Necesitamos al menos 2 eventos de ESTA IP para evaluar progresion
        if n_eventos_ip < 2:
            return {
                "apt_activo":  False,
                "motivo":      f"Acumulando eventos de {ip} ({n_eventos_ip})",
                "n_eventos":   n_eventos_ip,
            }
        
        # Usar la secuencia REAL de esta IP, sin padding artificial
        ventana = np.array(secuencia_ip, dtype=np.float32)
        
        # Prediccion LSTM con longitud real (el modelo acepta seq_len variable)
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
            "n_eventos":     n_eventos_ip,
            "timestamp":     datetime.now().isoformat(),
            "ip":            alerta.get("ip", ""),
            "agente":        alerta.get("agente", ""),
        }

        # Registrar campana si es activa
        if apt_activo:
            self.campanas.append(analisis)
            self._guardar_campanas()
            print(f"[APT DETECTADO] Fase: {fase} | Confianza: {confianza}% | Riesgo: {nivel_riesgo}")
            
            # Generar explicacion XAI para esta deteccion
            try:
                import sys
                sys.path.insert(0, '/root/asoar')
                from apt_xai import obtener_explicador
                explicador = obtener_explicador()
                if explicador:
                    ventana_xai = np.array(secuencia_ip, dtype=np.float32)
                    explicador.explicar_ventana(
                        ventana=ventana_xai,
                        fase_predicha=fase,
                        confianza=confianza,
                        contexto={"ip": ip, "agente": alerta.get("agente","")}
                    )
                    print(f"[XAI] Explicacion generada para fase {fase} (secuencia real: {n_eventos_ip} eventos)")
            except Exception as ex:
                print(f"[XAI] Error generando explicacion: {ex}")

            # Crear ticket SOC automaticamente — solo si no hay uno activo para esta IP
            try:
                from apt_tickets import crear_ticket, _cargar
                ip = alerta.get("ip", "")
                if ip and ip not in ["", "desconocida", "0.0.0.0"]:
                    data = _cargar()
                    tickets_activos = [t for t in data.get("tickets", [])
                                      if t.get("ip") == ip
                                      and t.get("estado") in ["Abierto", "Investigando"]
                                      and (datetime.now() - datetime.fromisoformat(t["creado_en"].replace("Z","").split("+")[0])).total_seconds() < 7200]
                    abuse_score_detector = alerta.get("abuse_score", 0)
                    if not tickets_activos and abuse_score_detector < 50:
                        # Indicio de comportamiento anomalo detectado SOLO por el LSTM,
                        # sin respaldo de reputacion externa (AbuseIPDB < 50).
                        # No es una APT confirmada: es una senal de vigilancia temprana.
                        try:
                            titulo_bajo = f"Indicio de comportamiento anomalo (LSTM) — {fase.upper()} desde {ip}"
                            crear_ticket(
                                titulo=titulo_bajo,
                                descripcion=f"El motor LSTM ha clasificado esta secuencia de eventos en fase {fase} "
                                           f"con una confianza del {confianza}%, sin respaldo de reputacion externa "
                                           f"previa (AbuseIPDB: {abuse_score_detector}%). "
                                           f"Secuencia de {n_eventos_ip} eventos analizados (secuencia real, sin padding). "
                                           f"Se trata de una deteccion temprana de comportamiento, no de una campana APT confirmada; "
                                           f"requiere seguimiento para confirmar si la actividad persiste o escala de fase.",
                                prioridad="BAJA",
                                ip=ip,
                                fase_mitre=fase,
                                confianza=confianza,
                                abuse_score=abuse_score_detector,
                                abuse_pais="",
                                abuse_isp=""
                            )
                            print(f"[TICKET] Ticket de BAJA prioridad creado (LSTM puro, sin reputacion) para IP {ip}")
                        except Exception as eb:
                            print(f"[TICKET] Error creando ticket de baja prioridad: {eb}")
                    elif not tickets_activos and abuse_score_detector >= 50:
                        # Verificar cache de IPs bloqueadas antes de crear ticket
                        try:
                            import json as _json
                            with open("/root/asoar/blocked_ips_cache.json") as _f:
                                _cache_bloqueadas = set(_json.load(_f))
                        except:
                            _cache_bloqueadas = set()
                        
                        if ip in _cache_bloqueadas:
                            print(f"[TICKET] IP {ip} ya bloqueada en cache — omitiendo ticket nuevo, anotando deteccion LSTM")
                            try:
                                from apt_tickets import listar_tickets, anadir_nota
                                tickets_ip = [t for t in listar_tickets() if t.get("ip") == ip]
                                if tickets_ip:
                                    ticket_existente = sorted(tickets_ip, key=lambda t: t["creado_en"], reverse=True)[0]
                                    anadir_nota(
                                        ticket_existente["id"],
                                        f"Motor LSTM: deteccion independiente en fase {fase} "
                                        f"con confianza {confianza}% (secuencia de {n_eventos_ip} eventos). "
                                        f"IP ya bloqueada previamente por reputacion AbuseIPDB."
                                    )
                                    print(f"[TICKET] Nota LSTM anadida a {ticket_existente['id']} para IP {ip}")
                            except Exception as en:
                                print(f"[TICKET] Error anadiendo nota LSTM: {en}")
                        else:
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
                            
                            # Título dinámico según fases detectadas
                            if ip not in self.fases_por_ip:
                                self.fases_por_ip[ip] = set()
                            self.fases_por_ip[ip].add(fase)
                            if len(self.fases_por_ip[ip]) >= 2:
                                titulo_ticket = f"Campaña APT detectada — MULTI-FASE desde {ip}"
                            else:
                                titulo_ticket = f"Actividad maliciosa detectada — {fase.upper()} desde {ip}"

                            crear_ticket(
                                titulo=titulo_ticket,
                                descripcion=f"El motor LSTM ha detectado una campana en fase {fase} "
                                           f"con confianza del {confianza}% desde la IP {ip}. "
                                           f"Nivel de riesgo: {nivel_riesgo}. "
                                           f"Secuencia de {n_eventos_ip} eventos analizados. (secuencia real, sin padding). "
                                           f"Reputacion AbuseIPDB: {abuse_score}% | Pais: {abuse_pais} | ISP: {abuse_isp}",
                                prioridad="CRITICA" if nivel_riesgo == "CRITICO" else "ALTA" if nivel_riesgo == "ALTO" else "MEDIA",
                                ip=ip,
                                fase_mitre=fase,
                                confianza=confianza,
                                abuse_score=abuse_score,
                                abuse_pais=abuse_pais,
                                abuse_isp=abuse_isp
                            )
                            print(f"[TICKET] Ticket SOC creado para IP {ip}")
                            # Lanzar playbook automaticamente si AbuseIPDB >= 90%
                            es_multi_fase = len(self.fases_por_ip.get(ip, set())) >= 2
                            if abuse_score_detector >= 90 and not es_multi_fase:
                                try:
                                    cache_file = "/root/asoar/blocked_ips_cache.json"
                                    import json as _json
                                    try:
                                        with open(cache_file) as _f:
                                            _cache = set(_json.load(_f))
                                    except:
                                        _cache = set()
                                    if ip in _cache:
                                        print(f"[PLAYBOOK] IP {ip} ya bloqueada en cache — omitiendo playbook")
                                    else:
                                        import sys
                                        sys.path.insert(0, '/root/asoar')
                                        from main import bloquear_ip_hetzner, actualizar_ticket_por_ip, cargar_playbooks, guardar_playbooks
                                        from datetime import datetime as dt
                                        ejecucion_pb = {
                                            "id": f"PB-AUTO-{ip}",
                                            "playbook": "ip_maliciosa",
                                            "ip": ip,
                                            "timestamp": dt.now().isoformat(),
                                            "estado": "EJECUTANDO",
                                            "acciones": [],
                                            "contexto": {
                                                "fase_mitre": fase,
                                                "confianza": confianza,
                                                "nivel_riesgo": nivel_riesgo,
                                                "abuse_score": abuse_score_detector,
                                                "pais": abuse_pais,
                                                "isp": abuse_isp,
                                                "narrativa": (
                                                    f"El motor LSTM detecto actividad maliciosa en fase {fase.upper()} "
                                                    f"desde la IP {ip} ({abuse_isp}, {abuse_pais}) "
                                                    f"con una confianza del {confianza}% y nivel de riesgo {nivel_riesgo}. "
                                                    f"AbuseIPDB confirma score del {abuse_score_detector}%. "
                                                    f"IP bloqueada automaticamente en Hetzner sin intervencion del analista."
                                                ),
                                            }
                                        }
                                        bloquear_ip_hetzner(ip)
                                        ejecucion_pb["acciones"].append({"accion": "BLOQUEAR_HETZNER", "estado": "OK", "timestamp": dt.now().isoformat()})
                                        actualizar_ticket_por_ip(ip, "ip_maliciosa", ejecucion_pb)
                                        ejecucion_pb["estado"] = "COMPLETADO"
                                        pb_data = cargar_playbooks()
                                        pb_data["ejecuciones"].append(ejecucion_pb)
                                        guardar_playbooks(pb_data)
                                        print(f"[PLAYBOOK] Playbook ip_maliciosa lanzado automaticamente para {ip}")
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
        total_eventos_ips = sum(len(v) for v in self.buffers_por_ip.values())
        return {
            "modelo_cargado":     self.cargado,
            "eventos_en_buffer":  len(self.buffer),
            "ips_monitorizadas":  len(self.buffers_por_ip),
            "total_eventos_ips":  total_eventos_ips,
            "campanas_totales":   len(self.campanas),
            "campanas_24h":       len(campanas_recientes),
            "ultima_campana":     self.campanas[-1] if self.campanas else None,
        }
    
    def limpiar_buffers_inactivos(self, dias_max: int = 7):
        """Elimina buffers de IPs sin actividad reciente para acotar el uso de memoria."""
        limite = datetime.now() - timedelta(days=dias_max)
        ips_a_eliminar = [
            ip for ip, ultima in self.ultima_actividad_ip.items()
            if ultima < limite
        ]
        for ip in ips_a_eliminar:
            self.buffers_por_ip.pop(ip, None)
            self.ultima_actividad_ip.pop(ip, None)
            self.fases_por_ip.pop(ip, None)
        if ips_a_eliminar:
            print(f"[APT Detector] Limpieza: {len(ips_a_eliminar)} buffers de IPs inactivas eliminados")
        return len(ips_a_eliminar)

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
