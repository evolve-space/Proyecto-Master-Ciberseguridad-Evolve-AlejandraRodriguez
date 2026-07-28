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


class DetectorAPT:
    """
    Detector de campanas APT en tiempo real.
    Mantiene un buffer deslizante de eventos y evalua cada nueva alerta.
    """

    def __init__(self):
        self.modelo    = None
        self.scaler    = None
        self.encoders  = None
        self.buffer    = deque(maxlen=SEQ_LEN)
        self.campanas  = []
        self.cargado   = False
        self._cargar_modelo()
        self._cargar_campanas()

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
            json.dump(self.campanas[-100:], f, indent=2, default=str)

    def _alerta_a_vector(self, alerta: dict) -> np.ndarray:
        """
        Convierte una alerta de Wazuh en un vector de features.
        Mismo formato que apt_pipeline.py para consistencia.
        """
        rule_id = str(alerta.get("rule_id", "0"))
        nivel   = float(alerta.get("nivel", 0))
        ip      = alerta.get("ip", "0.0.0.0")
        agente  = alerta.get("agente", "master")

        # IP a numero
        try:
            partes = ip.split(".")
            ip_num = int(partes[3]) + int(partes[2]) * 256 if len(partes) == 4 else 0
        except Exception:
            ip_num = 0

        # Hora actual
        ahora      = datetime.now()
        hora_dia   = ahora.hour
        dia_semana = ahora.weekday()
        es_nocturno = 1 if 0 <= hora_dia <= 6 else 0

        # Fase MITRE
        from apt_pipeline import RULE_TO_MITRE, MITRE_PHASES as MP
        fase = RULE_TO_MITRE.get(rule_id, "unknown")
        fase_idx = MP.index(fase) if fase in MP else len(MP) - 1

        # Agente encoded
        agente_idx = 0
        if self.encoders:
            try:
                le_agente = self.encoders["agente"]
                if agente in le_agente.classes_:
                    agente_idx = int(le_agente.transform([agente])[0])
            except Exception:
                pass

        vector = np.array([
            nivel / 15.0,       # nivel_norm
            fase_idx,           # fase_encoded
            agente_idx,         # agente_encoded
            ip_num / 65535.0,   # ip_num normalizado
            hora_dia / 23.0,    # hora_dia
            dia_semana / 6.0,   # dia_semana
            es_nocturno,        # es_nocturno
            1.0 if nivel >= 12 else 0.0,  # es_critico
            1.0 if nivel >= 10 else 0.0,  # es_alto
        ], dtype=np.float32)

        # Aplicar scaler si disponible
        if self.scaler:
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
            confianza > 30.0
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

        # Registrar campana si es activa y critica
        if apt_activo and nivel_riesgo in ["ALTO", "CRITICO"]:
            self.campanas.append(analisis)
            self._guardar_campanas()
            print(f"[APT DETECTADO] Fase: {fase} | Confianza: {confianza}% | Riesgo: {nivel_riesgo}")

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
