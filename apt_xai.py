"""
Noctua Predictive — Modulo XAI con SHAP
Modulo 5: Explicabilidad de las decisiones del modelo LSTM

Para cada deteccion de campana APT genera un informe que explica:
- Que eventos de la secuencia han contribuido mas a la deteccion
- Con que peso relativo contribuye cada feature
- Por que el modelo clasifica la secuencia en la fase MITRE detectada

Cumple con el Reglamento Europeo de IA (EU AI Act 2024) que exige
explicabilidad en sistemas de ciberseguridad de alto riesgo.
"""

import numpy as np
import torch
import shap
import json
import os
from datetime import datetime
from pathlib import Path
from apt_lstm import NoctuaLSTM, MITRE_PHASES, N_CLASES, cargar_modelo

MODELS_PATH = "/root/asoar/models"
XAI_LOG     = "/root/asoar/xai_explicaciones.json"
Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)

FEATURE_NAMES = [
    "nivel_severidad",
    "fase_mitre",
    "agente_origen",
    "ip_origen",
    "hora_del_dia",
    "dia_semana",
    "horario_nocturno",
    "evento_critico",
    "evento_alto",
]

FEATURE_DESCRIPTIONS = {
    "nivel_severidad":  "Nivel de severidad de la alerta Wazuh (0-15)",
    "fase_mitre":       "Fase MITRE ATT&CK asignada al evento",
    "agente_origen":    "Agente o endpoint que genero el evento",
    "ip_origen":        "Direccion IP de origen del ataque",
    "hora_del_dia":     "Hora del dia en que ocurrio el evento (0-23)",
    "dia_semana":       "Dia de la semana (0=lunes, 6=domingo)",
    "horario_nocturno": "Evento ocurrido entre 00:00 y 06:00",
    "evento_critico":   "Evento con nivel >= 12 (critico)",
    "evento_alto":      "Evento con nivel >= 10 (alto)",
}


class ExplicadorAPT:
    """
    Genera explicaciones SHAP para las decisiones del modelo LSTM.
    Implementa el modulo XAI requerido por el EU AI Act para sistemas
    de ciberseguridad clasificados como de alto riesgo.
    """

    def __init__(self, modelo: NoctuaLSTM = None):
        self.modelo      = modelo or cargar_modelo()
        self.explainer   = None
        self.explicaciones = []
        self._cargar_explicaciones()
        self._inicializar_explainer()

    def _cargar_explicaciones(self):
        if os.path.exists(XAI_LOG):
            try:
                with open(XAI_LOG, "r") as f:
                    self.explicaciones = json.load(f)
            except Exception:
                self.explicaciones = []

    def _guardar_explicaciones(self):
        with open(XAI_LOG, "w") as f:
            json.dump(self.explicaciones[-50:], f, indent=2, default=str)

    def _inicializar_explainer(self):
        """
        Inicializa el explainer SHAP para el modelo LSTM.
        Usa GradientExplainer que es compatible con PyTorch y modelos secuenciales.
        """
        try:
            # Crear datos de referencia (background) con ceros
            # Representa el "estado neutro" sin actividad sospechosa
            background = torch.zeros(1, 32, 9)
            self.explainer = shap.GradientExplainer(self.modelo, background)
            print("[XAI] Explainer SHAP inicializado correctamente.")
        except Exception as e:
            print(f"[XAI] Error inicializando explainer: {e}")
            self.explainer = None

    def explicar_ventana(self, ventana: np.ndarray,
                         fase_predicha: str,
                         confianza: float,
                         contexto: dict = None) -> dict:
        """
        Genera una explicacion SHAP para una ventana de eventos.

        ventana: array (seq_len, n_features)
        fase_predicha: fase MITRE detectada por el LSTM
        confianza: confianza de la prediccion (%)
        contexto: informacion adicional (ip, agente, timestamp)

        Retorna: dict con la explicacion completa
        """
        if self.explainer is None:
            return {"error": "Explainer no disponible"}

        try:
            x = torch.tensor(ventana, dtype=torch.float32).unsqueeze(0)

            # Calcular valores SHAP
            shap_values = self.explainer.shap_values(x)
            sv_all = np.array(shap_values)
            # Shape: (1, seq_len, n_features, n_classes)

            # Obtener indice de la clase predicha
            clase_idx = MITRE_PHASES.index(fase_predicha) if fase_predicha in MITRE_PHASES else 11

            # SHAP values para la clase predicha: (seq_len, n_features)
            sv_clase = sv_all[0, :, :, clase_idx]

            # Importancia por feature (media del valor absoluto sobre toda la secuencia)
            importancia_features = np.abs(sv_clase).mean(axis=0)
            total = importancia_features.sum()
            if total > 0:
                importancia_norm = (importancia_features / total * 100).round(2)
            else:
                importancia_norm = np.zeros_like(importancia_features)

            # Top 3 features mas importantes
            top_idx = np.argsort(importancia_norm)[::-1][:3]
            top_features = [
                {
                    "feature":     FEATURE_NAMES[i],
                    "descripcion": FEATURE_DESCRIPTIONS[FEATURE_NAMES[i]],
                    "importancia": float(importancia_norm[i]),
                }
                for i in top_idx
            ]

            # Importancia por paso temporal (que momentos de la secuencia son mas relevantes)
            importancia_temporal = np.abs(sv_clase).sum(axis=1)
            total_t = importancia_temporal.sum()
            if total_t > 0:
                importancia_temporal_norm = (importancia_temporal / total_t * 100).round(2)
            else:
                importancia_temporal_norm = np.zeros_like(importancia_temporal)

            # Top 3 momentos mas relevantes de la secuencia
            top_t_idx = np.argsort(importancia_temporal_norm)[::-1][:3]
            momentos_criticos = [
                {
                    "posicion":    int(i),
                    "descripcion": f"Evento en posicion {i+1} de la secuencia",
                    "importancia": float(importancia_temporal_norm[i]),
                }
                for i in top_t_idx
            ]

            # Generar narrativa explicativa
            narrativa = self._generar_narrativa(
                fase_predicha, confianza, top_features, momentos_criticos, contexto
            )

            explicacion = {
                "timestamp":          datetime.now().isoformat(),
                "fase_detectada":     fase_predicha,
                "confianza":          confianza,
                "importancia_features": {
                    FEATURE_NAMES[i]: float(importancia_norm[i])
                    for i in range(len(FEATURE_NAMES))
                },
                "top_features":       top_features,
                "momentos_criticos":  momentos_criticos,
                "narrativa":          narrativa,
                "contexto":           contexto or {},
                "cumplimiento_eu_ai_act": True,
            }

            # Persistir explicacion
            self.explicaciones.append(explicacion)
            self._guardar_explicaciones()

            return explicacion

        except Exception as e:
            print(f"[XAI] Error generando explicacion: {e}")
            return {"error": str(e), "fase_detectada": fase_predicha}

    def _generar_narrativa(self, fase: str, confianza: float,
                           top_features: list, momentos: list,
                           contexto: dict = None) -> str:
        """
        Genera una narrativa en lenguaje natural explicando la decision del modelo.
        """
        f1 = top_features[0]["feature"] if top_features else "desconocido"
        p1 = top_features[0]["importancia"] if top_features else 0
        f2 = top_features[1]["feature"] if len(top_features) > 1 else None
        p2 = top_features[1]["importancia"] if len(top_features) > 1 else 0

        ip  = contexto.get("ip", "desconocida") if contexto else "desconocida"
        desc_fase = {
            "reconnaissance":      "reconocimiento previo al ataque",
            "initial_access":      "acceso inicial no autorizado",
            "execution":           "ejecucion de codigo malicioso",
            "persistence":         "establecimiento de persistencia",
            "privilege_escalation":"escalada de privilegios",
            "defense_evasion":     "evasion de defensas",
            "credential_access":   "acceso a credenciales",
            "discovery":           "reconocimiento interno de la red",
            "lateral_movement":    "movimiento lateral entre sistemas",
            "collection":          "recopilacion de informacion sensible",
            "exfiltration":        "exfiltracion de datos",
            "unknown":             "actividad sospechosa no clasificada",
        }.get(fase, fase)

        narrativa = (
            f"El modelo LSTM ha detectado una secuencia de eventos consistente con "
            f"{desc_fase} (fase MITRE ATT&CK: {fase}) con una confianza del {confianza}%. "
            f"La caracteristica con mayor peso en esta decision ha sido '{f1}' "
            f"con una contribucion del {p1:.1f}%"
        )

        if f2:
            narrativa += f", seguida de '{f2}' con un {p2:.1f}%"

        narrativa += f". Los eventos mas determinantes se concentran en la posicion "
        narrativa += f"{momentos[0]['posicion']+1} de la secuencia analizada"

        if ip != "desconocida":
            narrativa += f". La actividad proviene de la IP {ip}"

        narrativa += (
            f". Esta explicacion ha sido generada automaticamente por el modulo XAI "
            f"de Noctua Predictive en cumplimiento del Reglamento Europeo de IA (EU AI Act 2024)."
        )

        return narrativa

    def obtener_explicaciones(self, ultimas_n: int = 10) -> list:
        """Devuelve las ultimas N explicaciones generadas."""
        return self.explicaciones[-ultimas_n:]

    def resumen_importancia_global(self) -> dict:
        """
        Calcula la importancia media de cada feature sobre todas las explicaciones.
        Util para entender que patrones son mas relevantes globalmente.
        """
        if not self.explicaciones:
            return {}

        totales = {f: 0.0 for f in FEATURE_NAMES}
        n = 0
        for exp in self.explicaciones:
            if "importancia_features" in exp:
                for f, v in exp["importancia_features"].items():
                    if f in totales:
                        totales[f] += v
                n += 1

        if n == 0:
            return {}

        return {f: round(v / n, 2) for f, v in totales.items()}


# Instancia global del explicador
explicador_apt = None

def obtener_explicador() -> ExplicadorAPT:
    """Devuelve la instancia global del explicador (singleton)."""
    global explicador_apt
    if explicador_apt is None:
        try:
            explicador_apt = ExplicadorAPT()
        except Exception as e:
            print(f"[XAI] No se pudo inicializar el explicador: {e}")
    return explicador_apt


if __name__ == "__main__":
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Modulo XAI con SHAP")
    print("="*60)

    # Cargar datos del pipeline
    X_path = f"{MODELS_PATH}/X_pipeline.npy"
    if not os.path.exists(X_path):
        print("ERROR: Ejecuta primero apt_pipeline.py")
        exit(1)

    X = np.load(X_path)
    print(f"Datos cargados: {X.shape}")

    # Inicializar explicador
    explicador = ExplicadorAPT()

    # Generar explicacion para la primera ventana
    print("\n[Test] Generando explicacion para ventana 0...")
    exp = explicador.explicar_ventana(
        ventana=X[0],
        fase_predicha="initial_access",
        confianza=65.0,
        contexto={"ip": "185.220.101.45", "agente": "master"}
    )

    if "error" not in exp:
        print(f"\nFase detectada  : {exp['fase_detectada']}")
        print(f"Confianza       : {exp['confianza']}%")
        print(f"\nTop features:")
        for f in exp["top_features"]:
            print(f"  {f['feature']}: {f['importancia']}%")
        print(f"\nMomentos criticos:")
        for m in exp["momentos_criticos"]:
            print(f"  Posicion {m['posicion']+1}: {m['importancia']}%")
        print(f"\nNarrativa:")
        print(f"  {exp['narrativa']}")
        print(f"\nCumplimiento EU AI Act: {exp['cumplimiento_eu_ai_act']}")
    else:
        print(f"Error: {exp}")

    print("\n[Test] Resumen importancia global:")
    resumen = explicador.resumen_importancia_global()
    for f, v in sorted(resumen.items(), key=lambda x: -x[1]):
        print(f"  {f}: {v}%")

    print("\n" + "="*60)
    print("Modulo XAI completado")
    print(f"Explicaciones guardadas en {XAI_LOG}")
    print("="*60)
