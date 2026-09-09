"""
Noctua Predictive — Pipeline de Series Temporales para Deteccion de APTs
Modulo 1: Ingesta, normalizacion y ventanas temporales de eventos Wazuh

Este modulo lee alertas de Wazuh, las convierte en vectores de caracteristicas
y construye ventanas temporales de 6h, 24h y 7 dias para alimentar el modelo LSTM.
"""

import json
import subprocess
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle
import os

# ── Configuracion ─────────────────────────────────────────────────────────────
WAZUH_LOGS_PATH = "/var/ossec/logs/alerts/"
MODELS_PATH = "/root/asoar/models"
WINDOW_SIZES = {
    "6h":  6 * 60,    # minutos
    "24h": 24 * 60,
    "7d":  7 * 24 * 60
}

# Fases MITRE ATT&CK que detectamos
MITRE_PHASES = [
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
    "unknown"
]

# Mapeo de reglas Wazuh a fases MITRE
RULE_TO_MITRE = {
    # Reconocimiento
    "5501": "reconnaissance",   # Port scan
    "5502": "reconnaissance",
    "5503": "reconnaissance",
    # Acceso inicial
    "5551": "initial_access",   # SSH brute force
    "5552": "initial_access",
    "5710": "initial_access",   # Multiple failed logins
    "5711": "initial_access",
    "5712": "initial_access",
    # Persistencia
    "5902": "persistence",      # New user created
    "5903": "persistence",
    "5904": "persistence",
    # Escalada de privilegios
    "5401": "privilege_escalation",
    "5402": "privilege_escalation",
    # Movimiento lateral
    "5301": "lateral_movement",
    "5302": "lateral_movement",
    # Exfiltracion
    "5601": "exfiltration",
    "5602": "exfiltration",
}

# Clasificacion por palabras clave en la descripcion — cubre alertas Suricata
# agrupadas bajo reglas Wazuh genericas (86610, 86611, 86612)
DESCRIPCION_TO_MITRE = {
    "scan": "reconnaissance",
    "zmap": "reconnaissance",
    "mirai": "initial_access",
    "jaws": "initial_access",
    "shell command execution": "initial_access",
    "webshell": "initial_access",
    "remote code execution": "initial_access",
    "authentication failed": "credential_access",
    "login failed": "credential_access",
    "non-existent user": "credential_access",
    "brute force": "credential_access",
    "integrity checksum changed": "persistence",
    "new port opened": "discovery",
    "netstat": "discovery",
}

def clasificar_por_descripcion(descripcion: str) -> str:
    """Clasifica la fase MITRE a partir de palabras clave en la descripcion."""
    desc_lower = descripcion.lower()
    for palabra, fase in DESCRIPCION_TO_MITRE.items():
        if palabra in desc_lower:
            return fase
    return "unknown"

Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)


# ── 1. Carga de alertas Wazuh ─────────────────────────────────────────────────
def cargar_alertas_wazuh(horas_atras: int = 168) -> pd.DataFrame:
    """
    Lee los logs de alertas de Wazuh de las ultimas N horas.
    Devuelve un DataFrame con los eventos normalizados.
    """
    try:
        result = subprocess.run(
            ["bash", "-c", f"find {WAZUH_LOGS_PATH} -name '*.json' -o -name 'alerts.json' | sort | xargs cat 2>/dev/null"],
            capture_output=True, text=True, timeout=30
        )
        lineas = result.stdout.strip().split("\n")
        alertas = []
        cutoff = datetime.now() - timedelta(hours=horas_atras)

        for linea in lineas:
            if not linea.strip():
                continue
            try:
                a = json.loads(linea)
                ts = pd.to_datetime(a.get("timestamp", ""), utc=True, errors="coerce")
                if pd.isna(ts):
                    continue
                ts = ts.tz_localize(None)
                if ts < cutoff:
                    continue

                rule_id = str(a.get("rule", {}).get("id", "0"))
                nivel = int(a.get("rule", {}).get("level", 0))
                ip = a.get("data", {}).get("srcip",
                     a.get("agent", {}).get("ip", "0.0.0.0"))
                agente = a.get("agent", {}).get("name", "master")
                descripcion = a.get("rule", {}).get("description", "")
                mitre_tacticas = a.get("rule", {}).get("mitre", {}).get("tactic", [])
                mitre_id = a.get("rule", {}).get("mitre", {}).get("id", [])

                fase = RULE_TO_MITRE.get(rule_id, "unknown")
                if mitre_tacticas and fase == "unknown":
                    tactica = mitre_tacticas[0].lower().replace(" ", "_") if mitre_tacticas else "unknown"
                    fase = tactica if tactica in MITRE_PHASES else "unknown"
                if fase == "unknown":
                    fase = clasificar_por_descripcion(descripcion)

                alertas.append({
                    "timestamp":   ts,
                    "rule_id":     rule_id,
                    "nivel":       nivel,
                    "ip":          ip,
                    "agente":      agente,
                    "descripcion": descripcion,
                    "fase_mitre":  fase,
                    "mitre_id":    mitre_id[0] if mitre_id else "",
                })
            except Exception:
                continue

        if not alertas:
            print("[Pipeline] No se encontraron alertas en el rango de tiempo.")
            return pd.DataFrame()

        df = pd.DataFrame(alertas)
        df = df.sort_values("timestamp").reset_index(drop=True)
        print(f"[Pipeline] Cargadas {len(df)} alertas de las ultimas {horas_atras}h")
        return df

    except Exception as e:
        print(f"[Pipeline] Error cargando alertas: {e}")
        return pd.DataFrame()


# ── 2. Extraccion de caracteristicas por evento ───────────────────────────────
def extraer_caracteristicas(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convierte cada alerta en un vector de caracteristicas numericas.
    Estas seran las entradas del modelo LSTM.
    """
    if df.empty:
        return df

    le_fase = LabelEncoder()
    le_fase.fit(MITRE_PHASES)

    le_agente = LabelEncoder()
    le_agente.fit(df["agente"].unique().tolist() + ["unknown"])

    df["fase_encoded"]   = le_fase.transform(df["fase_mitre"].apply(
        lambda x: x if x in MITRE_PHASES else "unknown"
    ))
    df["agente_encoded"] = le_agente.transform(df["agente"].apply(
        lambda x: x if x in le_agente.classes_ else "unknown"
    ))

    # IP como feature numerica (ultimo octeto + hash del prefijo)
    def ip_a_numero(ip):
        try:
            partes = ip.split(".")
            if len(partes) == 4:
                return int(partes[3]) + (int(partes[2]) * 256)
            return 0
        except Exception:
            return 0

    df["ip_num"]       = df["ip"].apply(ip_a_numero)
    df["hora_dia"]     = df["timestamp"].dt.hour
    df["dia_semana"]   = df["timestamp"].dt.dayofweek
    df["es_nocturno"]  = ((df["hora_dia"] >= 0) & (df["hora_dia"] <= 6)).astype(int)
    df["es_critico"]   = (df["nivel"] >= 12).astype(int)
    df["es_alto"]      = (df["nivel"] >= 10).astype(int)
    df["nivel_norm"]   = df["nivel"] / 15.0

    # Guardar encoders para inferencia posterior
    with open(f"{MODELS_PATH}/label_encoders.pkl", "wb") as f:
        pickle.dump({"fase": le_fase, "agente": le_agente}, f)

    print(f"[Pipeline] Caracteristicas extraidas: {len(df.columns)} columnas")
    return df


# ── 3. Construccion de ventanas temporales ────────────────────────────────────
FEATURE_COLS = [
    "nivel_norm", "fase_encoded", "agente_encoded",
    "ip_num", "hora_dia", "dia_semana",
    "es_nocturno", "es_critico", "es_alto"
]

def construir_ventanas(df: pd.DataFrame, ventana_min: int = 360,
                       paso_min: int = 60, seq_len: int = 32):
    """
    Construye secuencias de eventos para el LSTM.

    - ventana_min: duracion de cada ventana en minutos (360 = 6h)
    - paso_min: desplazamiento entre ventanas (60 = 1h)
    - seq_len: numero maximo de eventos por secuencia

    Devuelve:
    - X: array (N, seq_len, n_features)
    - meta: lista de dicts con timestamp y fase predominante de cada ventana
    """
    if df.empty or len(df) < 2:
        return np.array([]), []

    scaler = StandardScaler()
    features = df[FEATURE_COLS].values.astype(np.float32)
    features_scaled = scaler.fit_transform(features)

    with open(f"{MODELS_PATH}/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    timestamps = df["timestamp"].values
    fases = df["fase_mitre"].values
    t_inicio = df["timestamp"].min()
    t_fin    = df["timestamp"].max()

    ventanas_X = []
    ventanas_meta = []

    t_actual = t_inicio
    delta_ventana = timedelta(minutes=ventana_min)
    delta_paso    = timedelta(minutes=paso_min)

    while t_actual + delta_ventana <= t_fin + delta_paso:
        t_corte = t_actual + delta_ventana
        mask = (df["timestamp"] >= t_actual) & (df["timestamp"] < t_corte)
        eventos_ventana = features_scaled[mask]

        if len(eventos_ventana) == 0:
            t_actual += delta_paso
            continue

        # Pad o truncar a seq_len
        if len(eventos_ventana) >= seq_len:
            seq = eventos_ventana[-seq_len:]
        else:
            pad = np.zeros((seq_len - len(eventos_ventana), features_scaled.shape[1]))
            seq = np.vstack([pad, eventos_ventana])

        # Fase predominante en la ventana
        fases_ventana = fases[mask]
        fase_pred = "unknown"
        if len(fases_ventana) > 0:
            from collections import Counter
            conteo = Counter(fases_ventana)
            conteo.pop("unknown", None)
            if conteo:
                fase_pred = conteo.most_common(1)[0][0]

        ventanas_X.append(seq)
        ventanas_meta.append({
            "t_inicio":      t_actual,
            "t_fin":         t_corte,
            "n_eventos":     int(mask.sum()),
            "fase_mitre":    fase_pred,
            "nivel_max":     int(df.loc[mask, "nivel"].max()) if mask.sum() > 0 else 0,
        })
        t_actual += delta_paso

    if not ventanas_X:
        return np.array([]), []

    X = np.stack(ventanas_X, axis=0).astype(np.float32)
    print(f"[Pipeline] Ventanas construidas: {X.shape[0]} ventanas de {seq_len} pasos x {X.shape[2]} features")
    return X, ventanas_meta


# ── 4. Etiquetado para entrenamiento ─────────────────────────────────────────
FASE_A_INDICE = {fase: i for i, fase in enumerate(MITRE_PHASES)}

def etiquetar_ventanas(meta: list) -> np.ndarray:
    """
    Convierte los metadatos de ventanas en etiquetas de clase para entrenamiento.
    Retorna array de indices de fase MITRE.
    """
    return np.array([FASE_A_INDICE.get(m["fase_mitre"], 11) for m in meta])


# ── 5. Pipeline completo ──────────────────────────────────────────────────────
def ejecutar_pipeline(horas_atras: int = 168, ventana_h: int = 6,
                      seq_len: int = 32) -> dict:
    """
    Ejecuta el pipeline completo:
    1. Carga alertas de Wazuh
    2. Extrae caracteristicas
    3. Construye ventanas temporales
    4. Etiqueta para entrenamiento

    Retorna dict con X, y, meta y estadisticas.
    """
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Pipeline de Series Temporales")
    print("="*60)

    df = cargar_alertas_wazuh(horas_atras=horas_atras)
    if df.empty:
        return {"error": "No hay alertas disponibles"}

    df = extraer_caracteristicas(df)

    X, meta = construir_ventanas(
        df,
        ventana_min=ventana_h * 60,
        paso_min=60,
        seq_len=seq_len
    )

    if len(X) == 0:
        return {"error": "No se pudieron construir ventanas"}

    y = etiquetar_ventanas(meta)

    # Estadisticas
    from collections import Counter
    dist_fases = Counter([m["fase_mitre"] for m in meta])

    resultado = {
        "X":          X,
        "y":          y,
        "meta":       meta,
        "n_ventanas": len(X),
        "n_features": X.shape[2],
        "seq_len":    seq_len,
        "dist_fases": dict(dist_fases),
        "alertas_totales": len(df),
    }

    print(f"\n[Pipeline] Resultado:")
    print(f"  Ventanas generadas : {resultado['n_ventanas']}")
    print(f"  Features por paso  : {resultado['n_features']}")
    print(f"  Longitud secuencia : {seq_len}")
    print(f"  Distribucion fases : {dist_fases}")
    print("="*60 + "\n")

    # Guardar para uso posterior
    np.save(f"{MODELS_PATH}/X_pipeline.npy", X)
    np.save(f"{MODELS_PATH}/y_pipeline.npy", y)
    with open(f"{MODELS_PATH}/meta_pipeline.pkl", "wb") as f:
        pickle.dump(meta, f)

    print(f"[Pipeline] Datos guardados en {MODELS_PATH}/")
    return resultado


if __name__ == "__main__":
    resultado = ejecutar_pipeline(horas_atras=1440, ventana_h=6, seq_len=32)
    if "error" not in resultado:
        print(f"Pipeline completado. Shape X: {resultado['X'].shape}")
