"""
Noctua Predictive — Pipeline CICIDS2018
Modulo de ingesta y preprocesamiento del dataset CSE-CIC-IDS2018

Convierte los CSVs de CICIDS2018 al formato de ventanas temporales
que necesita el modelo LSTM para entrenamiento con datos estandar.

El dataset contiene trafico de red real con 15 tipos de ataque:
- Benign (trafico normal)
- FTP-BruteForce, SSH-Bruteforce
- DoS attacks (GoldenEye, Slowloris, SlowHTTPTest, Hulk)
- DDoS attacks (LOIC-UDP, HOIC, LOIC-HTTP)
- Brute Force Web, XSS, SQL Injection
- Bot, Infilteration

Referencia:
I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani,
"Toward Generating a New Intrusion Detection Dataset and
Intrusion Detection Traffic Characterization",
ICISSP 2018.
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from collections import Counter
import pickle
import warnings
warnings.filterwarnings('ignore')

DATASET_PATH = "/root/asoar/datasets/cicids2018/"
MODELS_PATH  = "/root/asoar/models"
Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)

# Mapeo de etiquetas CICIDS2018 a fases MITRE ATT&CK
CICIDS_A_MITRE = {
    "Benign":                  "unknown",
    "FTP-BruteForce":          "initial_access",
    "SSH-Bruteforce":          "initial_access",
    "DoS attacks-GoldenEye":   "execution",
    "DoS attacks-Slowloris":   "execution",
    "DoS attacks-SlowHTTPTest":"execution",
    "DoS attacks-Hulk":        "execution",
    "DDoS attacks-LOIC-HTTP":  "execution",
    "DDOS attack-LOIC-UDP":    "execution",
    "DDOS attack-HOIC":        "execution",
    "Brute Force -Web":        "credential_access",
    "Brute Force -XSS":        "credential_access",
    "SQL Injection":           "credential_access",
    "Bot":                     "persistence",
    "Infilteration":           "lateral_movement",
}

MITRE_PHASES = [
    "reconnaissance", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "exfiltration", "unknown"
]
FASE_A_INDICE = {f: i for i, f in enumerate(MITRE_PHASES)}

# Features del dataset CICIDS2018 con nombres reales de las columnas
FEATURES_REDUCIDAS = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "SYN Flag Cnt",
    "ACK Flag Cnt",
    "Pkt Size Avg",
    "Flow IAT Mean",
]


def cargar_cicids(max_filas_por_archivo: int = 50000) -> pd.DataFrame:
    """
    Carga y combina todos los CSVs del dataset CICIDS2018.
    """
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Pipeline CICIDS2018")
    print("="*60)

    archivos = [f for f in os.listdir(DATASET_PATH) if f.endswith('.csv')]
    print(f"Archivos encontrados: {len(archivos)}")

    dfs = []
    for archivo in sorted(archivos):
        ruta = os.path.join(DATASET_PATH, archivo)
        try:
            df_temp = pd.read_csv(ruta, nrows=max_filas_por_archivo,
                                  low_memory=False, encoding='utf-8',
                                  on_bad_lines='skip')
            df_temp.columns = [c.strip() for c in df_temp.columns]

            # Encontrar columna de etiqueta
            col_label = None
            for c in df_temp.columns:
                if c.lower().strip() in ['label']:
                    col_label = c
                    break

            if col_label is None:
                print(f"  [WARN] {archivo[:30]}: sin columna Label")
                continue

            # Eliminar filas con Label como cabecera
            df_temp = df_temp[df_temp[col_label] != 'Label']
            df_temp = df_temp[df_temp[col_label].notna()]

            # Mapear a fases MITRE
            df_temp['fase_mitre'] = df_temp[col_label].map(
                lambda x: CICIDS_A_MITRE.get(str(x).strip(), "unknown")
            )

            # Seleccionar features disponibles
            features_disponibles = [f for f in FEATURES_REDUCIDAS if f in df_temp.columns]
            if len(features_disponibles) < 5:
                print(f"  [WARN] {archivo[:30]}: pocas features ({len(features_disponibles)})")
                continue

            cols_usar = features_disponibles + ['fase_mitre']
            df_temp = df_temp[cols_usar].copy()

            # Convertir a numerico
            for col in features_disponibles:
                df_temp[col] = pd.to_numeric(df_temp[col], errors='coerce')

            df_temp = df_temp.dropna()
            df_temp = df_temp.replace([np.inf, -np.inf], np.nan).dropna()

            n = len(df_temp)
            dist = df_temp['fase_mitre'].value_counts().to_dict()
            print(f"  {archivo[:35]}: {n} filas | {dist}")
            dfs.append(df_temp)

        except Exception as e:
            print(f"  [ERROR] {archivo[:30]}: {e}")

    if not dfs:
        print("[ERROR] No se pudieron cargar archivos")
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal: {len(df)} filas cargadas")
    print(f"Distribucion fases MITRE: {df['fase_mitre'].value_counts().to_dict()}")
    return df


def preprocesar_cicids(df: pd.DataFrame, seq_len: int = 32,
                        max_por_clase: int = 5000) -> dict:
    """
    Preprocesa el dataset CICIDS2018 para el modelo LSTM.
    """
    if df.empty:
        return {"error": "DataFrame vacio"}

    features = [c for c in df.columns if c != 'fase_mitre']

    # 1. Balancear clases
    print(f"\n[CICIDS] Balanceando clases (max {max_por_clase} por clase)...")
    dfs_balanceados = []
    for fase in df['fase_mitre'].unique():
        df_fase = df[df['fase_mitre'] == fase]
        n = min(len(df_fase), max_por_clase)
        dfs_balanceados.append(df_fase.sample(n, random_state=42))

    df_bal = pd.concat(dfs_balanceados, ignore_index=True).sample(
        frac=1, random_state=42).reset_index(drop=True)

    # 2. Intercalar filas de diferentes clases para ventanas heterogeneas
    df_bal = df_bal.sort_values('fase_mitre').reset_index(drop=True)
    indices = []
    clases = df_bal['fase_mitre'].unique()
    max_len = max(len(df_bal[df_bal['fase_mitre'] == c]) for c in clases)
    for i in range(max_len):
        for clase in clases:
            idx = df_bal[df_bal['fase_mitre'] == clase].index
            if i < len(idx):
                indices.append(idx[i])
    df_bal = df_bal.loc[indices].reset_index(drop=True)

    print(f"[CICIDS] Dataset balanceado e intercalado: {len(df_bal)} filas")
    print(f"[CICIDS] Distribucion: {df_bal['fase_mitre'].value_counts().to_dict()}")

    # 3. Escalar features
    X_raw = df_bal[features].values.astype(np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    with open(f"{MODELS_PATH}/scaler_cicids.pkl", "wb") as f:
        pickle.dump(scaler, f)

    # 4. Etiquetas
    y_raw = df_bal['fase_mitre'].values
    y = np.array([FASE_A_INDICE.get(f, 11) for f in y_raw])

    # 5. Construir secuencias con paso = seq_len // 4 para mas variedad
    print(f"\n[CICIDS] Construyendo secuencias de {seq_len} eventos...")
    X_seq, y_seq = [], []
    paso = max(1, seq_len // 4)
    n_total = len(X_scaled)

    for i in range(0, n_total - seq_len, paso):
        ventana = X_scaled[i:i+seq_len]
        if len(ventana) == seq_len:
            etiquetas_ventana = y[i:i+seq_len]
            conteo = Counter(etiquetas_ventana.tolist())
            # Usar la fase mas frecuente en la ventana
            etiqueta = max(conteo, key=conteo.get)
            X_seq.append(ventana)
            y_seq.append(etiqueta)

    X = np.array(X_seq, dtype=np.float32)
    y_final = np.array(y_seq, dtype=np.int64)

    # Guardar
    np.save(f"{MODELS_PATH}/X_cicids.npy", X)
    np.save(f"{MODELS_PATH}/y_cicids.npy", y_final)

    dist_final = Counter(y_final.tolist())
    dist_nombres = {MITRE_PHASES[k]: v for k, v in dist_final.items()}

    print(f"\n[CICIDS] Resultado:")
    print(f"  Ventanas: {X.shape[0]}")
    print(f"  Features: {X.shape[2]}")
    print(f"  Seq len:  {seq_len}")
    print(f"  Clases:   {len(dist_final)}")
    print(f"  Distribucion: {dist_nombres}")
    print(f"\n[CICIDS] Datos guardados en {MODELS_PATH}/")
    print("="*60)

    return {
        "X":           X,
        "y":           y_final,
        "n_ventanas":  X.shape[0],
        "n_features":  X.shape[2],
        "seq_len":     seq_len,
        "n_clases":    len(dist_final),
        "dist_clases": dist_nombres,
        "features":    features,
    }


def combinar_con_wazuh(resultado_cicids: dict) -> dict:
    """
    Combina el dataset CICIDS2018 con los datos reales de Wazuh.
    """
    X_cicids = resultado_cicids["X"]
    y_cicids = resultado_cicids["y"]

    X_wazuh_path = f"{MODELS_PATH}/X_pipeline.npy"
    y_wazuh_path = f"{MODELS_PATH}/y_pipeline.npy"

    if not os.path.exists(X_wazuh_path):
        print("[CICIDS] No hay datos Wazuh disponibles, usando solo CICIDS2018")
        return resultado_cicids

    X_wazuh = np.load(X_wazuh_path)
    y_wazuh = np.load(y_wazuh_path)

    n_features_cicids = X_cicids.shape[2]
    n_features_wazuh  = X_wazuh.shape[2]

    if n_features_cicids != n_features_wazuh:
        min_features = min(n_features_cicids, n_features_wazuh)
        X_cicids = X_cicids[:, :, :min_features]
        X_wazuh  = X_wazuh[:, :, :min_features]

    X_combined = np.vstack([X_cicids, X_wazuh])
    y_combined = np.concatenate([y_cicids, y_wazuh])

    print(f"\n[CICIDS] Dataset combinado: {X_combined.shape[0]} ventanas")
    print(f"         CICIDS: {X_cicids.shape[0]} | Wazuh: {X_wazuh.shape[0]}")

    return {
        **resultado_cicids,
        "X":          X_combined,
        "y":          y_combined,
        "n_ventanas": X_combined.shape[0],
    }


if __name__ == "__main__":
    df = cargar_cicids(max_filas_por_archivo=30000)

    if df.empty:
        print("ERROR: No se pudo cargar el dataset")
        exit(1)

    resultado = preprocesar_cicids(df, seq_len=32, max_por_clase=3000)

    if "error" in resultado:
        print(f"ERROR: {resultado['error']}")
        exit(1)

    resultado_final = combinar_con_wazuh(resultado)

    print(f"\nPipeline CICIDS2018 completado:")
    print(f"  Ventanas totales: {resultado_final['n_ventanas']}")
    print(f"  Features:         {resultado_final['n_features']}")
    print(f"  Clases MITRE:     {resultado_final['n_clases']}")
    print(f"\nListo para entrenar con apt_lstm.py")
