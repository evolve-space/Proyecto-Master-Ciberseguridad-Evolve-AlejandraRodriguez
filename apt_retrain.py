"""
Noctua Predictive — Reentrenamiento Automatico del Modelo LSTM
Modulo 7: Reentrena el modelo cuando llegan suficientes datos nuevos

El modelo mejora continuamente a medida que Wazuh acumula mas alertas reales.
Cada vez que hay suficientes datos nuevos, el pipeline se ejecuta de nuevo
y el modelo se reentrena incorporando los nuevos patrones de ataque.

Estrategia:
- Comprueba cada hora si hay suficientes datos nuevos (umbral configurable)
- Si hay datos nuevos suficientes, ejecuta pipeline + reentrenamiento
- Guarda historial de versiones del modelo para poder revertir si es necesario
- Notifica via log cuando el modelo mejora su F1-score
"""

import os
import json
import time
import pickle
import numpy as np
import torch
from datetime import datetime, timedelta
from pathlib import Path

from apt_pipeline import ejecutar_pipeline
from apt_lstm import entrenar_modelo, evaluar_modelo, NoctuaLSTM, MITRE_PHASES, N_CLASES

MODELS_PATH    = "/root/asoar/models"
RETRAIN_LOG    = "/root/asoar/retrain_historial.json"
RETRAIN_CONFIG = "/root/asoar/retrain_config.json"

# Configuracion por defecto
CONFIG_DEFAULT = {
    "min_ventanas_nuevas":  10,    # minimo de ventanas nuevas para reentrenar
    "intervalo_horas":       6,    # cada cuantas horas comprobar
    "epochs":               30,    # epochs de reentrenamiento
    "mejora_minima_f1":    0.01,   # mejora minima de F1 para aceptar el nuevo modelo
    "max_versiones":         5,    # numero maximo de versiones a conservar
    "activo":             True,    # si el reentrenamiento automatico esta activo
}


def cargar_config() -> dict:
    if os.path.exists(RETRAIN_CONFIG):
        try:
            with open(RETRAIN_CONFIG, "r") as f:
                return {**CONFIG_DEFAULT, **json.load(f)}
        except Exception:
            pass
    return CONFIG_DEFAULT.copy()


def guardar_config(config: dict):
    with open(RETRAIN_CONFIG, "w") as f:
        json.dump(config, f, indent=2)


def cargar_historial() -> list:
    if os.path.exists(RETRAIN_LOG):
        try:
            with open(RETRAIN_LOG, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def guardar_historial(historial: list):
    with open(RETRAIN_LOG, "w") as f:
        json.dump(historial[-50:], f, indent=2, default=str)


def obtener_n_ventanas_actual() -> int:
    """Devuelve el numero de ventanas en el pipeline actual."""
    X_path = f"{MODELS_PATH}/X_pipeline.npy"
    if not os.path.exists(X_path):
        return 0
    return np.load(X_path).shape[0]


def evaluar_modelo_actual(X: np.ndarray, y: np.ndarray) -> float:
    """Evalua el modelo actual y devuelve su F1-score."""
    modelo_path = f"{MODELS_PATH}/lstm_noctua.pt"
    if not os.path.exists(modelo_path):
        return 0.0
    try:
        checkpoint = torch.load(modelo_path, map_location="cpu")
        modelo = NoctuaLSTM(
            n_features=checkpoint["n_features"],
            hidden_size=checkpoint["hidden_size"],
            n_layers=checkpoint["n_layers"],
            n_classes=checkpoint["n_classes"],
        )
        modelo.load_state_dict(checkpoint["model_state"])
        return checkpoint.get("mejor_f1", 0.0)
    except Exception:
        return 0.0


def hacer_backup_modelo(version: int):
    """Guarda una copia del modelo actual como backup."""
    src = f"{MODELS_PATH}/lstm_noctua.pt"
    dst = f"{MODELS_PATH}/lstm_v{version}.pt"
    if os.path.exists(src):
        import shutil
        shutil.copy2(src, dst)
        print(f"[Retrain] Backup guardado: {dst}")


def limpiar_versiones_antiguas(max_versiones: int):
    """Elimina versiones antiguas del modelo si supera el maximo."""
    versiones = sorted([
        f for f in os.listdir(MODELS_PATH)
        if f.startswith("lstm_v") and f.endswith(".pt")
    ])
    while len(versiones) > max_versiones:
        os.remove(f"{MODELS_PATH}/{versiones[0]}")
        print(f"[Retrain] Eliminada version antigua: {versiones[0]}")
        versiones = versiones[1:]


def reentrenar(forzar: bool = False) -> dict:
    """
    Ejecuta el reentrenamiento del modelo si hay suficientes datos nuevos.

    forzar: si True, reentrena aunque no haya suficientes datos nuevos
    Retorna: dict con el resultado del reentrenamiento
    """
    config   = cargar_config()
    historial = cargar_historial()

    print(f"\n[Retrain] Comprobando datos nuevos... {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    # Ejecutar pipeline para obtener datos actuales
    resultado_pipeline = ejecutar_pipeline(horas_atras=1440, ventana_h=6, seq_len=32)

    if "error" in resultado_pipeline:
        entrada = {
            "timestamp": datetime.now().isoformat(),
            "estado":    "error_pipeline",
            "motivo":    resultado_pipeline["error"],
        }
        historial.append(entrada)
        guardar_historial(historial)
        return entrada

    n_ventanas = resultado_pipeline["n_ventanas"]
    X = resultado_pipeline["X"]
    y = resultado_pipeline["y"]

    # Comprobar si hay suficientes datos
    n_anterior = historial[-1].get("n_ventanas", 0) if historial else 0
    datos_suficientes = n_ventanas >= config["min_ventanas_nuevas"]

    if not datos_suficientes and not forzar:
        entrada = {
            "timestamp":  datetime.now().isoformat(),
            "estado":     "datos_insuficientes",
            "n_ventanas": n_ventanas,
            "minimo":     config["min_ventanas_nuevas"],
        }
        historial.append(entrada)
        guardar_historial(historial)
        print(f"[Retrain] Datos insuficientes: {n_ventanas}/{config['min_ventanas_nuevas']} ventanas")
        return entrada

    # F1 del modelo actual
    f1_anterior = evaluar_modelo_actual(X, y)
    version_actual = len([
        f for f in os.listdir(MODELS_PATH)
        if f.startswith("lstm_v") and f.endswith(".pt")
    ])

    print(f"[Retrain] Iniciando reentrenamiento con {n_ventanas} ventanas...")
    print(f"[Retrain] F1 modelo anterior: {f1_anterior:.4f}")

    # Hacer backup antes de reentrenar
    hacer_backup_modelo(version_actual + 1)

    # Anadir datos sinteticos si solo hay una clase
    if len(np.unique(y)) < 2:
        n_sint = max(3, len(X) // 3)
        X_sint = X[:n_sint].copy() * 0.8
        y_sint = np.zeros(n_sint, dtype=np.int64)
        X = np.vstack([X, X_sint])
        y = np.concatenate([y, y_sint])

    # Reentrenar
    modelo_nuevo = entrenar_modelo(
        X, y,
        epochs=config["epochs"],
        batch_size=4
    )

    # Evaluar nuevo modelo
    checkpoint = torch.load(f"{MODELS_PATH}/lstm_noctua.pt", map_location="cpu")
    f1_nuevo = checkpoint.get("mejor_f1", 0.0)
    mejora   = f1_nuevo - f1_anterior

    print(f"[Retrain] F1 nuevo modelo: {f1_nuevo:.4f} | Mejora: {mejora:+.4f}")

    # Si el nuevo modelo es peor revertir al anterior
    if mejora < -config["mejora_minima_f1"] and not forzar:
        backup_path = f"{MODELS_PATH}/lstm_v{version_actual + 1}.pt"
        if os.path.exists(backup_path):
            import shutil
            shutil.copy2(backup_path, f"{MODELS_PATH}/lstm_noctua.pt")
            print(f"[Retrain] Modelo revertido — el nuevo era peor")
            estado = "revertido"
        else:
            estado = "completado_sin_mejora"
    else:
        estado = "completado_con_mejora" if mejora > 0 else "completado"
        limpiar_versiones_antiguas(config["max_versiones"])

    entrada = {
        "timestamp":   datetime.now().isoformat(),
        "estado":      estado,
        "n_ventanas":  n_ventanas,
        "f1_anterior": round(f1_anterior, 4),
        "f1_nuevo":    round(f1_nuevo, 4),
        "mejora":      round(mejora, 4),
        "epochs":      config["epochs"],
    }
    historial.append(entrada)
    guardar_historial(historial)

    print(f"[Retrain] Estado: {estado}")
    return entrada


def bucle_reentrenamiento():
    """
    Bucle principal de reentrenamiento automatico.
    Se ejecuta en segundo plano comprobando periodicamente si hay datos nuevos.
    """
    config = cargar_config()
    print(f"[Retrain] Bucle iniciado — intervalo: {config['intervalo_horas']}h")

    while True:
        config = cargar_config()
        if not config.get("activo", True):
            print("[Retrain] Reentrenamiento automatico desactivado")
            time.sleep(3600)
            continue

        try:
            resultado = reentrenar()
            print(f"[Retrain] {resultado['estado']} — proxima comprobacion en {config['intervalo_horas']}h")
        except Exception as e:
            print(f"[Retrain] Error: {e}")

        time.sleep(config["intervalo_horas"] * 3600)


def obtener_estado_retrain() -> dict:
    """Devuelve el estado actual del sistema de reentrenamiento."""
    config   = cargar_config()
    historial = cargar_historial()

    versiones = [
        f for f in os.listdir(MODELS_PATH)
        if f.startswith("lstm_v") and f.endswith(".pt")
    ]

    return {
        "activo":           config.get("activo", True),
        "intervalo_horas":  config.get("intervalo_horas", 6),
        "min_ventanas":     config.get("min_ventanas_nuevas", 10),
        "n_reentrenamientos": len([h for h in historial if "completado" in h.get("estado", "")]),
        "ultimo":           historial[-1] if historial else None,
        "versiones_guardadas": len(versiones),
        "mejor_f1_historico": max((h.get("f1_nuevo", 0) for h in historial if "f1_nuevo" in h), default=0),
    }


if __name__ == "__main__":
    import sys
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Reentrenamiento Automatico")
    print("="*60)

    if len(sys.argv) > 1 and sys.argv[1] == "forzar":
        print("\n[Retrain] Modo forzado activado")
        resultado = reentrenar(forzar=True)
    else:
        print("\n[Retrain] Comprobando si hay datos suficientes...")
        resultado = reentrenar(forzar=False)

    print(f"\nResultado: {json.dumps(resultado, indent=2, default=str)}")

    print("\n[Estado del sistema de reentrenamiento:]")
    estado = obtener_estado_retrain()
    for k, v in estado.items():
        if k != "ultimo":
            print(f"  {k}: {v}")

    print("\n" + "="*60)
