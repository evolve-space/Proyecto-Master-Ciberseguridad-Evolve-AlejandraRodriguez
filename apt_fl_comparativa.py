"""
Noctua Predictive — Comparativa Federated Learning vs Centralizado
Experimento cientifico con particion non-IID de CICIDS2018

Demuestra empiricamente que el modelo federado mejora la deteccion
de amenazas respecto al entrenamiento centralizado cuando cada nodo
tiene un perfil de amenazas diferente (datos non-IID).

Escenario:
- Nodo 1: Servidor expuesto (datos Wazuh reales + SSH brute force)
- Nodo 2: Empresa bajo ataque volumetrico (DoS/DDoS de CICIDS2018)
- Nodo 3: Empresa bajo ataque dirigido (credential_access + persistence)

Referencia metodologica:
McMahan et al. (2017). Communication-Efficient Learning of Deep Networks
from Decentralized Data. AISTATS 2017.
"""

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from collections import OrderedDict, Counter
from sklearn.metrics import f1_score, classification_report
from pathlib import Path
import json
import os
from datetime import datetime

from apt_lstm import NoctuaLSTM, APTDataset, N_CLASES, MITRE_PHASES

MODELS_PATH   = "/root/asoar/models"
RESULTS_PATH  = "/root/asoar/fl_comparativa.json"
Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)

FASE_A_INDICE = {f: i for i, f in enumerate(MITRE_PHASES)}


# ── Particion non-IID de CICIDS2018 ──────────────────────────────────────────

def crear_particiones_noniid(X: np.ndarray, y: np.ndarray) -> dict:
    """
    Crea particiones non-IID del dataset CICIDS2018.
    Cada nodo tiene un perfil de amenazas diferente.

    Nodo 1: initial_access (SSH brute force) + datos Wazuh reales
    Nodo 2: execution (DoS/DDoS)
    Nodo 3: credential_access + persistence (ataques dirigidos)
    """
    print("\n[Comparativa] Creando particiones non-IID...")

    # Indices por clase
    idx_initial    = np.where(y == FASE_A_INDICE["initial_access"])[0]
    idx_execution  = np.where(y == FASE_A_INDICE["execution"])[0]
    idx_credential = np.where(y == FASE_A_INDICE["credential_access"])[0]
    idx_persistence= np.where(y == FASE_A_INDICE["persistence"])[0]
    idx_unknown    = np.where(y == FASE_A_INDICE["unknown"])[0]

    # Nodo 1: servidor expuesto — SSH brute force + trafico normal
    idx_nodo1 = np.concatenate([
        idx_initial,
        idx_unknown[:len(idx_initial)//2]
    ])
    np.random.shuffle(idx_nodo1)

    # Cargar datos reales de Wazuh si existen
    X_wazuh_path = f"{MODELS_PATH}/X_pipeline.npy"
    if os.path.exists(X_wazuh_path):
        X_wazuh = np.load(X_wazuh_path)
        y_wazuh = np.load(f"{MODELS_PATH}/y_pipeline.npy")
        X_n1 = np.vstack([X[idx_nodo1], X_wazuh[:, :, :9]])
        y_n1 = np.concatenate([y[idx_nodo1], y_wazuh])
        print(f"  Nodo 1: {len(X_n1)} ventanas (CICIDS + Wazuh real)")
    else:
        X_n1 = X[idx_nodo1]
        y_n1 = y[idx_nodo1]
        print(f"  Nodo 1: {len(X_n1)} ventanas (CICIDS)")

    # Nodo 2: empresa bajo ataque volumetrico — DoS/DDoS
    idx_nodo2 = np.concatenate([
        idx_execution,
        idx_unknown[len(idx_initial)//2:len(idx_initial)]
    ])
    np.random.shuffle(idx_nodo2)
    X_n2 = X[idx_nodo2]
    y_n2 = y[idx_nodo2]
    print(f"  Nodo 2: {len(X_n2)} ventanas (DoS/DDoS)")

    # Nodo 3: empresa bajo ataque dirigido — credential + persistence
    idx_nodo3 = np.concatenate([
        idx_credential,
        idx_persistence,
        idx_unknown[len(idx_initial):len(idx_initial)+len(idx_credential)]
    ])
    np.random.shuffle(idx_nodo3)
    X_n3 = X[idx_nodo3]
    y_n3 = y[idx_nodo3]
    print(f"  Nodo 3: {len(X_n3)} ventanas (Credential + Persistence)")

    dist_n1 = {MITRE_PHASES[k]: v for k, v in Counter(y_n1.tolist()).items()}
    dist_n2 = {MITRE_PHASES[k]: v for k, v in Counter(y_n2.tolist()).items()}
    dist_n3 = {MITRE_PHASES[k]: v for k, v in Counter(y_n3.tolist()).items()}

    print(f"\n  Distribucion Nodo 1: {dist_n1}")
    print(f"  Distribucion Nodo 2: {dist_n2}")
    print(f"  Distribucion Nodo 3: {dist_n3}")

    return {
        "nodo1": (X_n1, y_n1),
        "nodo2": (X_n2, y_n2),
        "nodo3": (X_n3, y_n3),
    }


# ── Utilidades ────────────────────────────────────────────────────────────────

def crear_modelo():
    return NoctuaLSTM(n_features=9, hidden_size=64, n_layers=2,
                      n_classes=N_CLASES, dropout=0.3)

def get_params(modelo):
    return [v.cpu().numpy() for v in modelo.state_dict().values()]

def set_params(modelo, params):
    state = OrderedDict({k: torch.tensor(v)
                         for k, v in zip(modelo.state_dict().keys(), params)})
    modelo.load_state_dict(state, strict=True)

def evaluar(modelo, X, y, nombre=""):
    modelo.eval()
    ds = APTDataset(X, y)
    loader = DataLoader(ds, batch_size=32, shuffle=False)
    preds, labels = [], []
    with torch.no_grad():
        for xb, yb in loader:
            logits = modelo(xb)
            preds.extend(logits.argmax(dim=-1).cpu().numpy())
            labels.extend(yb.cpu().numpy())
    f1 = f1_score(labels, preds, average="weighted", zero_division=0)
    acc = sum(p == l for p, l in zip(preds, labels)) / len(labels)
    if nombre:
        print(f"  {nombre}: F1={f1:.4f} | Acc={acc:.4f}")
    return f1, acc, preds, labels

def entrenar_local(modelo, X, y, epochs=5, lr=1e-3, batch_size=16):
    """Entrena el modelo localmente en un nodo."""
    ds = APTDataset(X, y)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    counts = np.bincount(y, minlength=N_CLASES).astype(np.float32)
    counts = np.where(counts == 0, 1, counts)
    weights = torch.tensor(1.0 / counts)

    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(modelo.parameters(), lr=lr, weight_decay=1e-4)

    modelo.train()
    loss_total = 0.0
    for _ in range(epochs):
        for xb, yb in loader:
            optimizer.zero_grad()
            loss = criterion(modelo(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(modelo.parameters(), 1.0)
            optimizer.step()
            loss_total += loss.item()
    return get_params(modelo), len(ds)


def fedavg(params_list, n_muestras):
    """Agregacion FedAvg ponderada por numero de muestras."""
    total = sum(n_muestras)
    agregados = []
    for i in range(len(params_list[0])):
        param_pond = sum(p[i] * n / total
                         for p, n in zip(params_list, n_muestras))
        agregados.append(param_pond)
    return agregados


# ── Experimento 1: Entrenamiento Centralizado ─────────────────────────────────

def entrenar_centralizado(X_all: np.ndarray, y_all: np.ndarray,
                           epochs: int = 30) -> dict:
    """
    Entrena un modelo con todos los datos combinados (escenario centralizado).
    Baseline para comparar con Federated Learning.
    """
    print("\n" + "="*60)
    print("EXPERIMENTO 1: Entrenamiento Centralizado (Baseline)")
    print("="*60)
    print(f"  Datos totales: {len(X_all)} ventanas")
    print(f"  Clases: {len(np.unique(y_all))}")

    modelo = crear_modelo()
    ds = APTDataset(X_all, y_all)

    n_val   = max(1, int(len(ds) * 0.2))
    n_train = len(ds) - n_val
    from torch.utils.data import random_split
    train_ds, val_ds = random_split(ds, [n_train, n_val])

    loader_train = DataLoader(train_ds, batch_size=16, shuffle=True)
    loader_val   = DataLoader(val_ds,   batch_size=32, shuffle=False)

    counts  = np.bincount(y_all, minlength=N_CLASES).astype(np.float32)
    counts  = np.where(counts == 0, 1, counts)
    weights = torch.tensor(1.0 / counts)

    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(modelo.parameters(), lr=1e-3, weight_decay=1e-4)

    historial = []
    mejor_f1  = 0.0

    for epoch in range(1, epochs + 1):
        modelo.train()
        for xb, yb in loader_train:
            optimizer.zero_grad()
            loss = criterion(modelo(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(modelo.parameters(), 1.0)
            optimizer.step()

        # Validacion
        modelo.eval()
        preds_v, labels_v = [], []
        with torch.no_grad():
            for xb, yb in loader_val:
                preds_v.extend(modelo(xb).argmax(dim=-1).cpu().numpy())
                labels_v.extend(yb.cpu().numpy())

        f1 = f1_score(labels_v, preds_v, average="weighted", zero_division=0)
        historial.append({"epoch": epoch, "f1": round(f1, 4)})

        if f1 > mejor_f1:
            mejor_f1 = f1
            torch.save(modelo.state_dict(), f"{MODELS_PATH}/lstm_centralizado.pt")

        if epoch % 10 == 0:
            print(f"  Epoch {epoch:3d}/{epochs} | F1 val: {f1:.4f}")

    # Cargar mejor modelo y evaluar en todos los datos
    modelo.load_state_dict(torch.load(f"{MODELS_PATH}/lstm_centralizado.pt",
                                       map_location="cpu"))
    f1_final, acc_final, preds_all, labels_all = evaluar(modelo, X_all, y_all)

    print(f"\n  Mejor F1 centralizado: {mejor_f1:.4f}")
    print(f"\n  Classification Report (Centralizado):")
    clases_presentes = sorted(set(labels_all))
    nombres = [MITRE_PHASES[i] for i in clases_presentes]
    print(classification_report(labels_all, preds_all,
                                labels=clases_presentes,
                                target_names=nombres,
                                zero_division=0))

    return {
        "metodo":    "Centralizado",
        "f1_final":  round(f1_final, 4),
        "acc_final": round(acc_final, 4),
        "mejor_f1":  round(mejor_f1, 4),
        "historial": historial,
        "n_datos":   len(X_all),
        "n_clases":  len(np.unique(y_all)),
    }


# ── Experimento 2: Federated Learning (FedAvg) ───────────────────────────────

def entrenar_federado(particiones: dict, n_rondas: int = 20,
                       epochs_local: int = 5) -> dict:
    """
    Entrena el modelo con Federated Learning (FedAvg) usando
    particiones non-IID de CICIDS2018.
    """
    print("\n" + "="*60)
    print("EXPERIMENTO 2: Federated Learning FedAvg (non-IID)")
    print("="*60)
    print(f"  Nodos: {len(particiones)} | Rondas: {n_rondas} | Epochs locales: {epochs_local}")

    nodos = list(particiones.items())
    modelo_global = crear_modelo()
    historial = []

    # Dataset combinado para evaluacion global
    X_all = np.vstack([d[0] for _, d in nodos])
    y_all = np.concatenate([d[1] for _, d in nodos])

    for ronda in range(1, n_rondas + 1):
        params_global = get_params(modelo_global)
        params_locales = []
        n_muestras = []

        for nombre_nodo, (X_n, y_n) in nodos:
            modelo_local = crear_modelo()
            set_params(modelo_local, params_global)
            params_nuevos, n = entrenar_local(
                modelo_local, X_n, y_n,
                epochs=epochs_local, lr=1e-3
            )
            params_locales.append(params_nuevos)
            n_muestras.append(n)

        # Agregar con FedAvg
        params_agregados = fedavg(params_locales, n_muestras)
        set_params(modelo_global, params_agregados)

        # Evaluar modelo global
        f1, acc, _, _ = evaluar(modelo_global, X_all, y_all)
        historial.append({
            "ronda": ronda,
            "f1":    round(f1, 4),
            "acc":   round(acc, 4)
        })

        if ronda % 5 == 0:
            print(f"  Ronda {ronda:3d}/{n_rondas} | F1: {f1:.4f} | Acc: {acc:.4f}")

    # Evaluacion final
    f1_final, acc_final, preds_all, labels_all = evaluar(
        modelo_global, X_all, y_all, "FL Final"
    )

    print(f"\n  F1 final federado: {f1_final:.4f}")
    print(f"\n  Classification Report (Federado):")
    clases_presentes = sorted(set(labels_all))
    nombres = [MITRE_PHASES[i] for i in clases_presentes]
    print(classification_report(labels_all, preds_all,
                                labels=clases_presentes,
                                target_names=nombres,
                                zero_division=0))

    # Guardar modelo federado
    torch.save({
        "model_state":  modelo_global.state_dict(),
        "n_features":   9,
        "n_classes":    N_CLASES,
        "hidden_size":  64,
        "n_layers":     2,
        "fecha":        datetime.now().isoformat(),
        "mitre_phases": MITRE_PHASES,
        "modo":         "federado_noniid",
        "n_nodos":      len(nodos),
        "n_rondas":     n_rondas,
    }, f"{MODELS_PATH}/lstm_federado_noniid.pt")

    return {
        "metodo":    "Federado FedAvg (non-IID)",
        "f1_final":  round(f1_final, 4),
        "acc_final": round(acc_final, 4),
        "historial": historial,
        "n_datos":   len(X_all),
        "n_clases":  len(np.unique(y_all)),
        "n_nodos":   len(nodos),
        "n_rondas":  n_rondas,
    }


# ── Comparativa final ─────────────────────────────────────────────────────────

def mostrar_comparativa(res_central: dict, res_fl: dict):
    """Muestra la tabla comparativa de resultados."""
    print("\n" + "="*60)
    print("COMPARATIVA FL vs CENTRALIZADO")
    print("="*60)
    print(f"{'Metrica':<25} {'Centralizado':>15} {'FL FedAvg':>15} {'Mejora':>10}")
    print("-"*65)

    mejora_f1  = res_fl["f1_final"]  - res_central["f1_final"]
    mejora_acc = res_fl["acc_final"] - res_central["acc_final"]

    print(f"{'F1-score (weighted)':<25} {res_central['f1_final']:>15.4f} {res_fl['f1_final']:>15.4f} {mejora_f1:>+10.4f}")
    print(f"{'Accuracy':<25} {res_central['acc_final']:>15.4f} {res_fl['acc_final']:>15.4f} {mejora_acc:>+10.4f}")
    print(f"{'Datos utilizados':<25} {res_central['n_datos']:>15} {res_fl['n_datos']:>15}")
    print(f"{'Clases detectadas':<25} {res_central['n_clases']:>15} {res_fl['n_clases']:>15}")
    print("="*60)

    if mejora_f1 > 0:
        print(f"\nCONCLUSION: El modelo Federado mejora el F1 en {mejora_f1:+.4f} ({mejora_f1*100:+.2f}%)")
        print("El Federated Learning supera al entrenamiento centralizado")
        print("en el escenario non-IID con perfiles de amenaza heterogeneos.")
    else:
        print(f"\nCONCLUSION: El modelo Centralizado supera al Federado en {-mejora_f1:.4f}")
        print("Nota: En escenarios non-IID severos, FL puede requerir")
        print("mas rondas o tecnicas avanzadas (FedProx, SCAFFOLD).")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Comparativa FL vs Centralizado")
    print("Experimento con datos non-IID (CICIDS2018)")
    print("="*60)

    # Cargar dataset CICIDS2018
    X_path = f"{MODELS_PATH}/X_cicids.npy"
    y_path = f"{MODELS_PATH}/y_cicids.npy"

    if not os.path.exists(X_path):
        print("ERROR: Ejecuta primero apt_pipeline_cicids.py")
        exit(1)

    X = np.load(X_path)
    y = np.load(y_path)
    print(f"\nDataset cargado: {X.shape[0]} ventanas, {len(np.unique(y))} clases")

    # Crear particiones non-IID
    particiones = crear_particiones_noniid(X, y)

    # Dataset combinado para baseline centralizado
    X_all = np.vstack([d[0] for d in particiones.values()])
    y_all = np.concatenate([d[1] for d in particiones.values()])

    # Experimento 1: Centralizado
    res_central = entrenar_centralizado(X_all, y_all, epochs=30)

    # Experimento 2: Federado
    res_fl = entrenar_federado(particiones, n_rondas=20, epochs_local=5)

    # Comparativa
    mostrar_comparativa(res_central, res_fl)

    # Guardar resultados
    resultados = {
        "fecha":       datetime.now().isoformat(),
        "centralizado": res_central,
        "federado":     res_fl,
        "mejora_f1":    round(res_fl["f1_final"] - res_central["f1_final"], 4),
        "mejora_acc":   round(res_fl["acc_final"] - res_central["acc_final"], 4),
    }
    with open(RESULTS_PATH, "w") as f:
        json.dump(resultados, f, indent=2)
    print(f"\nResultados guardados en {RESULTS_PATH}")
