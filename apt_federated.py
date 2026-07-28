"""
Noctua Predictive — Federated Learning con Flower
Modulo 4: Entrenamiento federado del modelo LSTM entre multiples nodos

Arquitectura:
- Servidor de agregacion: aplica FedAvg sobre los gradientes de los nodos
- Cliente federado: entrena el LSTM localmente y envia gradientes al servidor

Uso:
  Servidor: python3 apt_federated.py server
  Cliente:  python3 apt_federated.py client --node-id 1
"""

import sys
import argparse
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split
from collections import OrderedDict
from pathlib import Path
from datetime import datetime
import json
import os

import flwr as fl
from flwr.common import NDArrays, Scalar
from typing import Dict, List, Optional, Tuple

from apt_lstm import NoctuaLSTM, APTDataset, MITRE_PHASES, N_CLASES
from apt_pipeline import ejecutar_pipeline

MODELS_PATH = "/root/asoar/models"
FL_LOG      = "/root/asoar/fl_historial.json"
Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)

# ── Utilidades ────────────────────────────────────────────────────────────────

def get_model_params(modelo: NoctuaLSTM) -> NDArrays:
    """Extrae los parametros del modelo como lista de arrays numpy."""
    return [val.cpu().numpy() for val in modelo.state_dict().values()]


def set_model_params(modelo: NoctuaLSTM, params: NDArrays):
    """Carga parametros numpy en el modelo."""
    state_dict = OrderedDict(
        {k: torch.tensor(v) for k, v in zip(modelo.state_dict().keys(), params)}
    )
    modelo.load_state_dict(state_dict, strict=True)


def crear_modelo(n_features: int = 9) -> NoctuaLSTM:
    return NoctuaLSTM(
        n_features=n_features,
        hidden_size=64,
        n_layers=2,
        n_classes=N_CLASES,
        dropout=0.3,
    )


# ── Cliente Federado ──────────────────────────────────────────────────────────

class NoctuaFLClient(fl.client.NumPyClient):
    """
    Cliente de Federated Learning para Noctua Predictive.
    Cada nodo (PYME) ejecuta este cliente con sus propios datos locales.
    Los datos nunca salen del nodo — solo se comparten los gradientes.
    """

    def __init__(self, node_id: int, X: np.ndarray, y: np.ndarray):
        self.node_id  = node_id
        self.modelo   = crear_modelo(n_features=X.shape[2])
        self.device   = torch.device("cpu")

        # Split local train/val
        dataset = APTDataset(X, y)
        n_val   = max(1, int(len(dataset) * 0.2))
        n_train = len(dataset) - n_val
        self.train_ds, self.val_ds = random_split(dataset, [n_train, n_val])

        print(f"[Nodo {node_id}] Datos: {len(self.train_ds)} train, {len(self.val_ds)} val")

    def get_parameters(self, config: Dict) -> NDArrays:
        """Devuelve los parametros actuales del modelo local."""
        return get_model_params(self.modelo)

    def fit(self, parameters: NDArrays, config: Dict) -> Tuple[NDArrays, int, Dict]:
        """
        Recibe el modelo global, entrena localmente y devuelve los gradientes.
        Los datos de entrenamiento NUNCA se envian al servidor.
        """
        # Cargar modelo global recibido del servidor
        set_model_params(self.modelo, parameters)

        epochs     = int(config.get("local_epochs", 5))
        batch_size = int(config.get("batch_size", 4))
        lr         = float(config.get("lr", 1e-3))

        loader = DataLoader(self.train_ds, batch_size=batch_size, shuffle=True)

        # Pesos de clase para desbalance
        all_labels = [self.train_ds[i][1].item() for i in range(len(self.train_ds))]
        class_counts = np.bincount(all_labels, minlength=N_CLASES).astype(np.float32)
        class_counts = np.where(class_counts == 0, 1, class_counts)
        class_weights = torch.tensor(1.0 / class_counts)

        criterion = nn.CrossEntropyLoss(weight=class_weights)
        optimizer = torch.optim.Adam(self.modelo.parameters(), lr=lr, weight_decay=1e-4)

        self.modelo.train()
        loss_total = 0.0
        for _ in range(epochs):
            for X_batch, y_batch in loader:
                optimizer.zero_grad()
                logits = self.modelo(X_batch)
                loss   = criterion(logits, y_batch)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.modelo.parameters(), 1.0)
                optimizer.step()
                loss_total += loss.item()

        loss_media = loss_total / (epochs * max(len(loader), 1))
        print(f"[Nodo {self.node_id}] Entrenamiento completado | Loss: {loss_media:.4f}")

        return get_model_params(self.modelo), len(self.train_ds), {"loss": loss_media}

    def evaluate(self, parameters: NDArrays, config: Dict) -> Tuple[float, int, Dict]:
        """Evalua el modelo global recibido con los datos locales de validacion."""
        set_model_params(self.modelo, parameters)
        loader = DataLoader(self.val_ds, batch_size=8, shuffle=False)

        criterion = nn.CrossEntropyLoss()
        self.modelo.eval()
        loss_total, correctos, total = 0.0, 0, 0

        with torch.no_grad():
            for X_batch, y_batch in loader:
                logits = self.modelo(X_batch)
                loss   = criterion(logits, y_batch)
                loss_total += loss.item()
                preds = logits.argmax(dim=-1)
                correctos += (preds == y_batch).sum().item()
                total     += len(y_batch)

        accuracy = correctos / total if total > 0 else 0.0
        loss_media = loss_total / max(len(loader), 1)
        print(f"[Nodo {self.node_id}] Evaluacion | Loss: {loss_media:.4f} | Acc: {accuracy:.4f}")

        return loss_media, total, {"accuracy": accuracy}


# ── Estrategia del Servidor (FedAvg personalizado) ───────────────────────────

class NoctuaFedAvg(fl.server.strategy.FedAvg):
    """
    Estrategia FedAvg personalizada para Noctua.
    Guarda el modelo global tras cada ronda y registra el historial.
    """

    def __init__(self, n_features: int = 9, **kwargs):
        super().__init__(**kwargs)
        self.n_features = n_features
        self.historial  = []
        self._cargar_historial()

    def _cargar_historial(self):
        if os.path.exists(FL_LOG):
            try:
                with open(FL_LOG, "r") as f:
                    self.historial = json.load(f)
            except Exception:
                self.historial = []

    def _guardar_historial(self):
        with open(FL_LOG, "w") as f:
            json.dump(self.historial[-50:], f, indent=2)

    def aggregate_fit(self, server_round, results, failures):
        """Agrega los modelos locales con FedAvg y guarda el modelo global."""
        aggregated = super().aggregate_fit(server_round, results, failures)

        if aggregated is not None:
            params_aggregated, metrics = aggregated

            # Guardar modelo global
            modelo_global = crear_modelo(self.n_features)
            params_list   = fl.common.parameters_to_ndarrays(params_aggregated)
            set_model_params(modelo_global, params_list)

            torch.save({
                "model_state":  modelo_global.state_dict(),
                "n_features":   self.n_features,
                "n_classes":    N_CLASES,
                "hidden_size":  64,
                "n_layers":     2,
                "ronda":        server_round,
                "fecha":        datetime.now().isoformat(),
                "mitre_phases": MITRE_PHASES,
            }, f"{MODELS_PATH}/lstm_federated_r{server_round}.pt")

            # Guardar como modelo principal si es la ultima ronda
            torch.save({
                "model_state":  modelo_global.state_dict(),
                "n_features":   self.n_features,
                "n_classes":    N_CLASES,
                "hidden_size":  64,
                "n_layers":     2,
                "ronda":        server_round,
                "fecha":        datetime.now().isoformat(),
                "mitre_phases": MITRE_PHASES,
            }, f"{MODELS_PATH}/lstm_noctua.pt")

            print(f"[Servidor FL] Ronda {server_round} completada — modelo global guardado")

        return aggregated

    def aggregate_evaluate(self, server_round, results, failures):
        """Registra las metricas de evaluacion de cada ronda."""
        aggregated = super().aggregate_evaluate(server_round, results, failures)

        if results:
            accs = [r.metrics.get("accuracy", 0) for _, r in results]
            acc_media = sum(accs) / len(accs) if accs else 0.0
            entrada = {
                "ronda":       server_round,
                "accuracy":    round(acc_media, 4),
                "n_clientes":  len(results),
                "timestamp":   datetime.now().isoformat(),
            }
            self.historial.append(entrada)
            self._guardar_historial()
            print(f"[Servidor FL] Ronda {server_round} | Accuracy media: {acc_media:.4f} | Clientes: {len(results)}")

        return aggregated


# ── Datos sinteticos para nodos simulados ────────────────────────────────────

def generar_datos_nodo(node_id: int, n_muestras: int = 20) -> Tuple[np.ndarray, np.ndarray]:
    """
    Genera datos sinteticos para un nodo simulado.
    En produccion cada nodo usaria sus propios datos reales de Wazuh.
    """
    np.random.seed(node_id * 42)

    # Cada nodo "ve" patrones ligeramente distintos segun su entorno
    X = np.random.randn(n_muestras, 32, 9).astype(np.float32)

    # Simular distribucion realista de fases APT
    # Nodo 1: principalmente initial_access (VPS expuesto)
    # Nodo 2: mezcla de fases (red corporativa)
    # Nodo 3: reconnaissance y discovery (objetivo de APT)
    if node_id == 1:
        y = np.random.choice([1, 0], size=n_muestras, p=[0.7, 0.3])
    elif node_id == 2:
        y = np.random.choice([0, 1, 7, 8], size=n_muestras, p=[0.3, 0.3, 0.2, 0.2])
    else:
        y = np.random.choice([0, 7, 11], size=n_muestras, p=[0.4, 0.4, 0.2])

    return X, y.astype(np.int64)


# ── Simulacion local de FL (sin red) ─────────────────────────────────────────

def simular_federated_learning(n_rondas: int = 5, n_nodos: int = 3):
    """
    Simula el proceso de Federated Learning localmente.
    Util para desarrollo y validacion sin necesidad de red.

    En produccion cada nodo correria en un VPS separado.
    """
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Federated Learning (Simulacion Local)")
    print("="*60)
    print(f"Nodos: {n_nodos} | Rondas: {n_rondas}")
    print("Cada nodo entrena con sus propios datos — datos no se comparten")
    print("="*60)

    # Cargar datos reales del nodo principal si existen
    X_real, y_real = None, None
    if os.path.exists(f"{MODELS_PATH}/X_pipeline.npy"):
        X_real = np.load(f"{MODELS_PATH}/X_pipeline.npy")
        y_real = np.load(f"{MODELS_PATH}/y_pipeline.npy")
        print(f"\n[Nodo 1] Usando datos reales de Wazuh: {X_real.shape}")

    # Preparar datos de cada nodo
    nodos_datos = []
    for i in range(1, n_nodos + 1):
        if i == 1 and X_real is not None:
            X, y = X_real, y_real
            # Anadir sinteticos si solo hay una clase
            if len(np.unique(y)) < 2:
                X_s = X[:5].copy() * 0.8
                y_s = np.zeros(5, dtype=np.int64)
                X = np.vstack([X, X_s])
                y = np.concatenate([y, y_s])
        else:
            X, y = generar_datos_nodo(i)
        nodos_datos.append((i, X, y))
        print(f"[Nodo {i}] {X.shape[0]} muestras | Clases: {np.unique(y).tolist()}")

    # Modelo global inicial
    n_features   = nodos_datos[0][1].shape[2]
    modelo_global = crear_modelo(n_features)
    historial_fl  = []

    print("\n--- Iniciando rondas de Federated Learning ---")

    for ronda in range(1, n_rondas + 1):
        print(f"\n[Ronda {ronda}/{n_rondas}]")

        params_globales = get_model_params(modelo_global)
        params_locales  = []
        n_muestras_total = 0
        accs_ronda = []

        for node_id, X, y in nodos_datos:
            cliente = NoctuaFLClient(node_id, X, y)
            # Simular fit
            params_nuevos, n, metricas_fit = cliente.fit(
                params_globales,
                {"local_epochs": 3, "batch_size": 4, "lr": 1e-3}
            )
            # Simular evaluate
            loss_val, n_val, metricas_eval = cliente.evaluate(params_globales, {})
            params_locales.append((params_nuevos, n))
            n_muestras_total += n
            accs_ronda.append(metricas_eval.get("accuracy", 0))

        # FedAvg: promedio ponderado por numero de muestras
        params_agregados = []
        for i in range(len(params_locales[0][0])):
            param_pond = sum(
                p[0][i] * p[1] for p in params_locales
            ) / n_muestras_total
            params_agregados.append(param_pond)

        # Actualizar modelo global
        set_model_params(modelo_global, params_agregados)

        acc_media = sum(accs_ronda) / len(accs_ronda)
        entrada = {
            "ronda":      ronda,
            "accuracy":   round(acc_media, 4),
            "n_clientes": n_nodos,
            "timestamp":  datetime.now().isoformat(),
        }
        historial_fl.append(entrada)
        print(f"  FedAvg completado | Accuracy media: {acc_media:.4f}")

    # Guardar modelo federado final
    torch.save({
        "model_state":  modelo_global.state_dict(),
        "n_features":   n_features,
        "n_classes":    N_CLASES,
        "hidden_size":  64,
        "n_layers":     2,
        "ronda":        n_rondas,
        "fecha":        datetime.now().isoformat(),
        "mitre_phases": MITRE_PHASES,
        "modo":         "federado_simulado",
        "n_nodos":      n_nodos,
    }, f"{MODELS_PATH}/lstm_noctua.pt")

    # Guardar historial
    with open(FL_LOG, "w") as f:
        json.dump(historial_fl, f, indent=2)

    print(f"\n[FL] Modelo federado guardado en {MODELS_PATH}/lstm_noctua.pt")
    print(f"[FL] Historial guardado en {FL_LOG}")
    print("\n" + "="*60)
    print("Federated Learning completado")
    print(f"Accuracy final: {historial_fl[-1]['accuracy']:.4f}")
    print("="*60 + "\n")

    return modelo_global, historial_fl


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Noctua Predictive — Federated Learning")
    parser.add_argument("modo", choices=["simular", "server", "client"],
                        help="simular: local sin red | server: servidor FL | client: nodo cliente")
    parser.add_argument("--rondas",  type=int, default=5,  help="Numero de rondas FL")
    parser.add_argument("--nodos",   type=int, default=3,  help="Numero de nodos (solo simular)")
    parser.add_argument("--node-id", type=int, default=1,  help="ID del nodo cliente")
    parser.add_argument("--server",  type=str, default="localhost:8080", help="Direccion del servidor FL")
    args = parser.parse_args()

    if args.modo == "simular":
        modelo, historial = simular_federated_learning(
            n_rondas=args.rondas,
            n_nodos=args.nodos
        )

    elif args.modo == "server":
        print(f"[Servidor FL] Iniciando en {args.server} | Rondas: {args.rondas}")
        estrategia = NoctuaFedAvg(
            n_features=9,
            min_fit_clients=2,
            min_evaluate_clients=2,
            min_available_clients=2,
            fraction_fit=1.0,
            fraction_evaluate=1.0,
        )
        fl.server.start_server(
            server_address=args.server,
            config=fl.server.ServerConfig(num_rounds=args.rondas),
            strategy=estrategia,
        )

    elif args.modo == "client":
        print(f"[Nodo {args.node_id}] Conectando a {args.server}")
        if args.node_id == 1 and os.path.exists(f"{MODELS_PATH}/X_pipeline.npy"):
            X = np.load(f"{MODELS_PATH}/X_pipeline.npy")
            y = np.load(f"{MODELS_PATH}/y_pipeline.npy")
            if len(np.unique(y)) < 2:
                X_s = X[:5].copy() * 0.8
                y_s = np.zeros(5, dtype=np.int64)
                X   = np.vstack([X, X_s])
                y   = np.concatenate([y, y_s])
        else:
            X, y = generar_datos_nodo(args.node_id)

        cliente = NoctuaFLClient(args.node_id, X, y)
        fl.client.start_client(
            server_address=args.server,
            client=cliente.to_client(),
        )
