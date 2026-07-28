"""
Noctua Predictive — Modelo LSTM para Deteccion de Campanas APT
Modulo 2: Definicion, entrenamiento y evaluacion del modelo LSTM

Entrena un modelo LSTM sobre las ventanas temporales generadas por apt_pipeline.py
para clasificar secuencias de eventos en fases MITRE ATT&CK.
"""

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split
from sklearn.metrics import classification_report, f1_score
import pickle
import os
from pathlib import Path
from datetime import datetime

MODELS_PATH = "/root/asoar/models"
Path(MODELS_PATH).mkdir(parents=True, exist_ok=True)

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
N_CLASES = len(MITRE_PHASES)


# ── Dataset ───────────────────────────────────────────────────────────────────
class APTDataset(Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


# ── Modelo LSTM ───────────────────────────────────────────────────────────────
class NoctuaLSTM(nn.Module):
    """
    Red LSTM para clasificacion de fases APT en secuencias de eventos de red.

    Arquitectura:
    - Capa LSTM bidireccional con dropout para regularizacion
    - Capa de atencion simple para ponderar eventos mas relevantes
    - Clasificador final con capas densas
    """

    def __init__(self, n_features: int, hidden_size: int = 64,
                 n_layers: int = 2, n_classes: int = N_CLASES,
                 dropout: float = 0.3):
        super(NoctuaLSTM, self).__init__()

        self.hidden_size = hidden_size
        self.n_layers    = n_layers

        # LSTM bidireccional
        self.lstm = nn.LSTM(
            input_size=n_features,
            hidden_size=hidden_size,
            num_layers=n_layers,
            batch_first=True,
            dropout=dropout if n_layers > 1 else 0,
            bidirectional=True
        )

        # Atencion simple
        self.atencion = nn.Linear(hidden_size * 2, 1)

        # Clasificador
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * 2, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, n_classes)
        )

    def forward(self, x):
        # x: (batch, seq_len, n_features)
        lstm_out, _ = self.lstm(x)
        # lstm_out: (batch, seq_len, hidden_size * 2)

        # Pesos de atencion
        attn_weights = torch.softmax(self.atencion(lstm_out), dim=1)
        # Contexto ponderado
        context = (lstm_out * attn_weights).sum(dim=1)
        # Clasificacion
        out = self.classifier(context)
        return out

    def predecir_fase(self, x: torch.Tensor) -> tuple:
        """
        Predice la fase MITRE para una secuencia.
        Retorna (fase_str, confianza)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs  = torch.softmax(logits, dim=-1)
            idx    = probs.argmax(dim=-1).item()
            conf   = probs[0][idx].item()
        return MITRE_PHASES[idx], round(conf * 100, 1)


# ── Entrenamiento ─────────────────────────────────────────────────────────────
def entrenar_modelo(X: np.ndarray, y: np.ndarray,
                    epochs: int = 50,
                    batch_size: int = 8,
                    lr: float = 1e-3,
                    val_split: float = 0.2) -> NoctuaLSTM:

    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Entrenamiento LSTM")
    print("="*60)
    print(f"Datos: {X.shape[0]} ventanas, {X.shape[1]} pasos, {X.shape[2]} features")
    print(f"Clases: {N_CLASES} fases MITRE ATT&CK")
    print(f"Epochs: {epochs} | Batch: {batch_size} | LR: {lr}")

    device = torch.device("cpu")
    dataset = APTDataset(X, y)

    # Split train/val
    n_val   = max(1, int(len(dataset) * val_split))
    n_train = len(dataset) - n_val
    train_ds, val_ds = random_split(dataset, [n_train, n_val])

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False)

    modelo = NoctuaLSTM(
        n_features=X.shape[2],
        hidden_size=64,
        n_layers=2,
        n_classes=N_CLASES,
        dropout=0.3
    ).to(device)

    # Pesos de clase para manejar desbalance
    class_counts = np.bincount(y, minlength=N_CLASES).astype(np.float32)
    class_counts = np.where(class_counts == 0, 1, class_counts)
    class_weights = torch.tensor(1.0 / class_counts).to(device)

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(modelo.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, patience=5, factor=0.5
    )

    mejor_f1    = 0.0
    mejor_epoch = 0
    historial   = []

    for epoch in range(1, epochs + 1):
        # Entrenamiento
        modelo.train()
        loss_train = 0.0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            logits = modelo(X_batch)
            loss   = criterion(logits, y_batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(modelo.parameters(), 1.0)
            optimizer.step()
            loss_train += loss.item()

        # Validacion
        modelo.eval()
        preds_val, labels_val = [], []
        loss_val = 0.0
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                logits = modelo(X_batch)
                loss   = criterion(logits, y_batch)
                loss_val += loss.item()
                preds_val.extend(logits.argmax(dim=-1).cpu().numpy())
                labels_val.extend(y_batch.cpu().numpy())

        f1 = f1_score(labels_val, preds_val, average="weighted",
                      zero_division=0) if len(set(labels_val)) > 1 else 0.0
        scheduler.step(loss_val)

        historial.append({
            "epoch": epoch,
            "loss_train": round(loss_train / len(train_loader), 4),
            "loss_val":   round(loss_val   / max(len(val_loader), 1), 4),
            "f1_val":     round(f1, 4),
        })

        if epoch % 10 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d}/{epochs} | "
                  f"Loss train: {historial[-1]['loss_train']:.4f} | "
                  f"Loss val: {historial[-1]['loss_val']:.4f} | "
                  f"F1: {f1:.4f}")

        if f1 > mejor_f1:
            mejor_f1    = f1
            mejor_epoch = epoch
            torch.save(modelo.state_dict(), f"{MODELS_PATH}/lstm_best.pt")

    print(f"\n  Mejor F1: {mejor_f1:.4f} en epoch {mejor_epoch}")

    # Cargar mejor modelo
    modelo.load_state_dict(torch.load(f"{MODELS_PATH}/lstm_best.pt",
                                       map_location=device))

    # Guardar modelo completo
    torch.save({
        "model_state":  modelo.state_dict(),
        "n_features":   X.shape[2],
        "n_classes":    N_CLASES,
        "hidden_size":  64,
        "n_layers":     2,
        "historial":    historial,
        "mejor_f1":     mejor_f1,
        "fecha":        datetime.now().isoformat(),
        "mitre_phases": MITRE_PHASES,
    }, f"{MODELS_PATH}/lstm_noctua.pt")

    print(f"  Modelo guardado en {MODELS_PATH}/lstm_noctua.pt")
    print("="*60 + "\n")
    return modelo


# ── Evaluacion ────────────────────────────────────────────────────────────────
def evaluar_modelo(modelo: NoctuaLSTM, X: np.ndarray, y: np.ndarray):
    """Imprime el classification report completo."""
    modelo.eval()
    dataset = APTDataset(X, y)
    loader  = DataLoader(dataset, batch_size=16, shuffle=False)
    preds, labels = [], []
    with torch.no_grad():
        for X_batch, y_batch in loader:
            logits = modelo(X_batch)
            preds.extend(logits.argmax(dim=-1).cpu().numpy())
            labels.extend(y_batch.cpu().numpy())

    clases_presentes = sorted(set(labels))
    nombres = [MITRE_PHASES[i] for i in clases_presentes]
    print("\n[Evaluacion] Classification Report:")
    print(classification_report(
        labels, preds,
        labels=clases_presentes,
        target_names=nombres,
        zero_division=0
    ))


# ── Inferencia sobre nuevas ventanas ─────────────────────────────────────────
def cargar_modelo() -> NoctuaLSTM:
    """Carga el modelo entrenado desde disco."""
    checkpoint = torch.load(f"{MODELS_PATH}/lstm_noctua.pt",
                             map_location="cpu")
    modelo = NoctuaLSTM(
        n_features=checkpoint["n_features"],
        hidden_size=checkpoint["hidden_size"],
        n_layers=checkpoint["n_layers"],
        n_classes=checkpoint["n_classes"],
    )
    modelo.load_state_dict(checkpoint["model_state"])
    modelo.eval()
    return modelo


def predecir_ventana(modelo: NoctuaLSTM, ventana: np.ndarray) -> dict:
    """
    Predice la fase APT de una ventana de eventos.

    ventana: array (seq_len, n_features)
    Retorna dict con fase, confianza y nivel de alerta.
    """
    x = torch.tensor(ventana, dtype=torch.float32).unsqueeze(0)
    fase, confianza = modelo.predecir_fase(x)

    nivel_alerta = "BAJO"
    if fase in ["lateral_movement", "exfiltration", "privilege_escalation"]:
        nivel_alerta = "CRITICO"
    elif fase in ["persistence", "credential_access", "defense_evasion"]:
        nivel_alerta = "ALTO"
    elif fase in ["initial_access", "execution", "discovery"]:
        nivel_alerta = "MEDIO"
    elif fase == "reconnaissance":
        nivel_alerta = "BAJO"

    return {
        "fase_mitre":    fase,
        "confianza":     confianza,
        "nivel_alerta":  nivel_alerta,
        "timestamp":     datetime.now().isoformat(),
    }


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Cargar datos del pipeline
    X_path = f"{MODELS_PATH}/X_pipeline.npy"
    y_path = f"{MODELS_PATH}/y_pipeline.npy"

    if not os.path.exists(X_path):
        print("ERROR: Ejecuta primero apt_pipeline.py para generar los datos.")
        exit(1)

    X = np.load(X_path)
    y = np.load(y_path)

    print(f"Datos cargados: X={X.shape}, y={y.shape}")
    print(f"Clases en y: {np.unique(y)}")
    print(f"Distribucion: {dict(zip(*np.unique(y, return_counts=True)))}")

    if len(np.unique(y)) < 2:
        print("\nAVISO: Solo hay una clase en los datos actuales.")
        print("Esto es normal — el servidor tiene principalmente ataques de")
        print("'initial_access' (SSH brute force). El modelo se entrena igual")
        print("y mejorara a medida que se acumulen mas datos con mas variedad.")
        print("\nAnadiendo clase 'reconnaissance' sintetica para entrenamiento inicial...")

        # Anadir ejemplos sinteticos de reconocimiento para poder entrenar
        n_sinteticos = max(3, len(X) // 3)
        X_sint = X[:n_sinteticos].copy()
        # Modificar ligeramente los features para simular reconocimiento
        X_sint[:, :, 0] *= 0.5   # nivel mas bajo
        X_sint[:, :, 1]  = 0     # fase 0 = reconnaissance
        y_sint = np.zeros(n_sinteticos, dtype=np.int64)  # reconnaissance

        X = np.vstack([X, X_sint])
        y = np.concatenate([y, y_sint])
        print(f"Datos ampliados: X={X.shape}, y={y.shape}")

    modelo = entrenar_modelo(X, y, epochs=50, batch_size=4)
    evaluar_modelo(modelo, X, y)

    # Test de inferencia
    print("\n[Test] Prediccion sobre primera ventana:")
    resultado = predecir_ventana(modelo, X[0])
    print(f"  Fase detectada : {resultado['fase_mitre']}")
    print(f"  Confianza      : {resultado['confianza']}%")
    print(f"  Nivel de alerta: {resultado['nivel_alerta']}")
