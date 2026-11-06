#!/usr/bin/env python3
"""
Experimento FL (Opcion B) — Centralizado vs Federado sobre datos REALES repartidos non-IID.
- NO toca produccion: guarda el modelo en models/lstm_federado_real.pt (NUNCA lstm_noctua.pt)
  y los resultados en fl_comparativa_real.json / fl_historial_real.json (ficheros nuevos).
- Reparte el dataset combinado real entre N nodos de forma non-IID (cada nodo ve clases distintas),
  como organizaciones con datos heterogeneos.
- Comparacion justa: mismo conjunto de test para centralizado y federado.
Uso: python3 fl_experimento_real.py [--rondas 20] [--nodos 3] [--epochs-locales 3]
"""
import os, sys, json, argparse
import numpy as np
import torch
import torch.nn as nn
from datetime import datetime
from torch.utils.data import DataLoader
from sklearn.metrics import f1_score

sys.path.insert(0, "/root/asoar")
from apt_federated import NoctuaFLClient, crear_modelo, get_model_params, set_model_params
from apt_lstm import APTDataset, N_CLASES

MODELS = "/root/asoar/models"
OUT_MODEL = f"{MODELS}/lstm_federado_real.pt"          # NUEVO, no pisa produccion
OUT_COMP  = "/root/asoar/fl_comparativa_real.json"      # NUEVO
OUT_HIST  = "/root/asoar/fl_historial_real.json"        # NUEVO

def cargar_dataset():
    for base in ("X_combined", "X_pipeline"):
        xp, yp = f"{MODELS}/{base}.npy", f"{MODELS}/{base.replace('X_','y_')}.npy"
        if os.path.exists(xp) and os.path.exists(yp):
            X = np.load(xp).astype(np.float32); y = np.load(yp).astype(np.int64)
            print(f"[Datos] {base}: X={X.shape}  clases={np.bincount(y, minlength=N_CLASES).tolist()}")
            return X, y, base
    raise SystemExit("No se encontro X_combined.npy ni X_pipeline.npy en models/")

def split_train_test(X, y, test_frac=0.25, seed=42):
    rng = np.random.default_rng(seed)
    idx_tr, idx_te = [], []
    for c in np.unique(y):                       # split estratificado por clase
        ci = np.where(y == c)[0]; rng.shuffle(ci)
        k = max(1, int(round(len(ci) * test_frac))) if len(ci) > 1 else 0
        idx_te += ci[:k].tolist(); idx_tr += ci[k:].tolist()
    rng.shuffle(idx_tr); rng.shuffle(idx_te)
    return np.array(idx_tr), np.array(idx_te)

def particion_noniid(y_tr, n_nodos, seed=42):
    """Reparto non-IID: ordena por etiqueta y corta en shards contiguos -> cada nodo ve clases sesgadas."""
    order = np.argsort(y_tr, kind="stable")
    shards = np.array_split(order, n_nodos)
    return [np.array(s) for s in shards]

@torch.no_grad()
def evaluar(modelo, X, y):
    modelo.eval()
    loader = DataLoader(APTDataset(X, y), batch_size=16, shuffle=False)
    ytrue, ypred = [], []
    for Xb, yb in loader:
        logits = modelo(Xb)
        ypred += logits.argmax(dim=-1).tolist(); ytrue += yb.tolist()
    acc = float(np.mean(np.array(ypred) == np.array(ytrue))) if ytrue else 0.0
    f1 = float(f1_score(ytrue, ypred, average="macro", zero_division=0))
    return acc, f1

def entrenar_local(X, y, params_iniciales, epochs, node_id=0):
    """Usa el cliente FL real para entrenar localmente y devolver sus parametros."""
    cli = NoctuaFLClient(node_id, X, y)
    nuevos, n, _ = cli.fit(params_iniciales, {"local_epochs": epochs, "batch_size": 4, "lr": 1e-3})
    return nuevos, n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rondas", type=int, default=20)
    ap.add_argument("--nodos", type=int, default=3)
    ap.add_argument("--epochs-locales", type=int, default=3)
    a = ap.parse_args()

    X, y, fuente = cargar_dataset()
    n_features = X.shape[2]
    itr, ite = split_train_test(X, y)
    Xtr, ytr, Xte, yte = X[itr], y[itr], X[ite], y[ite]
    print(f"[Split] train={len(itr)}  test={len(ite)}  features={n_features}")

    # ---------- CENTRALIZADO (baseline, mismos datos de train) ----------
    print("\n=== CENTRALIZADO ===")
    m0 = crear_modelo(n_features)
    p0 = get_model_params(m0)
    p_cent, _ = entrenar_local(Xtr, ytr, p0, epochs=a.rondas * a.epochs_locales, node_id=0)
    mc = crear_modelo(n_features); set_model_params(mc, p_cent)
    acc_c, f1_c = evaluar(mc, Xte, yte)
    print(f"Centralizado -> acc={acc_c:.4f}  f1_macro={f1_c:.4f}")

    # ---------- FEDERADO non-IID ----------
    print("\n=== FEDERADO (non-IID) ===")
    shards = particion_noniid(ytr, a.nodos)
    for i, s in enumerate(shards, 1):
        print(f"[Nodo {i}] {len(s)} muestras | clases={np.bincount(ytr[s], minlength=N_CLASES).tolist()}")

    glob = crear_modelo(n_features)
    hist = []
    for ronda in range(1, a.rondas + 1):
        pg = get_model_params(glob)
        locales, pesos = [], []
        for i, s in enumerate(shards, 1):
            if len(s) < 2:   # nodo demasiado pequeno: lo saltamos esta ronda
                continue
            pl, n = entrenar_local(Xtr[s], ytr[s], pg, epochs=a.epochs_locales, node_id=i)
            locales.append(pl); pesos.append(n)
        total = sum(pesos)
        agg = [sum(pl[k] * w for pl, w in zip(locales, pesos)) / total
               for k in range(len(locales[0]))]
        set_model_params(glob, agg)
        acc_r, f1_r = evaluar(glob, Xte, yte)
        hist.append({"ronda": ronda, "accuracy": round(acc_r, 4), "f1_macro": round(f1_r, 4),
                     "n_clientes": len(pesos), "timestamp": datetime.now().isoformat()})
        print(f"[Ronda {ronda:2d}/{a.rondas}] acc={acc_r:.4f}  f1_macro={f1_r:.4f}  clientes={len(pesos)}")

    acc_f, f1_f = hist[-1]["accuracy"], hist[-1]["f1_macro"]

    # ---------- Guardar (ficheros NUEVOS, produccion intacta) ----------
    torch.save({"model_state": glob.state_dict(), "n_features": n_features,
                "n_classes": N_CLASES, "hidden_size": 64, "n_layers": 2,
                "modo": "federado_real_noniid", "n_nodos": a.nodos,
                "fecha": datetime.now().isoformat()}, OUT_MODEL)
    comp = {
        "fecha": datetime.now().isoformat(), "fuente_datos": fuente,
        "n_train": int(len(itr)), "n_test": int(len(ite)), "n_clases": int(N_CLASES),
        "centralizado": {"acc": round(acc_c, 4), "f1_macro": round(f1_c, 4)},
        "federado": {"acc": round(acc_f, 4), "f1_macro": round(f1_f, 4),
                      "n_nodos": a.nodos, "n_rondas": a.rondas, "reparto": "non-IID",
                      "distribucion_nodos": [np.bincount(ytr[s], minlength=N_CLASES).tolist() for s in shards]},
        "brecha_acc": round(acc_f - acc_c, 4), "brecha_f1": round(f1_f - f1_c, 4),
    }
    with open(OUT_COMP, "w") as f: json.dump(comp, f, indent=2)
    with open(OUT_HIST, "w") as f: json.dump(hist, f, indent=2)

    print("\n" + "=" * 56)
    print(f"  CENTRALIZADO : acc={acc_c:.4f}  f1={f1_c:.4f}")
    print(f"  FEDERADO     : acc={acc_f:.4f}  f1={f1_f:.4f}  ({a.nodos} nodos non-IID)")
    print(f"  BRECHA (fed-cent): acc={acc_f-acc_c:+.4f}  f1={f1_f-f1_c:+.4f}")
    print(f"  Modelo  -> {OUT_MODEL}")
    print(f"  Results -> {OUT_COMP}")
    print("  Produccion (lstm_noctua.pt) NO modificado.")
    print("=" * 56)

if __name__ == "__main__":
    main()
