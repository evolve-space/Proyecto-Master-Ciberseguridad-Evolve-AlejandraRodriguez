#!/usr/bin/env python3
"""
noctua_features.py — Ruta de vectorizacion UNIFICADA (fuente unica de verdad).

Objetivo: que entrenamiento e inferencia construyan el vector de la MISMA forma,
eliminando el train/serve skew. Un unico codigo de features, importado por ambos.

Diseno (cerrado 14/10):
- Features de COMPORTAMIENTO: red (Zeek conn) + host (agente Wazuh; 0 si ausente).
- Unidad de AGREGACION: ventana fija pequena parametrizable (VENTANA_SEG, def. 600 s).
- SECUENCIA por entidad (IP): solo ventanas CON actividad, ordenadas en el tiempo.
- Delta-t: canal APARTE (segundos entre ventanas consecutivas). Es lo que consumen
  los modelos time-aware (M1: feature Dt; M2: celda con decaimiento). B0 lo ignora.
- Scaler unico (z-score) ajustado una vez y guardado; aplicado igual en train e inferencia.

NO toca produccion. Ejecutar `python3 noctua_features.py` corre el self-test
(prueba de "vector identico": ruta batch == ruta incremental).
"""
from __future__ import annotations
import os, math, pickle
from collections import defaultdict

import numpy as np

try:
    from sklearn.preprocessing import StandardScaler
except Exception:                       # permitir import sin sklearn (solo para inspeccion)
    StandardScaler = None

MODELS_PATH   = "/root/asoar/models"
SCALER_PATH   = f"{MODELS_PATH}/scaler_features.pkl"
VENTANA_SEG   = 600                      # 10 min por defecto (parametrizable)

# ── Esquema de features canonico (ORDEN FIJO) ─────────────────────────────────
#   red (Zeek)                         host (agente Wazuh; 0 si no hay)
FEATURES = [
    "n_conn", "frac_s0", "frac_no_resp", "n_rports", "n_svcs",
    "dur_mean", "ob_log", "rb_log", "op_log", "rp_log", "frac_tcp",
    "h_auth_fail", "h_auth_ok", "h_proc_exec", "h_new_user", "h_file_integ", "h_nivel_max",
]
N_FEATURES = len(FEATURES)
CLASES_HOST = {"auth_fail", "auth_ok", "proc_exec", "new_user", "file_integ"}


# ── Normalizacion de eventos crudos a un mini-esquema comun ───────────────────
# Cada evento es un dict con al menos: ts (epoch float), entity (ip), kind ('net'|'host').
#   net : resp_p, service, proto, conn_state, resp_pkts, duration, orig_bytes,
#         resp_bytes, orig_pkts
#   host: clase (una de CLASES_HOST), nivel (int)

def _nuevo_acumulador():
    return {
        "n": 0, "s0": 0, "no_resp": 0, "tcp": 0,
        "rports": set(), "svcs": set(),
        "dur": 0.0, "ob": 0.0, "rb": 0.0, "op": 0.0, "rp": 0.0,
        "h_auth_fail": 0, "h_auth_ok": 0, "h_proc_exec": 0,
        "h_new_user": 0, "h_file_integ": 0, "h_nivel_max": 0,
    }


def acumular(acc: dict, ev: dict) -> None:
    """Acumula UN evento en el acumulador de su ventana (misma logica para train/serve)."""
    if ev.get("kind") == "net":
        acc["n"] += 1
        if ev.get("conn_state") == "S0":
            acc["s0"] += 1
        if float(ev.get("resp_pkts", 0) or 0) == 0:
            acc["no_resp"] += 1
        if ev.get("proto") == "tcp":
            acc["tcp"] += 1
        rp = ev.get("resp_p")
        if rp not in (None, "-", ""):
            acc["rports"].add(rp)
        sv = ev.get("service")
        if sv not in (None, "-", ""):
            acc["svcs"].add(sv)
        acc["dur"] += float(ev.get("duration", 0) or 0)
        acc["ob"]  += float(ev.get("orig_bytes", 0) or 0)
        acc["rb"]  += float(ev.get("resp_bytes", 0) or 0)
        acc["op"]  += float(ev.get("orig_pkts", 0) or 0)
        acc["rp"]  += float(ev.get("resp_pkts", 0) or 0)
    elif ev.get("kind") == "host":
        clase = ev.get("clase")
        if clase in CLASES_HOST:
            acc["h_" + clase] += 1
        acc["h_nivel_max"] = max(acc["h_nivel_max"], int(ev.get("nivel", 0) or 0))


def vectorizar_ventana(acc: dict) -> np.ndarray:
    """Convierte un acumulador de ventana en el vector canonico (pre-escalado)."""
    n = max(acc["n"], 1)
    vec = np.array([
        acc["n"],
        acc["s0"] / n,
        acc["no_resp"] / n,
        len(acc["rports"]),
        len(acc["svcs"]),
        acc["dur"] / n,
        math.log1p(acc["ob"]),
        math.log1p(acc["rb"]),
        math.log1p(acc["op"]),
        math.log1p(acc["rp"]),
        acc["tcp"] / n,
        acc["h_auth_fail"], acc["h_auth_ok"], acc["h_proc_exec"],
        acc["h_new_user"], acc["h_file_integ"], acc["h_nivel_max"],
    ], dtype=np.float64)
    assert vec.shape[0] == N_FEATURES
    return vec


def _idx_ventana(ts: float, ventana_seg: int) -> int:
    return int(ts // ventana_seg)


# ── RUTA 1 (batch, para ENTRENAMIENTO): todos los eventos de golpe ────────────
def construir_secuencias(eventos, ventana_seg: int = VENTANA_SEG):
    """
    eventos: iterable de dicts (net/host) con ts y entity.
    Devuelve {entity: {"X": (n_win, N_FEATURES), "dt": (n_win,), "win_ts": (n_win,)}}
    Solo ventanas con actividad; dt = segundos entre inicios de ventanas consecutivas.
    """
    por_entidad = defaultdict(lambda: defaultdict(_nuevo_acumulador))
    for ev in eventos:
        idx = _idx_ventana(float(ev["ts"]), ventana_seg)
        acumular(por_entidad[ev["entity"]][idx], ev)

    salida = {}
    for ent, ventanas in por_entidad.items():
        idxs = sorted(ventanas.keys())
        X = np.stack([vectorizar_ventana(ventanas[i]) for i in idxs], axis=0)
        win_ts = np.array([i * ventana_seg for i in idxs], dtype=np.float64)
        dt = np.zeros(len(idxs), dtype=np.float64)
        dt[1:] = np.diff(win_ts)
        salida[ent] = {"X": X, "dt": dt, "win_ts": win_ts}
    return salida


# ── RUTA 2 (incremental, para INFERENCIA en vivo): evento a evento ────────────
class SecuenciadorEnVivo:
    """
    Mantiene, por entidad, la ventana en curso. Al avanzar de ventana, CIERRA la
    anterior y la vectoriza con la MISMA funcion que la ruta batch.
    Uso: s.agregar(ev) -> devuelve (entity, vector, dt) cuando cierra una ventana,
    o None mientras la ventana sigue abierta. flush() cierra las pendientes.
    """
    def __init__(self, ventana_seg: int = VENTANA_SEG):
        self.ventana_seg = ventana_seg
        self._acc = {}        # entity -> acumulador
        self._idx = {}        # entity -> idx ventana en curso
        self._ult_ts = {}     # entity -> win_ts de la ultima ventana cerrada

    def agregar(self, ev: dict):
        ent = ev["entity"]
        idx = _idx_ventana(float(ev["ts"]), self.ventana_seg)
        cerrado = None
        if ent in self._idx and idx != self._idx[ent]:
            cerrado = self._cerrar(ent)
        if ent not in self._acc or (ent in self._idx and idx != self._idx[ent]):
            self._acc[ent] = _nuevo_acumulador()
            self._idx[ent] = idx
        acumular(self._acc[ent], ev)
        return cerrado

    def _cerrar(self, ent: str):
        idx = self._idx[ent]
        vec = vectorizar_ventana(self._acc[ent])
        win_ts = idx * self.ventana_seg
        dt = 0.0 if ent not in self._ult_ts else (win_ts - self._ult_ts[ent])
        self._ult_ts[ent] = win_ts
        del self._acc[ent]; del self._idx[ent]
        return {"entity": ent, "X": vec, "dt": dt, "win_ts": win_ts}

    def flush(self):
        return [self._cerrar(e) for e in list(self._idx.keys())]


# ── Scaler unico (z-score) ────────────────────────────────────────────────────
def ajustar_scaler(X_all: np.ndarray, guardar: bool = True):
    if StandardScaler is None:
        raise RuntimeError("sklearn no disponible")
    sc = StandardScaler().fit(X_all)
    if guardar:
        os.makedirs(MODELS_PATH, exist_ok=True)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump({"scaler": sc, "features": FEATURES}, f)
    return sc


def cargar_scaler():
    with open(SCALER_PATH, "rb") as f:
        d = pickle.load(f)
    return d["scaler"]


def aplicar_scaler(X: np.ndarray, sc) -> np.ndarray:
    return sc.transform(X)


# ── SELF-TEST: prueba de "vector identico" (batch == incremental) ─────────────
def _eventos_sinteticos(seed: int = 7):
    rng = np.random.default_rng(seed)
    evs = []
    base = 1_760_000_000.0
    # 2 IPs, con huecos temporales distintos (para que el dt sea variable)
    for ent, offsets in [("10.0.0.1", [0, 120, 300, 5000, 5200]),
                         ("10.0.0.2", [50, 60, 70, 20000])]:
        for off in offsets:
            # rafaga de conexiones en ese instante
            for _ in range(int(rng.integers(1, 6))):
                evs.append({"ts": base + off + rng.random(), "entity": ent, "kind": "net",
                            "conn_state": rng.choice(["S0", "SF", "REJ"]),
                            "resp_p": str(rng.integers(20, 25)), "service": rng.choice(["ssh", "-", "http"]),
                            "proto": "tcp", "resp_pkts": int(rng.integers(0, 3)),
                            "duration": float(rng.random()), "orig_bytes": float(rng.integers(0, 500)),
                            "resp_bytes": float(rng.integers(0, 500)), "orig_pkts": int(rng.integers(0, 5))})
            if rng.random() < 0.5:
                evs.append({"ts": base + off + rng.random(), "entity": ent, "kind": "host",
                            "clase": rng.choice(list(CLASES_HOST)), "nivel": int(rng.integers(3, 12))})
    rng.shuffle(evs)               # desordenados, como llegarian en vivo
    return evs


def self_test():
    print(f"noctua_features: {N_FEATURES} features, ventana={VENTANA_SEG}s")
    evs = _eventos_sinteticos()
    print(f"eventos sinteticos: {len(evs)}")

    # RUTA BATCH (entrenamiento)
    batch = construir_secuencias(evs, VENTANA_SEG)

    # RUTA INCREMENTAL (inferencia): eventos ORDENADOS por ts (como el buffer en vivo)
    seq = SecuenciadorEnVivo(VENTANA_SEG)
    vivos = defaultdict(list)
    for ev in sorted(evs, key=lambda e: e["ts"]):
        cerr = seq.agregar(ev)
        if cerr:
            vivos[cerr["entity"]].append((cerr["win_ts"], cerr["X"], cerr["dt"]))
    for cerr in seq.flush():
        vivos[cerr["entity"]].append((cerr["win_ts"], cerr["X"], cerr["dt"]))

    # COMPARACION: para cada entidad, mismos vectores y mismos dt
    ok = True
    for ent, b in batch.items():
        v = sorted(vivos.get(ent, []), key=lambda t: t[0])
        Xv = np.stack([x for _, x, _ in v], axis=0) if v else np.zeros((0, N_FEATURES))
        dtv = np.array([d for _, _, d in v])
        if Xv.shape != b["X"].shape or not np.allclose(Xv, b["X"]):
            ok = False; print(f"  [FALLO] {ent}: X difiere  batch={b['X'].shape} vivo={Xv.shape}")
        elif not np.allclose(dtv, b["dt"]):
            ok = False; print(f"  [FALLO] {ent}: dt difiere  batch={b['dt']} vivo={dtv}")
        else:
            print(f"  [OK] {ent}: {b['X'].shape[0]} ventanas identicas | dt={b['dt'].tolist()}")

    # prueba del scaler (solo si sklearn esta)
    if StandardScaler is not None:
        X_all = np.vstack([b["X"] for b in batch.values()])
        sc = ajustar_scaler(X_all, guardar=False)
        Xs = aplicar_scaler(X_all, sc)
        print(f"  scaler: media~{Xs.mean():.2e} std~{Xs.std():.3f} (esperado ~0 / ~1)")

    print("\nRESULTADO:", "VECTOR IDENTICO train==serve  ✓" if ok else "DISCREPANCIA  ✗")
    return ok


if __name__ == "__main__":
    import sys
    ok = self_test()
    sys.exit(0 if ok else 1)
