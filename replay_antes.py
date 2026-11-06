#!/usr/bin/env python3
# PASO 1 (carril ANTES) - SOLO LECTURA: reproduce una campana capturada por el
# detector ACTUAL (modelo vivo de 9 features, sin Dt) y muestra como la clasifica
# a lo largo del tiempo. NO toca tickets, buffers reales ni bloqueos.
import sys, json, glob
from datetime import datetime, timezone
import numpy as np
sys.path.insert(0, "/root/asoar")

cands = sorted(glob.glob('/root/asoar/poc/auto/atk_lento_*/eventos.json'))
CAMP = sys.argv[1] if len(sys.argv) > 1 else cands[0]

import apt_detector
apt_detector.buscar_conexion_zeek = lambda *a, **k: {}   # usar NUESTRO flow, no el zeek vivo
from apt_detector import DetectorAPT
from apt_lstm import predecir_ventana

det = DetectorAPT()
if not det.cargado:
    print("ERROR: modelo no cargado"); sys.exit(1)

def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")

ACK_OK = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "OTH", "ESTAB"}
def net_a_alerta(e):
    cs = e.get("conn_state", "")
    return {"ip": e["entity"], "abuse_score": 0,
            "flow": {"pkts_toserver": float(e.get("orig_pkts", 0)),
                     "pkts_toclient": float(e.get("resp_pkts", 0)),
                     "bytes_toserver": float(e.get("orig_bytes", 0)),
                     "bytes_toclient": float(e.get("resp_bytes", 0)),
                     "start": iso(e["ts"]), "end": iso(e["ts"] + float(e.get("duration", 0.0)))},
            "tcp": {"syn": e.get("proto") == "tcp", "ack": cs in ACK_OK}}
def host_a_alerta(e):
    return {"ip": e["entity"], "nivel": e.get("nivel", 0), "agente": "victima", "abuse_score": 0}

eventos = json.load(open(CAMP)); eventos.sort(key=lambda e: e["ts"])
t0 = eventos[0]["ts"]; ip = eventos[0]["entity"]
print("Campana:", CAMP)
print("Eventos: %d | IP atacante: %s | duracion: %.1f min\n" % (len(eventos), ip, (eventos[-1]["ts"]-t0)/60))

seq = []; fases_vistas = []; primera = None; hist = []
for e in eventos:
    alerta = net_a_alerta(e) if e.get("kind") == "net" else host_a_alerta(e)
    try:
        seq.append(det._alerta_a_vector(alerta))
    except Exception as ex:
        print("warn vector:", ex); continue
    if len(seq) < 2:
        continue
    try:
        r = predecir_ventana(det.modelo, np.array(seq, dtype=np.float32))
        fase = r["fase_mitre"]; conf = float(r["confianza"])
    except Exception as ex:
        continue
    apt = (fase not in ["unknown", "reconnaissance"] and conf > 5.0) or \
          (fase in ["lateral_movement", "exfiltration", "privilege_escalation"] and conf > 15.0)
    mins = (e["ts"] - t0) / 60
    if apt and primera is None:
        primera = (mins, fase, conf)
    if not fases_vistas or fases_vistas[-1] != fase:
        fases_vistas.append(fase); hist.append((mins, e.get("kind"), fase, conf, apt))

print("PROGRESION DE FASES QUE PREDICE EL MODELO ACTUAL (solo cambios):")
print("  %6s %5s %24s %7s %5s" % ("min", "kind", "fase", "conf%", "apt?"))
for mins, kind, fase, conf, apt in hist:
    print("  %6.1f %5s %24s %7.1f %5s" % (mins, kind, fase, conf, "SI" if apt else "no"))

print("\n--- RESUMEN (carril ANTES: modelo vivo 9-feat, SIN Dt) ---")
print("Primera deteccion APT: minuto %.1f (fase %s, conf %.1f%%)" % primera if primera
      else "NO llega a marcar apt_activo en toda la campana.")
print("Fases distintas predichas:", sorted(set(fases_vistas)))
print("Bloqueo? Politica actual = bloquear solo si AbuseIPDB>=90; IP de lab tiene abuse=0 -> NO bloquearia nunca.")
print("Tickets? Caeria en rama 'indicio BAJA' (abuse<50) -> tickets de prioridad BAJA, sin accion.")
