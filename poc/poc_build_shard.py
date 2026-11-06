#!/usr/bin/env python3
"""Construye el SHARD POSITIVO (Corrosion:2) via noctua_features. NO toca produccion."""
import sys, json, collections
from datetime import datetime, timezone
sys.path.insert(0, "/root/asoar")
import numpy as np
import noctua_features as nf

CONN_LOG="/root/asoar/poc/conn.log"; HOST_LOG="/root/poc_host_alerts.json"
OUT_NPZ ="/root/asoar/poc/shard_corrosion.npz"
OUT_EVS ="/root/asoar/poc/poc_eventos_corrosion.json"
ATACANTE="192.168.60.3"; VICTIMA="192.168.60.4"; ENTIDAD=ATACANTE

FASES=[("recon",(13,3,25)),("acceso_inicial",(13,6,20)),("ejecucion",(13,10,10)),
       ("lateral",(13,15,3)),("escalada",(13,19,49)),("persistencia",(13,27,9)),
       ("exfiltracion",(13,31,38)),("fin",(13,34,2))]
FASES_EP=[(n,datetime(2026,10,15,h,m,s,tzinfo=timezone.utc).timestamp()) for n,(h,m,s) in FASES]
CAMPANA_INI=FASES_EP[0][1]; CAMPANA_FIN=FASES_EP[-1][1]

def _f(x): return 0.0 if x in ("-","",None) else float(x)

def leer_conn(path):
    evs=[]; campos=None
    for ln in open(path):
        if ln.startswith("#fields"): campos=ln.rstrip("\n").split("\t")[1:]; continue
        if ln.startswith("#") or not ln.strip() or campos is None: continue
        r=dict(zip(campos, ln.rstrip("\n").split("\t")))
        if ATACANTE not in (r.get("id.orig_h"), r.get("id.resp_h")): continue
        evs.append({"ts":float(r["ts"]),"entity":ENTIDAD,"kind":"net",
            "resp_p":r.get("id.resp_p"),"service":r.get("service"),"proto":r.get("proto"),
            "conn_state":r.get("conn_state"),"resp_pkts":_f(r.get("resp_pkts")),
            "duration":_f(r.get("duration")),"orig_bytes":_f(r.get("orig_bytes")),
            "resp_bytes":_f(r.get("resp_bytes")),"orig_pkts":_f(r.get("orig_pkts"))})
    return evs

def _clase(groups):
    g=set(groups)
    if "adduser" in g: return "new_user"
    if "authentication_failed" in g: return "auth_fail"
    if "authentication_success" in g: return "auth_ok"
    if "sudo" in g: return "proc_exec"
    if "syscheck" in g: return "file_integ"
    return None

def _ts_wazuh(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%dT%H:%M:%S%z"):
        try: return datetime.strptime(s,fmt).timestamp()
        except ValueError: pass
    return datetime.fromisoformat(s).timestamp()

def leer_host(path):
    evs=[]; desc=collections.Counter()
    for ln in open(path):
        if not ln.strip(): continue
        a=json.loads(ln); r=a.get("rule",{}); cl=_clase(r.get("groups",[]))
        if cl is None: continue
        evs.append({"ts":_ts_wazuh(a["timestamp"]),"entity":ENTIDAD,"kind":"host",
                    "clase":cl,"nivel":int(r.get("level",0) or 0)}); desc[cl]+=1
    return evs, desc

def fase_de(ini, fin):
    mejor=("benigno",0.0)
    for i,(n,t0) in enumerate(FASES_EP[:-1]):
        t1=FASES_EP[i+1][1]; ov=max(0.0,min(fin,t1)-max(ini,t0))
        if ov>mejor[1]: mejor=(n,ov)
    return mejor[0]

def seq(evs,v):
    d=nf.construir_secuencias(evs, v).get(ENTIDAD)
    return (d["X"],d["dt"],d["win_ts"]) if d else None

fmt=lambda t: datetime.fromtimestamp(t,tz=timezone.utc).strftime('%H:%M:%S')

def main():
    net=leer_conn(CONN_LOG); host,desc=leer_host(HOST_LOG)
    nb_net,nb_host=len(net),len(host)
    net=[e for e in net if CAMPANA_INI<=e["ts"]<=CAMPANA_FIN]
    host=[e for e in host if CAMPANA_INI<=e["ts"]<=CAMPANA_FIN]
    dh=collections.Counter(e["clase"] for e in host)
    print("=== FUENTES (filtradas a ventana de campana) ===")
    print(f"net : {len(net)}/{nb_net} flujos (resto fuera de campana)")
    print(f"host: {len(host)}/{nb_host} alertas -> {dict(dh)} (resto = instrumentacion previa)")
    if net:  print(f"net  UTC: {fmt(min(e['ts'] for e in net))}-{fmt(max(e['ts'] for e in net))}")
    if host: print(f"host UTC: {fmt(min(e['ts'] for e in host))}-{fmt(max(e['ts'] for e in host))}")
    print(f"campana UTC: {fmt(CAMPANA_INI)}-{fmt(CAMPANA_FIN)}")

    evs=sorted(net+host, key=lambda e:e["ts"])
    json.dump(evs, open(OUT_EVS,"w"))
    print(f"\neventos fusionados -> {OUT_EVS} ({len(evs)})")

    print("\n=== VENTANAS por escala ===")
    for v in (60,120,600):
        r=seq(evs,v)
        if r: print(f"  {v:>4}s -> {r[0].shape[0]:>2} ventanas | dt={[int(x) for x in r[1].tolist()]}")

    V=nf.VENTANA_SEG; X,dt,wts=seq(evs,V); yf=[fase_de(t,t+V) for t in wts.tolist()]
    print(f"\n=== SHARD ventana={V}s === X={X.shape} NaN={np.isnan(X).any()} Inf={np.isinf(X).any()}")
    ci={f:i for i,f in enumerate(nf.FEATURES)}
    print("hora     | fase          | n_conn frac_s0 n_rports fileint procex newusr nivmax")
    for k in range(X.shape[0]):
        x=X[k]
        print(f"{fmt(wts[k])} | {yf[k]:<13} | {x[ci['n_conn']]:6.0f} {x[ci['frac_s0']]:6.2f} {x[ci['n_rports']]:8.0f} "
              f"{x[ci['h_file_integ']]:7.0f} {x[ci['h_proc_exec']]:6.0f} {x[ci['h_new_user']]:6.0f} {x[ci['h_nivel_max']]:6.0f}")
    sc=nf.ajustar_scaler(X,guardar=False); Xs=nf.aplicar_scaler(X,sc)
    print(f"\nscaler (informativo, NO guardado): media~{Xs.mean():.2e} std~{Xs.std():.3f}")
    np.savez(OUT_NPZ, X=X, dt=dt, win_ts=wts, y_fase=np.array(yf),
             y_attack=np.ones(X.shape[0],dtype=int), features=np.array(nf.FEATURES),
             ventana_seg=V, entidad=ENTIDAD)
    print(f"SHARD -> {OUT_NPZ} ({X.shape[0]} ventanas, todas de ataque)")

if __name__=="__main__": main()
