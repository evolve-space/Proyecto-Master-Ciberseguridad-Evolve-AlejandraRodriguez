#!/usr/bin/env python3
"""Shard NEGATIVO (trafico benigno) via noctua_features. Espejo del positivo."""
import sys, json, collections
from datetime import datetime, timezone
sys.path.insert(0, "/root/asoar")
import numpy as np, noctua_features as nf

CONN_LOG="/root/asoar/poc/conn_benigno.log"
HOST_LOG="/root/poc_benigno_host_alerts.json"
OUT_NPZ ="/root/asoar/poc/shard_benigno.npz"
OUT_EVS ="/root/asoar/poc/poc_eventos_benigno.json"
CLIENTE ="192.168.60.3"; ENTIDAD=CLIENTE
BEN_INI=datetime(2026,10,20,10,50,45,tzinfo=timezone.utc).timestamp()
BEN_FIN=datetime(2026,10,20,11,11,39,tzinfo=timezone.utc).timestamp()

def _f(x): return 0.0 if x in ("-","",None) else float(x)
def leer_conn(p):
    evs=[]; c=None
    for ln in open(p):
        if ln.startswith("#fields"): c=ln.rstrip("\n").split("\t")[1:]; continue
        if ln.startswith("#") or not ln.strip() or c is None: continue
        r=dict(zip(c, ln.rstrip("\n").split("\t")))
        if CLIENTE not in (r.get("id.orig_h"), r.get("id.resp_h")): continue
        evs.append({"ts":float(r["ts"]),"entity":ENTIDAD,"kind":"net","resp_p":r.get("id.resp_p"),
            "service":r.get("service"),"proto":r.get("proto"),"conn_state":r.get("conn_state"),
            "resp_pkts":_f(r.get("resp_pkts")),"duration":_f(r.get("duration")),
            "orig_bytes":_f(r.get("orig_bytes")),"resp_bytes":_f(r.get("resp_bytes")),"orig_pkts":_f(r.get("orig_pkts"))})
    return evs
def _clase(g):
    g=set(g)
    if "adduser" in g: return "new_user"
    if "authentication_failed" in g: return "auth_fail"
    if "authentication_success" in g: return "auth_ok"
    if "sudo" in g: return "proc_exec"
    if "syscheck" in g: return "file_integ"
    return None
def _ts(s):
    for f in ("%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%dT%H:%M:%S%z"):
        try: return datetime.strptime(s,f).timestamp()
        except ValueError: pass
    return datetime.fromisoformat(s).timestamp()
def leer_host(p):
    evs=[]; d=collections.Counter()
    for ln in open(p):
        if not ln.strip(): continue
        a=json.loads(ln); cl=_clase(a.get("rule",{}).get("groups",[]))
        if cl is None: continue
        evs.append({"ts":_ts(a["timestamp"]),"entity":ENTIDAD,"kind":"host","clase":cl,
                    "nivel":int(a.get("rule",{}).get("level",0) or 0)}); d[cl]+=1
    return evs,d
fmt=lambda t: datetime.fromtimestamp(t,tz=timezone.utc).strftime('%H:%M:%S')
def seq(evs,v):
    r=nf.construir_secuencias(evs,v).get(ENTIDAD); return (r["X"],r["dt"],r["win_ts"]) if r else None
def main():
    net=leer_conn(CONN_LOG); host,dh=leer_host(HOST_LOG)
    net=[e for e in net if BEN_INI<=e["ts"]<=BEN_FIN]; host=[e for e in host if BEN_INI<=e["ts"]<=BEN_FIN]
    print(f"net:{len(net)}  host:{len(host)} -> {dict(dh)}")
    if net:  print("net UTC :",fmt(min(e['ts'] for e in net)),"-",fmt(max(e['ts'] for e in net)))
    if host: print("host UTC:",fmt(min(e['ts'] for e in host)),"-",fmt(max(e['ts'] for e in host)))
    evs=sorted(net+host,key=lambda e:e["ts"]); json.dump(evs,open(OUT_EVS,"w"))
    for v in (60,120,600):
        r=seq(evs,v)
        if r: print(f"  {v:>4}s -> {r[0].shape[0]:>2} ventanas | dt={[int(x) for x in r[1].tolist()]}")
    V=nf.VENTANA_SEG; X,dt,wts=seq(evs,V)
    ci={f:i for i,f in enumerate(nf.FEATURES)}
    print(f"\nSHARD benigno X={X.shape} NaN={np.isnan(X).any()}")
    print("hora     | n_conn frac_s0 n_rports fileint proc_ex auth_ok auth_f newusr nivmax")
    for k in range(X.shape[0]):
        x=X[k]
        print(f"{fmt(wts[k])} | {x[ci['n_conn']]:6.0f} {x[ci['frac_s0']]:6.2f} {x[ci['n_rports']]:8.0f} "
              f"{x[ci['h_file_integ']]:7.0f} {x[ci['h_proc_exec']]:7.0f} {x[ci['h_auth_ok']]:7.0f} "
              f"{x[ci['h_auth_fail']]:6.0f} {x[ci['h_new_user']]:6.0f} {x[ci['h_nivel_max']]:6.0f}")
    np.savez(OUT_NPZ, X=X, dt=dt, win_ts=wts, y_attack=np.zeros(X.shape[0],dtype=int),
             features=np.array(nf.FEATURES), ventana_seg=V, entidad=ENTIDAD)
    print(f"\nSHARD -> {OUT_NPZ} ({X.shape[0]} ventanas, clase negativa)")
if __name__=="__main__": main()
