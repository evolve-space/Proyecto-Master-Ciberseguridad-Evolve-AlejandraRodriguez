#!/usr/bin/env python3
# demo_replay.py — DEMO para la defensa (modo SEGURO, solo tickets, SIN bloqueo real).
# Reproduce una campana APT real (clasificada por el modelo M2 -> demo_soc_tickets.json)
# levantando TICKETS REALES en el SOC, uno por fase, con retardo, para verlos ENTRAR en
# Streamlit. Politica graduada: monitor-only hasta exfiltracion -> "contencion" SIMULADA
# (nota + estado 'Contenido'; NUNCA toca Hetzner ni bloquea IPs reales). Todo con
# origen="demo_replay" + campana_id "DEMO-REPLAY-*" para borrarlo con --limpiar.
import sys, os, time, json, argparse
sys.path.insert(0, "/root/asoar")
from apt_tickets import crear_ticket, anadir_nota, actualizar_estado, _cargar, _guardar
DEMO_JSON = "/root/asoar/poc/auto/demo_soc_tickets.json"
SEV2PRIO = {"BAJO":"BAJA","MEDIO":"MEDIA","ALTO":"ALTA","CRITICO":"CRITICA",
            "BAJA":"BAJA","MEDIA":"MEDIA","ALTA":"ALTA","CRITICA":"CRITICA"}
def limpiar():
    data=_cargar(); antes=len(data.get("tickets",[]))
    data["tickets"]=[t for t in data.get("tickets",[]) if t.get("origen")!="demo_replay"]
    _guardar(data)
    print(f"[LIMPIEZA] Borrados {antes-len(data['tickets'])} tickets de demo. Quedan {len(data['tickets'])}.")
def replay(delay, ip):
    if not os.path.exists(DEMO_JSON):
        print(f"[ERROR] No existe {DEMO_JSON}. Genera la campana antes con demo_soc.py"); sys.exit(1)
    d=json.load(open(DEMO_JSON)); tks=d.get("tickets",[])
    if not tks: print("[ERROR] demo_soc_tickets.json sin tickets."); sys.exit(1)
    camp="DEMO-REPLAY-"+time.strftime("%Y%m%d-%H%M%S"); ip=ip or d.get("ip","192.168.60.3")
    print("="*70); print(f"DEMO REPLAY — {camp} | IP {ip} | {len(tks)} fases | retardo {delay}s")
    print("Modo SEGURO: tickets reales, bloqueo SIMULADO (no se toca Hetzner)."); print("="*70)
    creados=[]
    for i,tk in enumerate(tks):
        fase=tk.get("fase","?"); prio=SEV2PRIO.get(str(tk.get("severidad","MEDIA")).upper(),"MEDIA")
        mitre=tk.get("mitre",fase); conf=float(tk.get("confianza_pct",0)); dtm=tk.get("dt_desde_fase_anterior_min",0)
        exfil=(fase=="exfiltracion")
        titulo=f"[DEMO] Campana APT — {fase.replace('_',' ').upper()} desde {ip}"
        desc=(f"Fase {fase} ({mitre}) detectada por el modelo time-aware (M2). Confianza {conf:.0f}%. "
              f"+{dtm} min desde la fase anterior (ritmo low-and-slow). "
              +("RIESGO CRITICO sobre los activos: se activa la contencion automatica." if exfil
                else "Accion: observar y enriquecer en monitor-only; sin bloqueo (aun no hay riesgo inminente)."))
        t=crear_ticket(titulo=titulo,descripcion=desc,ip=ip,fase_mitre=fase,confianza=conf,
                       prioridad=prio,origen="demo_replay",abuse_pais="LAB",campana_id=camp)
        creados.append(t["id"])
        print(f"  [{i+1}/{len(tks)}] [TICKET] {t['id']} entra  | fase {fase:<13} | prio {prio}")
        if exfil:
            anadir_nota(t["id"],"CONTENCION AUTOMATICA (demo): exfiltracion detectada -> IP contenida. "
                               "En produccion aqui se dispara el bloqueo por fase (monitor-only en demo).")
            actualizar_estado(t["id"],"Contenido","Bloqueo automatico en exfiltracion (demo, simulado)")
            print(f"       [!! CONTENCION] {t['id']} -> estado 'Contenido' (bloqueo simulado)")
        if i<len(tks)-1: time.sleep(delay)
    print("-"*70); print(f"RESUMEN: {len(creados)} tickets de demo creados ({camp}).")
    print("Miralos ENTRAR en Streamlit. Para borrarlos: python3 demo_replay.py --limpiar")
if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--delay",type=float,default=4.0,help="segundos entre fases (default 4)")
    ap.add_argument("--ip",default="",help="IP de la campana (default: la del JSON)")
    ap.add_argument("--limpiar",action="store_true",help="borrar los tickets de demo y salir")
    a=ap.parse_args()
    (limpiar() if a.limpiar else replay(a.delay,a.ip))
