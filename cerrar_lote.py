#!/usr/bin/env python3
# cerrar_lote.py — cierra en lote los tickets ABIERTOS mas antiguos, dejando abiertos los
# N mas recientes (--mantener). NO borra: cambia estado a 'Cerrado' (reversible). --dry = preview.
import sys, argparse
sys.path.insert(0, "/root/asoar")
from apt_tickets import listar_tickets, actualizar_estado
def main(mantener, dry):
    abiertos = [t for t in listar_tickets() if t["estado"]=="Abierto"]  # ordenado por creado_en desc
    cerrar = abiertos[mantener:]
    print(f"Abiertos: {len(abiertos)} | se mantienen {min(mantener,len(abiertos))} | se cierran {len(cerrar)}")
    if dry:
        for t in cerrar[:5]: print("  (dry) cerraria", t["id"], t.get("fase_mitre",""), t["prioridad"])
        if len(cerrar)>5: print(f"  ... y {len(cerrar)-5} mas")
        print("DRY-RUN: no se ha cambiado nada."); return
    n=0
    for t in cerrar:
        if actualizar_estado(t["id"], "Cerrado", "Cierre masivo de backlog (limpieza pre-demo)"): n+=1
    print(f"[OK] Cerrados {n} tickets. Abiertos restantes: {len(abiertos)-n}.")
if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--mantener",type=int,default=10,help="cuantos abiertos recientes conservar")
    ap.add_argument("--dry",action="store_true",help="previsualizar sin cambiar nada")
    a=ap.parse_args(); main(a.mantener,a.dry)
