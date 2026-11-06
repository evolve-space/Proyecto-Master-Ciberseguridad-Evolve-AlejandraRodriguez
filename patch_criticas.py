import sys, time, shutil
P = "/root/asoar/dashboard.py"
bak = P + ".bak-criticas-" + time.strftime("%Y%m%d-%H%M%S")
shutil.copy(P, bak)
s = open(P, encoding="utf-8").read()
reps = [
 ('lv=substr($0,RSTART+8,RLENGTH-8)+0; if(lv>=10)a++; if(lv>=12)c++} END{print',
  'lv=substr($0,RSTART+8,RLENGTH-8)+0; isv=($0 ~ /vulnerability-detector/); if(lv>=10 && !isv)a++; if(lv>=12 && !isv)c++} END{print'),
 ('            if st.button("Ver nivel alto", key="btn_altas", use_container_width=True, type="primary"):\n                st.session_state.pagina = "Alertas y Eventos"; st.rerun()',
  '            if st.button("Ver nivel alto", key="btn_altas", use_container_width=True, type="primary"):\n                st.session_state.pagina = "Alertas y Eventos"; st.session_state.filtro_nivel = 10; st.rerun()'),
 ('            if st.button("Ver criticos", key="btn_criticas", use_container_width=True, type="secondary"):\n                st.session_state.pagina = "Alertas y Eventos"; st.rerun()',
  '            if st.button("Ver criticos", key="btn_criticas", use_container_width=True, type="secondary"):\n                st.session_state.pagina = "Alertas y Eventos"; st.session_state.filtro_nivel = 12; st.rerun()'),
 ('            filtro_nivel = st.slider("Nivel mínimo", 0, 15, 7)',
  '            st.session_state.setdefault("filtro_nivel", 7)\n            filtro_nivel = st.slider("Nivel mínimo", 0, 15, key="filtro_nivel")'),
 ('        df_show = df_f[["timestamp","tipo","ip","nivel","agente","id_regla","accion"]].copy()\n        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m/%Y %H:%M")\n        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Agente","Regla","Estado"]',
  '        df_show = df_f[["timestamp","tipo","ip","nivel","agente","id_regla","accion"]].copy()\n        df_show["severidad"] = df_show["nivel"].apply(lambda n: "CRITICO" if n>=12 else "ALTO" if n>=10 else "MEDIO" if n>=7 else "BAJO")\n        df_show["timestamp"] = df_show["timestamp"].dt.strftime("%d/%m/%Y %H:%M")\n        df_show = df_show[["timestamp","tipo","ip","nivel","severidad","agente","id_regla","accion"]]\n        df_show.columns = ["Fecha/Hora","Tipo","IP","Nivel","Severidad","Agente","Regla","Estado"]'),
]
for i,(o,n) in enumerate(reps,1):
    c = s.count(o)
    assert c==1, f"R{i}: esperaba 1 match, encontre {c} (no se aplica nada)"
    s = s.replace(o,n)
open(P,"w",encoding="utf-8").write(s)
print("OK: 5/5 reemplazos aplicados. Backup en", bak)
