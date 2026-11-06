import time, shutil
P="/root/asoar/dashboard.py"
bak=P+".bak-spinner-"+time.strftime("%Y%m%d-%H%M%S"); shutil.copy(P,bak)
s=open(P,encoding="utf-8").read()
old='''            resultado_grep = subprocess.run(
                ["bash", "-c", f"{{ tail -c 50M /var/log/suricata/eve.json; zcat /var/log/suricata/eve.json.*.gz 2>/dev/null; }} | grep '{ip_forense}'"],
                capture_output=True, text=True, errors="ignore",
                timeout=60
            )'''
new='''            with st.spinner("Rastreando evidencias de red en Suricata (puede tardar unos segundos)..."):
                resultado_grep = subprocess.run(
                    ["bash", "-c", f"{{ tail -c 50M /var/log/suricata/eve.json; zcat /var/log/suricata/eve.json.*.gz 2>/dev/null; }} | grep '{ip_forense}'"],
                    capture_output=True, text=True, errors="ignore",
                    timeout=60
                )'''
assert s.count(old)==1, f"esperaba 1 match, encontre {s.count(old)}"
open(P,"w",encoding="utf-8").write(s.replace(old,new))
print("OK: spinner anadido al forense de Suricata. Backup en",bak)
