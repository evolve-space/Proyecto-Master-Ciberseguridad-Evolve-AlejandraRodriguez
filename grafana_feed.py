#!/usr/bin/env python3
# grafana_feed.py - micro-servicio SOLO LECTURA que reempaqueta la API de Noctua en formas
# comodas para Grafana (listas [{label,value}]). Escucha en 127.0.0.1:8010 (sin auth, solo
# localhost). Lee API_KEY del .env para llamar a la API real. NO modifica nada del SOC.
import json, os, time, urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

API = "http://localhost:8000"
def _key():
    try:
        for line in open("/root/asoar/.env"):
            if line.startswith("API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return ""
KEY = _key()

def api(path):
    req = urllib.request.Request(API + path, headers={"X-API-Key": KEY})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

CENTROIDES = {
    "US": (39.8, -98.6), "BR": (-10.3, -53.2), "CN": (35.9, 104.2), "RU": (61.5, 105.3),
    "IN": (22.4, 78.7), "DE": (51.2, 10.4), "FR": (46.2, 2.2), "GB": (54.0, -2.0),
    "NL": (52.1, 5.3), "IT": (42.8, 12.6), "ES": (40.2, -3.7), "PT": (39.6, -8.0),
    "FI": (64.0, 26.0), "SE": (62.2, 15.6), "NO": (64.5, 17.9), "PL": (52.1, 19.4),
    "UA": (48.4, 31.2), "RO": (45.9, 24.9), "TR": (39.0, 35.2), "IR": (32.4, 53.7),
    "VN": (16.0, 107.8), "ID": (-2.5, 118.0), "JP": (36.2, 138.3), "KR": (36.4, 127.8),
    "SG": (1.35, 103.8), "HK": (22.3, 114.2), "TW": (23.7, 121.0), "TH": (15.1, 101.0),
    "PH": (12.9, 121.8), "MY": (4.2, 109.7), "PK": (30.4, 69.3), "BD": (23.7, 90.3),
    "AU": (-25.3, 133.8), "NZ": (-41.8, 172.5), "CA": (56.1, -106.3), "MX": (23.6, -102.5),
    "AR": (-38.4, -63.6), "CL": (-35.7, -71.5), "CO": (4.6, -74.3), "PE": (-9.2, -75.0),
    "VE": (6.4, -66.6), "EC": (-1.8, -78.2), "ZA": (-30.6, 22.9), "NG": (9.1, 8.7),
    "EG": (26.8, 30.8), "KE": (-0.0, 37.9), "MA": (31.8, -7.1), "DZ": (28.0, 1.7),
    "AO": (-11.2, 17.9), "GH": (7.9, -1.0), "ET": (9.1, 40.5), "TZ": (-6.4, 34.9),
    "SA": (23.9, 45.1), "AE": (23.4, 53.8), "IL": (31.0, 34.9), "IQ": (33.2, 43.7),
    "QA": (25.3, 51.2), "KW": (29.3, 47.5), "CZ": (49.8, 15.5), "AT": (47.6, 14.6),
    "CH": (46.8, 8.2), "BE": (50.6, 4.6), "IE": (53.2, -8.0), "DK": (56.3, 9.5),
    "GR": (39.1, 22.0), "HU": (47.2, 19.4), "BG": (42.7, 25.5), "RS": (44.0, 21.0),
    "HR": (45.1, 15.2), "SK": (48.7, 19.7), "SI": (46.1, 14.8), "LT": (55.2, 23.9),
    "LV": (56.9, 24.6), "EE": (58.6, 25.0), "MK": (41.6, 21.7), "AL": (41.2, 20.2),
    "BA": (43.9, 17.7), "MD": (47.4, 28.4), "BY": (53.7, 27.9), "GE": (42.3, 43.4),
    "KZ": (48.0, 66.9), "UZ": (41.4, 64.6), "AZ": (40.1, 47.6), "AM": (40.1, 45.0),
    "LK": (7.9, 80.8), "MM": (21.9, 95.9), "KH": (12.6, 104.9), "NP": (28.4, 84.1),
    "LU": (49.8, 6.1), "IS": (64.9, -19.0), "CY": (35.1, 33.4), "MT": (35.9, 14.4),
    "TN": (33.9, 9.6), "LY": (26.3, 17.2), "SD": (12.9, 30.2), "UG": (1.4, 32.3),
    "CM": (7.4, 12.4), "CI": (7.5, -5.5), "SN": (14.5, -14.5), "ZW": (-19.0, 29.9),
    "MZ": (-18.7, 35.5), "BO": (-16.3, -63.6), "PY": (-23.4, -58.4), "UY": (-32.5, -55.8),
    "CR": (9.7, -83.8), "PA": (8.5, -80.8), "GT": (15.8, -90.2), "DO": (18.7, -70.2),
    "CU": (21.5, -77.8), "HN": (15.0, -86.6), "SV": (13.8, -88.9), "NI": (12.9, -85.2),
}

def fases():
    m = api("/tickets/metricas/resumen").get("por_fase", {})
    return [{"fase": k, "count": v} for k, v in sorted(m.items(), key=lambda x: -x[1])]
def prioridad():
    m = api("/tickets/metricas/resumen").get("por_prioridad", {})
    orden = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
    return [{"prioridad": k, "count": v} for k, v in sorted(m.items(), key=lambda x: orden.get(x[0], 9))]
def paises():
    t = api("/tickets")
    c = Counter((x.get("abuse_pais") or "Desconocido") for x in (t if isinstance(t, list) else []))
    return [{"pais": k, "count": v} for k, v in c.most_common(15)]
def geo():
    t = api("/tickets")
    c = Counter((x.get("abuse_pais") or "") for x in (t if isinstance(t, list) else []))
    out = []
    for pais, n in c.most_common():
        cc = (pais or "").strip().upper()
        if cc in CENTROIDES:
            lat, lon = CENTROIDES[cc]
            out.append({"pais": cc, "lat": lat, "lon": lon, "count": n})
    return out
def demo():
    p = "/root/asoar/poc/auto/demo_soc_tickets.json"
    return json.load(open(p)) if os.path.exists(p) else {"tickets": []}
def demo_timeline():
    d = demo()
    tks = d.get("tickets", [])
    if not tks:
        return []
    dur = max((tk.get("t_min", 0) for tk in tks), default=0.0)
    base_ms = int((time.time() - (dur + 3.0) * 60) * 1000)  # margen exfil/BLOQUEO
    filas = []
    for tk in tks:
        fase = tk.get("fase", "?")
        ts = base_ms + int(tk.get("t_min", 0) * 60 * 1000)
        resp = "BLOQUEO" if fase == "exfiltracion" else "Monitor-only"
        filas.append({"time": ts, "fase": fase, "respuesta": resp,
                      "ip": tk.get("ip", ""), "sev": tk.get("severidad", "")})
    last = dict(filas[-1]); last["time"] = int(time.time() * 1000)
    filas.append(last)
    return filas

ROUTES = {"/fases": fases, "/prioridad": prioridad, "/paises": paises,
          "/geo": geo, "/demo": demo, "/demo_timeline": demo_timeline}
RUTAS_TXT = json.dumps(list(ROUTES.keys()))

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ruta = self.path.split("?")[0]
        fn = ROUTES.get(ruta)
        try:
            if fn is None:
                self.send_response(404); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(('{"error":"not found","rutas":%s}' % RUTAS_TXT).encode()); return
            body = json.dumps(fn()).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    def log_message(self, *a): pass

if __name__ == "__main__":
    print("grafana_feed en http://127.0.0.1:8010  (rutas: %s)" % ", ".join(ROUTES))
    HTTPServer(("127.0.0.1", 8010), H).serve_forever()
