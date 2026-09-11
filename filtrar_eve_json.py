"""
Noctua Predictive — Filtro de eve.json para Wazuh

Lee continuamente el eve.json completo de Suricata (con todos los metadatos)
y escribe una version filtrada solo con los campos que usa Noctua, para
evitar el error "Too many fields for JSON decoder" en Wazuh.

Campos que se mantienen:
  - timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto
  - alert.signature, alert.category, alert.severity, alert.signature_id
  - flow.pkts_toserver, flow.pkts_toclient, flow.bytes_toserver,
    flow.bytes_toclient, flow.start, flow.end
  - tcp.syn, tcp.ack
"""

import json
import time
import os

ORIGEN  = "/var/log/suricata/eve.json"
DESTINO = "/var/log/suricata/eve_filtered.json"

def filtrar_evento(e: dict) -> dict:
    """Extrae solo los campos que Noctua Predictive necesita."""
    filtrado = {
        "timestamp":  e.get("timestamp", ""),
        "event_type": e.get("event_type", ""),
        "src_ip":     e.get("src_ip", ""),
        "src_port":   e.get("src_port", 0),
        "dest_ip":    e.get("dest_ip", ""),
        "dest_port":  e.get("dest_port", 0),
        "proto":      e.get("proto", ""),
    }
    if "alert" in e:
        a = e["alert"]
        filtrado["alert"] = {
            "signature":    a.get("signature", ""),
            "category":     a.get("category", ""),
            "severity":     a.get("severity", 3),
            "signature_id": a.get("signature_id", 0),
        }
    if "flow" in e:
        f = e["flow"]
        filtrado["flow"] = {
            "pkts_toserver":  f.get("pkts_toserver", 0),
            "pkts_toclient":  f.get("pkts_toclient", 0),
            "bytes_toserver": f.get("bytes_toserver", 0),
            "bytes_toclient": f.get("bytes_toclient", 0),
            "start":          f.get("start", ""),
            "end":            f.get("end", ""),
        }
    if "tcp" in e:
        t = e["tcp"]
        filtrado["tcp"] = {
            "syn": t.get("syn", False),
            "ack": t.get("ack", False),
        }
    return filtrado


def main():
    print(f"[Filtro] Iniciando filtrado de {ORIGEN} -> {DESTINO}")

    # Posicionarse al final del archivo origen (solo procesar eventos nuevos)
    if not os.path.exists(ORIGEN):
        print(f"[Filtro] Error: {ORIGEN} no existe")
        return

    with open(ORIGEN, "r") as f_in:
        f_in.seek(0, os.SEEK_END)
        posicion = f_in.tell()

    with open(DESTINO, "a") as f_out:
        while True:
            try:
                with open(ORIGEN, "r") as f_in:
                    f_in.seek(posicion)
                    lineas_nuevas = f_in.readlines()
                    posicion = f_in.tell()

                for linea in lineas_nuevas:
                    linea = linea.strip()
                    if not linea:
                        continue
                    try:
                        evento = json.loads(linea)
                        filtrado = filtrar_evento(evento)
                        f_out.write(json.dumps(filtrado) + "\n")
                    except json.JSONDecodeError:
                        continue

                f_out.flush()

            except FileNotFoundError:
                # El archivo pudo haber rotado (logrotate) — reiniciar posicion
                posicion = 0
            except Exception as e:
                print(f"[Filtro] Error: {e}")

            time.sleep(2)


if __name__ == "__main__":
    main()
