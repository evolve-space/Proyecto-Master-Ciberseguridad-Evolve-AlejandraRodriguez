"""
Noctua Predictive — Filtro de eve.json para Wazuh

Lee continuamente el eve.json completo de Suricata (con todos los metadatos)
y escribe una version filtrada solo con los campos que usa Noctua, para
evitar el error "Too many fields for JSON decoder" en Wazuh.

Guarda su posicion de lectura en disco para sobrevivir reinicios del
propio servicio sin duplicar eventos, y detecta rotacion de logrotate
comparando el tamano del archivo con la posicion guardada.

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

ORIGEN       = "/var/log/suricata/eve.json"
DESTINO      = "/var/log/suricata/eve_filtered.json"
POSICION_FILE = "/root/asoar/eve_filter_posicion.json"


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


def cargar_posicion() -> int:
    """Carga la ultima posicion de lectura guardada, o 0 si no existe."""
    if os.path.exists(POSICION_FILE):
        try:
            with open(POSICION_FILE, "r") as f:
                return json.load(f).get("posicion", 0)
        except Exception:
            return 0
    return 0


def guardar_posicion(posicion: int):
    """Persiste la posicion de lectura actual en disco."""
    try:
        with open(POSICION_FILE, "w") as f:
            json.dump({"posicion": posicion}, f)
    except Exception:
        pass


def main():
    print(f"[Filtro] Iniciando filtrado de {ORIGEN} -> {DESTINO}")

    if not os.path.exists(ORIGEN):
        print(f"[Filtro] Error: {ORIGEN} no existe")
        return

    # Recuperar posicion guardada, o posicionarse al final si es la primera vez
    posicion = cargar_posicion()
    tamano_actual = os.path.getsize(ORIGEN)
    if posicion == 0 or posicion > tamano_actual:
        # Primera ejecucion, o el archivo roto es mas pequeno que la posicion
        # guardada (logrotate actuo) — empezar desde el principio del archivo nuevo
        posicion = 0
        print("[Filtro] Iniciando lectura desde el principio del archivo actual")
    else:
        print(f"[Filtro] Retomando lectura desde la posicion {posicion}")

    with open(DESTINO, "a") as f_out:
        while True:
            try:
                tamano_actual = os.path.getsize(ORIGEN)

                # Deteccion de rotacion: el archivo actual es mas pequeno
                # que nuestra posicion guardada — logrotate creo uno nuevo
                if tamano_actual < posicion:
                    print("[Filtro] Rotacion de log detectada — reiniciando desde el principio")
                    posicion = 0

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
                guardar_posicion(posicion)

            except FileNotFoundError:
                posicion = 0
            except Exception as e:
                print(f"[Filtro] Error: {e}")

            time.sleep(2)


if __name__ == "__main__":
    main()
