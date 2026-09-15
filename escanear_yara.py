"""
Noctua Predictive — Escaneo periodico con YARA
Analiza directorios sensibles en busca de malware conocido y genera
alertas hacia el pipeline principal si encuentra coincidencias.
"""

import subprocess
import json
import os
import requests
from datetime import datetime

YARA_INDEX = "/root/asoar/yara_rules/index.yar"
DIRECTORIOS_ESCANEAR = ["/tmp", "/home"]
ESTADO_FILE = "/root/asoar/yara_scan_state.json"
HISTORIAL_FILE = "/root/asoar/yara_historial.json"
API_KEY_FILE = "/root/asoar/.env"


def obtener_api_key():
    try:
        with open(API_KEY_FILE) as f:
            for linea in f:
                if linea.startswith("API_KEY="):
                    return linea.strip().split("=", 1)[1]
    except Exception:
        pass
    return ""


def cargar_ya_notificados() -> set:
    if os.path.exists(ESTADO_FILE):
        try:
            with open(ESTADO_FILE, "r") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def guardar_ya_notificados(notificados: set):
    try:
        with open(ESTADO_FILE, "w") as f:
            json.dump(list(notificados)[-500:], f)
    except Exception:
        pass


def guardar_en_historial(regla: str, archivo: str, directorio: str):
    """Guarda cada coincidencia en un historial detallado para el dashboard."""
    from datetime import datetime as dt
    historial = []
    if os.path.exists(HISTORIAL_FILE):
        try:
            with open(HISTORIAL_FILE, "r") as f:
                historial = json.load(f)
        except Exception:
            historial = []
    historial.append({
        "timestamp": dt.now().isoformat(),
        "regla": regla,
        "archivo": archivo,
        "directorio_escaneado": directorio,
    })
    with open(HISTORIAL_FILE, "w") as f:
        json.dump(historial[-200:], f, indent=2)


def escanear():
    """Ejecuta YARA sobre los directorios sensibles y notifica coincidencias nuevas."""
    ya_notificados = cargar_ya_notificados()
    api_key = obtener_api_key()

    for directorio in DIRECTORIOS_ESCANEAR:
        if not os.path.exists(directorio):
            continue
        try:
            resultado = subprocess.run(
                ["yara", "-r", YARA_INDEX, directorio],
                capture_output=True, text=True, timeout=120
            )
            for linea in resultado.stdout.splitlines():
                partes = linea.split(" ", 1)
                if len(partes) != 2:
                    continue
                regla, archivo = partes
                clave = f"{regla}:{archivo}"
                if clave in ya_notificados:
                    continue
                ya_notificados.add(clave)

                print(f"[YARA] Coincidencia detectada: regla '{regla}' en archivo '{archivo}'")
                guardar_en_historial(regla, archivo, directorio)
                try:
                    requests.post(
                        "http://localhost:8000/alerta",
                        headers={"X-API-Key": api_key},
                        json={
                            "rule": {
                                "level": 12,
                                "description": f"YARA: Malware detectado - regla '{regla}' en archivo {archivo}",
                                "id": "99002"
                            },
                            "data": {"srcip": ""}
                        },
                        timeout=45
                    )
                except Exception as e:
                    print(f"[YARA] Error enviando alerta: {e}")

        except subprocess.TimeoutExpired:
            print(f"[YARA] Timeout escaneando {directorio}")
        except Exception as e:
            print(f"[YARA] Error escaneando {directorio}: {e}")

    guardar_ya_notificados(ya_notificados)


if __name__ == "__main__":
    escanear()
