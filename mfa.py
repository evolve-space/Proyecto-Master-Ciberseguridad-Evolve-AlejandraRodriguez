"""
Noctua Predictive — Modulo MFA con TOTP
Autenticacion de doble factor compatible con Google Authenticator y Aegis

Genera un secreto TOTP, muestra el QR para registrar en la app
y verifica el codigo de 6 digitos en cada login.
"""

import pyotp
import qrcode
import os
import json
from pathlib import Path
from datetime import datetime

MFA_CONFIG_PATH = "/root/asoar/mfa_config.json"


def generar_secreto() -> str:
    """Genera un nuevo secreto TOTP aleatorio."""
    return pyotp.random_base32()


def guardar_config_mfa(username: str, secreto: str, activo: bool = True):
    """Guarda la configuracion MFA del usuario."""
    config = cargar_config_mfa()
    config[username] = {
        "secreto":  secreto,
        "activo":   activo,
        "creado_en": datetime.now().isoformat(),
    }
    with open(MFA_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def cargar_config_mfa() -> dict:
    """Carga la configuracion MFA guardada."""
    if os.path.exists(MFA_CONFIG_PATH):
        try:
            with open(MFA_CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def mfa_activo(username: str) -> bool:
    """Comprueba si el MFA esta activo para un usuario."""
    config = cargar_config_mfa()
    return config.get(username, {}).get("activo", False)


def obtener_secreto(username: str) -> str:
    """Obtiene el secreto TOTP de un usuario."""
    config = cargar_config_mfa()
    return config.get(username, {}).get("secreto", "")


def verificar_codigo(username: str, codigo: str) -> bool:
    """
    Verifica si el codigo TOTP introducido es valido.
    Acepta codigos con 30 segundos de margen para compensar diferencias de reloj.
    """
    secreto = obtener_secreto(username)
    if not secreto:
        return False
    totp = pyotp.TOTP(secreto)
    return totp.verify(codigo, valid_window=1)


def generar_qr_bytes(username: str, secreto: str, issuer: str = "Noctua Predictive") -> bytes:
    """
    Genera el QR en bytes para mostrar en Streamlit.
    El usuario lo escanea con Google Authenticator o Aegis.
    """
    totp = pyotp.TOTP(secreto)
    uri  = totp.provisioning_uri(name=username, issuer_name=issuer)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0f1f35", back_color="white")

    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.getvalue()


def codigo_actual(username: str) -> str:
    """Devuelve el codigo TOTP actual (util para tests)."""
    secreto = obtener_secreto(username)
    if not secreto:
        return ""
    return pyotp.TOTP(secreto).now()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("NOCTUA PREDICTIVE — Configuracion MFA")
    print("="*60)

    username = "admin"
    secreto  = generar_secreto()
    guardar_config_mfa(username, secreto, activo=True)

    print(f"\nUsuario:  {username}")
    print(f"Secreto:  {secreto}")
    print(f"Codigo actual: {codigo_actual(username)}")

    # Verificar que funciona
    codigo = codigo_actual(username)
    valido = verificar_codigo(username, codigo)
    print(f"Verificacion: {'OK' if valido else 'ERROR'}")

    print(f"\nConfiguracion guardada en {MFA_CONFIG_PATH}")
    print("\nEscanea el QR desde el dashboard en Configuracion > MFA")
    print("="*60)
