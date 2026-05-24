# Noctua. — Autonomous Security Operations

![Version](https://img.shields.io/badge/version-1.0-blue)
![Phase](https://img.shields.io/badge/fase-1%20completada-green)
![License](https://img.shields.io/badge/licencia-privada-red)

## Descripción

**Noctua.** es una plataforma ASOAR (Autonomous Security Operations, Analysis and Response) diseñada específicamente para PYMEs que no disponen de un equipo de seguridad dedicado.

El sistema combina detección de amenazas en tiempo real con inteligencia artificial local para analizar alertas y tomar decisiones de bloqueo automáticas, sin depender de servicios cloud externos ni exponer datos sensibles.

Desarrollado como proyecto de Máster en Ciberseguridad — Fase 1.

---

## Arquitectura

| Componente | Rol | Tecnología |
|---|---|---|
| Wazuh | Detección de amenazas (SIEM/XDR) | Python / C |
| Ollama / phi3 | Análisis con IA local | LLM / Python |
| FastAPI | Intermediario y orquestador | Python |
| Hetzner API | Bloqueo automático de IPs | REST API |
| Agente PowerShell | Telemetría de endpoints Windows | PowerShell |
| Streamlit | Panel de control web | Python |

---

## Funcionalidades — Fase 1

- Detección automática de amenazas con Wazuh
- Análisis de alertas con IA local (Ollama phi3)
- Bloqueo automático de IPs maliciosas en Hetzner Firewall
- Dashboard web profesional con autenticación
- Agente PowerShell para monitorización de endpoints Windows
- Control de cumplimiento normativo (ISO 27001, NIS2, ENS)
- Generación de informes en PDF
- Mapa mundial de IPs bloqueadas
- Histórico de IPs con opción de desbloqueo manual
- Notificaciones en tiempo real
- Clasificación TLP:AMBER

---

## Requisitos

- VPS Ubuntu 24.04 (mínimo 8GB RAM)
- Python 3.12+
- Wazuh 4.x
- Ollama con modelo phi3

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/alejandrarruizsotomayor/noctua-asoar.git
cd noctua-asoar

# Instalar dependencias
pip3 install -r requirements.txt --break-system-packages

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales

# Arrancar servicios
systemctl start asoar streamlit ollama
```

---

## Normativas Soportadas

- **ISO/IEC 27001:2022** — Controles del Anexo A
- **NIS2 — Directiva UE 2022/2555** — Medidas técnicas del Artículo 21
- **ENS — RD 311/2022** — Medidas del Anexo II

---

## Roadmap — Fase 2

- Mejoras en el motor de IA (modelos más potentes)
- Base de datos SQLite para histórico avanzado
- Soporte multi-tenant para múltiples clientes PYME
- Notificaciones por Telegram y email
- HTTPS con certificado SSL
- Integración con más fuentes de threat intelligence

---

## Autor

**Alejandra R.** — Máster en Ciberseguridad — 2026

---

*Noctua. — Autonomous Security Operations Platform*
*Clasificación: TLP:AMBER — Uso interno*
