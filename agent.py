import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

DB_PATH = BASE / CONFIG["agent"]["database"]
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
(BASE / "logs").mkdir(exist_ok=True)

logging.basicConfig(
    filename=BASE / "logs" / "agent.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("CodeAccessX.NetworkAgent")

from network_scan import scan  # noqa: E402

app = FastAPI(title="CodeAccessX Network Agent", version="1.0.0")
_scan_lock = threading.Lock()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(db()) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            subnet TEXT,
            device_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip)
        );

        CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            online INTEGER NOT NULL,
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)
        conn.commit()


def save_scan(devices: list[dict], subnet: str) -> int:
    with closing(db()) as conn:
        cur = conn.execute(
            "INSERT INTO scans(subnet, device_count) VALUES (?, ?)",
            (subnet, len(devices)),
        )
        scan_id = cur.lastrowid

        for d in devices:
            conn.execute("""
                INSERT INTO devices(ip, mac, hostname, online)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    hostname=excluded.hostname,
                    online=1,
                    last_seen=CURRENT_TIMESTAMP
            """, (d["ip"], d.get("mac"), d.get("hostname")))
            conn.execute("""
                INSERT INTO device_history(scan_id, ip, mac, hostname, online)
                VALUES (?, ?, ?, ?, 1)
            """, (scan_id, d["ip"], d.get("mac"), d.get("hostname")))

        conn.execute(
            "UPDATE scans SET finished_at=CURRENT_TIMESTAMP WHERE id=?",
            (scan_id,),
        )
        conn.commit()
        return int(scan_id)


def run_scan() -> dict[str, Any]:
    if not _scan_lock.acquire(blocking=False):
        return {"status": "already_running"}
    try:
        ncfg = CONFIG["network"]
        devices = scan(
            ncfg.get("subnet", ""),
            int(ncfg.get("ping_timeout_ms", 700)),
            int(ncfg.get("max_hosts", 1024)),
        )
        subnet = ncfg.get("subnet", "")
        scan_id = save_scan(devices, subnet)
        log.info("Scan %s completed: %s devices", scan_id, len(devices))
        return {"status": "ok", "scan_id": scan_id, "devices": devices}
    finally:
        _scan_lock.release()


def list_devices(online_only=False):
    q = "SELECT * FROM devices"
    if online_only:
        q += " WHERE online=1"
    q += " ORDER BY ip"
    with closing(db()) as conn:
        return [dict(r) for r in conn.execute(q).fetchall()]


def get_device(ip: str):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None


def new_devices_since(hours: int):
    with closing(db()) as conn:
        rows = conn.execute("""
            SELECT * FROM devices
            WHERE first_seen >= datetime('now', ?)
            ORDER BY first_seen DESC
        """, (f"-{int(hours)} hours",)).fetchall()
        return [dict(r) for r in rows]


def require_key(x_api_key: str | None):
    expected = CONFIG["security"].get("api_key", "")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="API key inválida.")


class ChatRequest(BaseModel):
    message: str
    model: str | None = None


@app.on_event("startup")
def startup():
    init_db()
    if CONFIG["agent"].get("scan_on_start", True):
        threading.Thread(target=run_scan, daemon=True).start()


@app.get("/health")
def health():
    return {"status": "ok", "service": "CodeAccessX.NetworkAgent"}


@app.post("/scan")
def api_scan(x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return run_scan()


@app.get("/devices")
def api_devices(online_only: bool = False, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return {"count": len(list_devices(online_only)), "devices": list_devices(online_only)}


@app.get("/devices/{ip}")
def api_device(ip: str, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    device = get_device(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")
    return device


@app.get("/devices/new")
def api_new_devices(hours: int = 24, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)
    return {"hours": hours, "devices": new_devices_since(hours)}


@app.post("/lmstudio/chat")
def lmstudio_chat(req: ChatRequest, x_api_key: str | None = Header(default=None)):
    require_key(x_api_key)

    devices = list_devices()
    context = {
        "network_devices": devices,
        "device_count": len(devices),
    }

    base = CONFIG["lm_studio"]["base_url"].rstrip("/")
    model = req.model or CONFIG["lm_studio"].get("model", "")
    if not model:
        try:
            models = requests.get(
                f"{base}/models",
                timeout=10,
            ).json().get("data", [])
            if not models:
                raise RuntimeError("Nenhum modelo disponível no LM Studio.")
            model = models[0]["id"]
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"LM Studio indisponível: {e}")

    system = """Você é o assistente de inventário de rede do CodeAccessX.
Responda somente com base nos dados fornecidos pelo agente.
Não invente dispositivos, IPs ou características.
Você pode explicar os dados, mas não deve executar comandos de rede.
Se os dados forem insuficientes, diga isso claramente."""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": req.message},
            {"role": "system", "content": "Dados atuais do inventário:\n" + json.dumps(context, ensure_ascii=False)},
        ],
        "temperature": 0.1,
    }

    try:
        r = requests.post(
            f"{base}/chat/completions",
            json=payload,
            timeout=int(CONFIG["lm_studio"].get("timeout_seconds", 120)),
        )
        r.raise_for_status()
        data = r.json()
        return {
            "model": model,
            "answer": data["choices"][0]["message"]["content"],
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao consultar LM Studio: {e}")


def scheduler():
    while True:
        try:
            time.sleep(int(CONFIG["agent"].get("scan_interval_seconds", 300)))
            run_scan()
        except Exception:
            log.exception("Erro no agendamento do scan")


if __name__ == "__main__":
    import uvicorn
    threading.Thread(target=scheduler, daemon=True).start()
    host = CONFIG["agent"].get("host", "127.0.0.1")
    port = int(CONFIG["agent"].get("port", 8765))
    uvicorn.run(app, host=host, port=port)
