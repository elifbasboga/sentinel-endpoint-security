#!/usr/bin/env python3
"""
server.py
---------
SentinEL merkezi sunucusu (SOC ekrani icin backend).

Ne yapar:
  - Client'lardan tehdit bildirimi alir (POST /api/report)
  - Client'lardan heartbeat (nabiz) alir (POST /api/heartbeat)
  - Dashboard'un periyodik cektigi ozet veriyi uretir (GET /api/dashboard-data)
  - Dashboard HTML sayfasini servis eder (GET /)

Veri kalicidir: threats_log.json dosyasina yazilir, sunucu yeniden
baslasa bile gecmis tehditler kaybolmaz. Client listesi (heartbeat
zamanlari) ise sadece bellekte tutulur - sunucu yeniden baslarsa
"aktif/pasif" durumu sifirdan hesaplanir (bu normal, sorun degil).

Calistirma:
    python3 server.py
    -> http://localhost:8000 adresinde acilir
"""

import json
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
THREATS_LOG_PATH = BASE_DIR / "threats_log.json"
DASHBOARD_HTML_PATH = BASE_DIR / "dashboard.html"

# Bir client, son heartbeat/report'undan bu kadar saniye sonra
# "pasif/offline" sayilir. central_reporter.py'deki HEARTBEAT_INTERVAL_SECONDS
# (20sn) ile uyumlu olmali: cok dusuk tutulursa client saglikliyken bile
# iki heartbeat arasinda yanlislikla "pasif" gorunur (flapping). Kural:
# ~heartbeat araligi x 2 + tampon. 20sn x 2 + 5sn tampon = 45sn.
ACTIVE_TIMEOUT_SECONDS = 45

app = FastAPI(title="SentinEL Central Server")

# Türkiye Saati (UTC+3)
TR_TZ = timezone(timedelta(hours=3))

# ---------------------------------------------------------------------------
# Bellek-ici durum (thread-safe erisim icin kilit kullaniyoruz, cunku
# FastAPI/uvicorn ayni anda birden fazla istegi paralel isleyebilir)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_clients: dict[str, dict] = {}   # hostname -> {"last_seen": float, "active_user": str}
_threats: list[dict] = []        # kalici log, threats_log.json ile senkron


def _load_threats_from_disk():
    global _threats
    if THREATS_LOG_PATH.exists():
        try:
            with open(THREATS_LOG_PATH, "r", encoding="utf-8") as f:
                _threats = json.load(f)
        except (json.JSONDecodeError, OSError):
            _threats = []


def _save_threats_to_disk():
    with open(THREATS_LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(_threats, f, indent=2, ensure_ascii=False)


_load_threats_from_disk()


# ---------------------------------------------------------------------------
# Istek/cevap modelleri
# ---------------------------------------------------------------------------
class HeartbeatPayload(BaseModel):
    hostname: str
    active_user: Optional[str] = None


class ThreatPayload(BaseModel):
    hostname: str
    active_user: str
    threat_label: str
    file_name: str
    location: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoint'ler
# ---------------------------------------------------------------------------
@app.post("/api/heartbeat")
def receive_heartbeat(payload: HeartbeatPayload):
    with _lock:
        _clients[payload.hostname] = {
            "last_seen": time.time(),
            "active_user": payload.active_user or "-",
        }
    return {"status": "ok"}


@app.post("/api/report")
def receive_report(payload: ThreatPayload):
    now = time.time()
    record = {
        "hostname": payload.hostname,
        "active_user": payload.active_user,
        "threat_label": payload.threat_label,
        "file_name": payload.file_name,
        "location": payload.location or "-",
        "timestamp": now,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        _threats.append(record)
        _save_threats_to_disk()
        # Bir tehdit bildirmek de o client'in "canli" oldugunun kanitidir
        _clients[payload.hostname] = {
            "last_seen": now,
            "active_user": payload.active_user,
        }
    return {"status": "ok"}


@app.get("/api/dashboard-data")
def dashboard_data():
    now = time.time()
    with _lock:
        clients_snapshot = dict(_clients)
        threats_snapshot = list(_threats)

    active_count = sum(
        1 for c in clients_snapshot.values()
        if now - c["last_seen"] <= ACTIVE_TIMEOUT_SECONDS
    )

    # --- Gruplama: ayni threat_label birden fazla client'ta gorulduyse
    # tek satirda birlestir. En son gorulen (last_seen) en yeni satir
    # olarak listenin basina gelir - boylece bir salgin/yayilim yeni bir
    # client'ta tekrar tespit edilince o satir tekrar en üste cikar.
    grouped: dict[str, dict] = {}
    for t in threats_snapshot:
        label = t["threat_label"]
        if label not in grouped:
            grouped[label] = {
                "threat_label": label,
                "clients": {},
                "first_seen": t["timestamp"],
                "last_seen": t["timestamp"],
            }
        g = grouped[label]
        g["last_seen"] = max(g["last_seen"], t["timestamp"])
        g["first_seen"] = min(g["first_seen"], t["timestamp"])
        # Ayni client'tan ayni tehdit birden fazla gelirse, en son bilgiyi tut
        g["clients"][t["hostname"]] = {
            "active_user": t["active_user"],
            "file_name": t["file_name"],
            "location": t["location"],
            "timestamp": t["timestamp"],
        }

    rows = []
    for g in grouped.values():
        client_list = [
            {"hostname": h, **info} for h, info in g["clients"].items()
        ]
        client_list.sort(key=lambda c: c["timestamp"], reverse=True)
        rows.append({
            "threat_label": g["threat_label"],
            "affected_client_count": len(g["clients"]),
            "clients": client_list,
            "last_seen": g["last_seen"],
            "last_seen_readable": datetime.fromtimestamp(g["last_seen"], tz=TR_TZ).strftime("%Y-%m-%d %H:%M:%S TRT"),
        })
    rows.sort(key=lambda r: r["last_seen"], reverse=True)

    last_received_at = None
    if threats_snapshot:
        last_ts = max(t["timestamp"] for t in threats_snapshot)
        last_received_at = datetime.fromtimestamp(last_ts, tz=TR_TZ).strftime("%Y-%m-%d %H:%M:%S TRT")

    return JSONResponse({
        "total_threats": len(threats_snapshot),
        "total_clients": len(clients_snapshot),
        "active_clients": active_count,
        "last_received_at": last_received_at,
        "threats": rows,
        "clients": [
            {
                "hostname": h,
                "active_user": c["active_user"],
                "is_active": (now - c["last_seen"]) <= ACTIVE_TIMEOUT_SECONDS,
                "last_seen_seconds_ago": int(now - c["last_seen"]),
                "last_seen_readable": datetime.fromtimestamp(c["last_seen"], tz=TR_TZ).strftime("%H:%M:%S"),
            }
            for h, c in clients_snapshot.items()
        ],
    })


@app.get("/")
def dashboard():
    if DASHBOARD_HTML_PATH.exists():
        return FileResponse(DASHBOARD_HTML_PATH)
    return JSONResponse({"error": "dashboard.html bulunamadi"}, status_code=500)


if __name__ == "__main__":
    print("SentinEL Central Server baslatiliyor -> http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)