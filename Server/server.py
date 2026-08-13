#!/usr/bin/env python3
"""
server.py
---------
SentinEL merkezi sunucusu (SOC ekrani icin backend).

Ne yapar:
  - Client'lardan tehdit bildirimi alir (POST /api/report)
  - Client'lardan heartbeat (nabiz) alir (POST /api/heartbeat)
  - Client'lardan lisans dogrulama istegi alir (POST /api/license/validate)
  - Dashboard'un periyodik cektigi ozet veriyi uretir (GET /api/dashboard-data)
  - Dashboard'un Security Center bolumu icin lisans ozetini uretir
    (GET /api/license/status)
  - Dashboard HTML sayfasini servis eder (GET /)

Veri kalicidir: threats_log.json ve licenses.json dosyalarina yazilir,
sunucu yeniden baslasa bile gecmis veriler kaybolmaz. Client listesi
(heartbeat zamanlari) ise sadece bellekte tutulur - sunucu yeniden
baslarsa "aktif/pasif" durumu sifirdan hesaplanir (bu normal, sorun degil).

Lisans mantigi ayri bir modulde (license_service.py) - bu dosya sadece
HTTP katmanini saglar, iş mantığına dokunmaz (central_reporter.py /
watcher.py ile ayni "kucuk bagimsiz modul" felsefesi).

Calistirma:
    python3 server.py
    -> http://localhost:8000 adresinde acilir

Gereksinim: .env dosyasinda LICENSE_ENCRYPTION_KEY tanimli olmali (bkz.
license_service.py docstring'i / DESIGN.md).

LOGLAMA: Tum log satirlari seviyeli (INFO/WARNING/ERROR) ve TURKCE'dir.
Hem terminale hem de server.log dosyasina yazilir.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

from license_service import LicenseService

BASE_DIR = Path(__file__).resolve().parent
THREATS_LOG_PATH = BASE_DIR / "threats_log.json"
DASHBOARD_HTML_PATH = BASE_DIR / "dashboard.html"
SERVER_LOG_PATH = BASE_DIR / "server.log"

load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Loglama kurulumu: terminale ve server.log'a, HER SATIRDA seviye (INFO/
# WARNING/ERROR) belirtilerek, tamamen Turkce mesajlarla yazar.
# ---------------------------------------------------------------------------
_log_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s]".ljust(29) + " %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler = logging.FileHandler(SERVER_LOG_PATH, encoding="utf-8")
_file_handler.setFormatter(_log_formatter)
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(_log_formatter)

logging.basicConfig(level=logging.INFO, handlers=[_file_handler, _console_handler])
log = logging.getLogger("server")

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

# Lisans is mantigi - ayri modul (bkz. license_service.py)
_license_service = LicenseService(BASE_DIR)


def _load_threats_from_disk():
    global _threats
    if THREATS_LOG_PATH.exists():
        try:
            with open(THREATS_LOG_PATH, "r", encoding="utf-8") as f:
                _threats = json.load(f)
            log.info(f"Veritabani yuklendi -> threats_log.json ({len(_threats)} kayit)")
        except (json.JSONDecodeError, OSError) as e:
            log.error(f"threats_log.json okunamadi, bos liste ile baslaniyor: {e}")
            _threats = []
    else:
        log.info("threats_log.json bulunamadi, yeni/bos bir kayit listesiyle baslaniyor")


def _save_threats_to_disk():
    try:
        with open(THREATS_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(_threats, f, indent=2, ensure_ascii=False)
        log.info(f"Veritabanina yazildi -> threats_log.json ({len(_threats)} kayit, basarili)")
    except OSError as e:
        log.error(f"Veritabanina yazma hatasi -> threats_log.json: {e}")


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


class LicenseValidatePayload(BaseModel):
    client_id: str
    hostname: str


# ---------------------------------------------------------------------------
# Endpoint'ler - mevcut (degismedi)
# ---------------------------------------------------------------------------
@app.post("/api/heartbeat")
def receive_heartbeat(payload: HeartbeatPayload):
    log.info(f"Istek alindi -> POST /api/heartbeat (hostname={payload.hostname}, active_user={payload.active_user})")

    try:
        with _lock:
            _clients[payload.hostname] = {
                "last_seen": time.time(),
                "active_user": payload.active_user or "-",
            }
        log.info(f"Islem tamamlandi -> client '{payload.hostname}' aktif olarak isaretlendi (bellek-ici durum guncellendi)")
        return {"status": "ok"}
    except Exception as e:
        log.error(f"Heartbeat islenirken beklenmeyen hata olustu: {e}")
        raise HTTPException(status_code=500, detail="Heartbeat islenemedi")


@app.post("/api/report")
def receive_report(payload: ThreatPayload):
    log.info(
        f"Istek alindi -> POST /api/report (hostname={payload.hostname}, "
        f"threat_label={payload.threat_label}, file_name={payload.file_name})"
    )

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

    log.info(f"Veri dogrulandi -> tehdit kaydi olusturuluyor: {payload.file_name} ({payload.threat_label})")

    try:
        with _lock:
            _threats.append(record)
            _save_threats_to_disk()
            # Bir tehdit bildirmek de o client'in "canli" oldugunun kanitidir
            _clients[payload.hostname] = {
                "last_seen": now,
                "active_user": payload.active_user,
            }
        log.info(f"Islem tamamlandi -> tehdit kaydi basariyla eklendi (toplam {len(_threats)} kayit)")
        return {"status": "ok"}
    except Exception as e:
        log.error(f"Tehdit kaydi islenirken beklenmeyen hata olustu: {e}")
        raise HTTPException(status_code=500, detail="Rapor islenemedi")


@app.get("/api/dashboard-data")
def dashboard_data():
    log.info("Istek alindi -> GET /api/dashboard-data (dashboard ozet verisi istendi)")
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


# ---------------------------------------------------------------------------
# Endpoint'ler - YENI: lisanslama
# ---------------------------------------------------------------------------
@app.post("/api/license/validate")
def validate_license(payload: LicenseValidatePayload):
    """
    Client (license_manager.py) periyodik olarak buraya sorar.
    - Gecerli lisans varsa: {"status": "active", "license_token": "<sifreli>"}
    - Yoksa/iptal/suresi dolmus: {"status": "no_license"}  (SIFRELENMEMIS -
      cunku iletecek gizli bir veri yok, sadece "hayir" cevabi)
    Bu endpoint HER ZAMAN HTTP 200 doner; karar govdedeki "status"
    alaninda tasinir - client tarafinda tek bir JSON-parse yolu yeterli olsun diye.
    """
    log.info(f"Istek alindi -> POST /api/license/validate (hostname={payload.hostname})")
    result = _license_service.validate(payload.client_id, payload.hostname)
    log.info(f"Islem tamamlandi -> /api/license/validate yaniti gonderildi (status={result.get('status')})")
    return JSONResponse(result)


@app.get("/api/license/status")
def license_status():
    """Dashboard'daki Security Center bolumu bunu cagirir (sifrelenmemis,
    sadece ic aglarda/yonetici ekraninda gosterilecek ozet veri)."""
    log.info("Istek alindi -> GET /api/license/status (dashboard lisans ozeti istendi)")
    rows = _license_service.status_for_dashboard()
    return JSONResponse({"licenses": rows})


if __name__ == "__main__":
    log.info("=" * 60)
    log.info("SentinEL Central Server baslatiliyor -> http://localhost:8000")
    log.info("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)