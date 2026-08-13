#!/usr/bin/env python3
"""
central_reporter.py
--------------------
watcher.py'nin merkezi sunucuyla (server.py) konusmasini saglayan
KUCUK ve BAGIMSIZ bir modul. watcher.py'nin tarama/karantina/mail
mantigina hic dokunmaz - sadece zararli tespit edildiginde EK olarak
sunucuya bir POST istegi atar, ayrica arka planda periyodik heartbeat
gonderir.

Client kimligi (hostname, active_user) GERCEK sistemden degil,
client_identity.json dosyasindan okunur - cunku ayni fiziksel makinede
3 ayri client simule edilecek, gercek hostname/user hepsinde ayni cikardi.

Sunucuya ulasilamazsa (kapali, ag sorunu vb.) HATA FIRLATILMAZ - seviyeli
ve ayrintili sekilde loglanir, watcher.py'nin ana akisini asla etkilemez.
Bunun yerine gonderilemeyen tehdit bildirimleri yerel bir "offline cache"
dosyasina (offline_reports_cache.json) yazilir ve sunucu tekrar erisilebilir
oldugunda (bir sonraki basarili heartbeat'te) otomatik olarak sunucuya
gonderilir.
"""

import json
import threading
import time
from pathlib import Path
from typing import Optional

import requests

IDENTITY_FILE_NAME = "client_identity.json"
OFFLINE_CACHE_FILE_NAME = "offline_reports_cache.json"
HEARTBEAT_INTERVAL_SECONDS = 20
REQUEST_TIMEOUT_SECONDS = 5

_cache_lock = threading.Lock()


def load_client_identity(base_dir: Path, log=None) -> dict:
    """
    client_identity.json'dan simule edilmis hostname/kullanici bilgisini
    okur. Dosya yoksa (tek client / eski kurulum) makul bir varsayilana
    duser, hata vermez.
    """
    identity_path = base_dir / IDENTITY_FILE_NAME
    if identity_path.exists():
        try:
            with open(identity_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                identity = {
                    "hostname": data.get("hostname", "bilinmeyen-client"),
                    "active_user": data.get("active_user", "bilinmiyor"),
                }
                if log:
                    log.info(f"Client kimligi yuklendi: hostname={identity['hostname']}")
                return identity
        except (json.JSONDecodeError, OSError) as e:
            if log:
                log.warning(f"client_identity.json okunamadi ({e}), varsayilan kimlik kullanilacak")
    return {"hostname": "bilinmeyen-client", "active_user": "bilinmiyor"}


# ---------------------------------------------------------------------------
# Offline cache: sunucuya gonderilemeyen tehdit bildirimlerini yerelde tutar
# ---------------------------------------------------------------------------
def _offline_cache_path(base_dir: Path) -> Path:
    return base_dir / OFFLINE_CACHE_FILE_NAME


def _load_offline_cache(base_dir: Path, log=None) -> list:
    path = _offline_cache_path(base_dir)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as e:
        if log:
            log.warning(f"offline_reports_cache.json okunamadi ({e}), bos liste ile devam ediliyor")
        return []


def _save_offline_cache(base_dir: Path, cache: list, log=None):
    path = _offline_cache_path(base_dir)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except OSError as e:
        if log:
            log.error(f"offline_reports_cache.json diske yazilamadi: {e}")


def _cache_failed_report(base_dir: Path, payload: dict, log=None):
    with _cache_lock:
        cache = _load_offline_cache(base_dir, log=log)
        cache.append(payload)
        _save_offline_cache(base_dir, cache, log=log)
    if log:
        log.info(f"Veriler local cache'de tutuldu (toplam {len(cache)} bekleyen kayit)")


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
def send_heartbeat(server_url: str, identity: dict, base_dir: Optional[Path] = None, log=None) -> bool:
    endpoint = f"{server_url}/api/heartbeat"
    payload = {"hostname": identity["hostname"], "active_user": identity["active_user"]}

    if log:
        log.info(f"Sunucu baglantisi deneniyor -> POST {endpoint}")
        log.info(f"Gonderilecek veri: {payload}")

    try:
        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.RequestException as e:
        if log:
            log.error(f"Sunucu baglantisi basarisiz ({e.__class__.__name__}: {e})")
        return False

    if resp.status_code == 200:
        if log:
            log.info(f"Yanit alindi -> HTTP {resp.status_code} (heartbeat kabul edildi)")
        return True

    if log:
        log.warning(f"Yanit alindi -> beklenmeyen durum kodu: HTTP {resp.status_code}")
    return False


def start_heartbeat_thread(server_url: str, identity: dict, base_dir: Optional[Path] = None, log=None) -> threading.Thread:
    """
    Arka planda surekli calisan, periyodik heartbeat atan daemon thread
    baslatir. Heartbeat basarili oldugunda (yani sunucu tekrar erisilebilir
    hale geldiginde) offline cache'te bekleyen tehdit bildirimlerini de
    otomatik olarak senkronize etmeyi dener.
    """
    def _loop():
        while True:
            ok = send_heartbeat(server_url, identity, base_dir=base_dir, log=log)
            if ok and base_dir is not None:
                resync_offline_cache(server_url, identity, base_dir, log=log)
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Tehdit bildirimi
# ---------------------------------------------------------------------------
def report_threat(server_url: str, identity: dict, threat_label: str, file_name: str,
                   location: str = "", base_dir: Optional[Path] = None, log=None) -> bool:
    endpoint = f"{server_url}/api/report"
    payload = {
        "hostname": identity["hostname"],
        "active_user": identity["active_user"],
        "threat_label": threat_label,
        "file_name": file_name,
        "location": location,
    }

    if log:
        log.info(f"Sunucu baglantisi deneniyor -> POST {endpoint}")
        log.info(f"Gonderilecek veri: {payload}")

    try:
        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.RequestException as e:
        if log:
            log.error(f"Sunucu baglantisi basarisiz ({e.__class__.__name__}: {e})")
        if base_dir is not None:
            _cache_failed_report(base_dir, payload, log=log)
        return False

    if resp.status_code == 200:
        if log:
            log.info(f"Yanit alindi -> HTTP {resp.status_code} (merkezi sunucuya bildirildi: {identity['hostname']})")
        return True

    if log:
        log.warning(f"Yanit alindi -> beklenmeyen durum kodu: HTTP {resp.status_code}, veri cache'e aliniyor")
    if base_dir is not None:
        _cache_failed_report(base_dir, payload, log=log)
    return False


# ---------------------------------------------------------------------------
# Offline cache senkronizasyonu
# ---------------------------------------------------------------------------
def resync_offline_cache(server_url: str, identity: dict, base_dir: Path, log=None) -> None:
    """
    offline_reports_cache.json'da bekleyen (daha once sunucuya gonderilemeyen)
    tehdit bildirimlerini sunucuya tekrar gondermeyi dener. Basariyla giden
    kayitlar cache'ten silinir; basarisiz olanlar bir sonraki denemeye kadar
    cache'te kalir.
    """
    with _cache_lock:
        cache = _load_offline_cache(base_dir, log=log)

    if not cache:
        return

    if log:
        log.info(f"Cache'de tutulan veriler bulundu ({len(cache)} kayit)")
        log.info("Veriler sunucuya gonderiliyor")

    endpoint = f"{server_url}/api/report"
    remaining = []
    sent_count = 0

    for payload in cache:
        try:
            resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.exceptions.RequestException as e:
            if log:
                log.warning(f"Cache senkronizasyonu sirasinda baglanti hatasi ({e.__class__.__name__}), kayit cache'te kaliyor")
            remaining.append(payload)
            continue

        if resp.status_code == 200:
            sent_count += 1
        else:
            if log:
                log.warning(f"Cache'teki kayit gonderilemedi (HTTP {resp.status_code}), cache'te kaliyor")
            remaining.append(payload)

    with _cache_lock:
        _save_offline_cache(base_dir, remaining, log=log)

    if log:
        if not remaining:
            log.info(f"Tum veriler basariyla senkronize edildi ({sent_count}/{len(cache)})")
        else:
            log.warning(f"{len(remaining)}/{len(cache)} kayit senkronize edilemedi, cache'de bekletiliyor")