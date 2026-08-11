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

Sunucuya ulasilamazsa (kapali, ag sorunu vb.) HATA FIRLATILMAZ - sessizce
loglanir, watcher.py'nin ana akisini asla etkilemez.
"""

import json
import threading
import time
from pathlib import Path

import requests

IDENTITY_FILE_NAME = "client_identity.json"
HEARTBEAT_INTERVAL_SECONDS = 20
REQUEST_TIMEOUT_SECONDS = 5


def load_client_identity(base_dir: Path) -> dict:
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
                return {
                    "hostname": data.get("hostname", "bilinmeyen-client"),
                    "active_user": data.get("active_user", "bilinmiyor"),
                }
        except (json.JSONDecodeError, OSError):
            pass
    return {"hostname": "bilinmeyen-client", "active_user": "bilinmiyor"}


def send_heartbeat(server_url: str, identity: dict, log=None) -> bool:
    try:
        resp = requests.post(
            f"{server_url}/api/heartbeat",
            json={"hostname": identity["hostname"], "active_user": identity["active_user"]},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        if log:
            log.warning(f"  · heartbeat sunucuya ulasamadi ({e.__class__.__name__})")
        return False


def report_threat(server_url: str, identity: dict, threat_label: str, file_name: str, location: str = "", log=None) -> bool:
    try:
        resp = requests.post(
            f"{server_url}/api/report",
            json={
                "hostname": identity["hostname"],
                "active_user": identity["active_user"],
                "threat_label": threat_label,
                "file_name": file_name,
                "location": location,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200 and log:
            log.info(f"  · merkezi sunucuya bildirildi ({identity['hostname']})")
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        if log:
            log.warning(f"  · merkezi sunucuya bildirilemedi ({e.__class__.__name__})")
        return False


def start_heartbeat_thread(server_url: str, identity: dict, log=None) -> threading.Thread:
    """Arka planda surekli calisan, periyodik heartbeat atan daemon thread baslatir."""
    def _loop():
        while True:
            send_heartbeat(server_url, identity, log=log)
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t
