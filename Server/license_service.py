#!/usr/bin/env python3
"""
license_service.py
-------------------
server.py'ye eklenen lisans dogrulama mantigini icinde barindiran, KUCUK
ve BAGIMSIZ bir modul (central_reporter.py'nin sunucu tarafindaki karsiligi
gibi dusunulebilir). server.py'nin mevcut heartbeat/threat-report akisina
DOKUNMAZ, sadece iki yeni endpoint icin gereken is mantigini saglar:

  - POST /api/license/validate  (client -> sunucu)   [server.py'de tanimli]
  - GET  /api/license/status    (dashboard -> sunucu) [server.py'de tanimli]

Lisans kayitlari licenses.json dosyasinda tutulur:
  {
    "<client_id>": {
      "hostname": "...",
      "plan": "pro",
      "status": "active" | "revoked",
      "issued_at": "2026-08-01T00:00:00+00:00",
      "expires_at": "2027-08-01T00:00:00+00:00",
      "last_check_in": "..."      <- her /validate cagrisinda guncellenir
    }
  }

Lisans kayitlarini olusturmak/iptal etmek icin license_admin.py CLI'ini
kullanin (ayni klasorde).

SIFRELEME: cryptography.fernet.Fernet (AES-128-CBC + HMAC-SHA256,
authenticated encryption) kullanilir. Anahtar (.env -> LICENSE_ENCRYPTION_KEY)
sunucu ve TUM client'larda AYNI olmalidir. Bu simetrik bir anahtardir;
guvenlik notlari icin DESIGN.md'ye bakin.
"""

import base64
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.fernet import Fernet  # pyright: ignore[reportMissingImports]  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - ortamda opsiyonel olarak bulunmayabilir
    Fernet = None

LICENSES_FILE_NAME = "licenses.json"
ASSET_LICENSE_KEY_RELATIVE = Path("assets") / "license.key"  # base_dir'in bir ust dizininde: sentinEL/assets/license.key

# uuid4() str() gosterimi HER ZAMAN sabit uzunluktadir: 8-4-4-4-12 hex, tiresiyle
# birlikte 36 karakter. clientID = base64(uuid4() + hostname) oldugundan, decode
# edilen metnin ilk 36 karakteri her zaman uuid, geri kalani hostname'dir.
_UUID_STR_LENGTH = 36

_lock = threading.Lock()


def _load_key_from_assets(base_dir: Path, log=None) -> Optional[str]:
    key_path = base_dir.parent / ASSET_LICENSE_KEY_RELATIVE
    if key_path.exists():
        try:
            key = key_path.read_text(encoding="utf-8").strip()
            if key:
                return key
        except OSError:
            if log:
                log.warning(f"  · {key_path} okunamadi")
    return None


class LicenseService:
    def __init__(self, base_dir: Path, encryption_key: Optional[str] = None, log: Optional[logging.Logger] = None):
        self.path = base_dir / LICENSES_FILE_NAME
        self.log = log or logging.getLogger("license_service")
        self._licenses: dict = {}
        self._mtime: float = 0.0
        self._load()

        key = encryption_key or _load_key_from_assets(base_dir, log=self.log) or os.getenv("LICENSE_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError(
                "Sifreleme anahtari bulunamadi. "
                f"'{ASSET_LICENSE_KEY_RELATIVE}' dosyasini olusturun (bkz. generate_license_key.py) "
                "ya da .env'e LICENSE_ENCRYPTION_KEY ekleyin (sunucu VE her client'ta AYNI anahtar)."
            )
        if Fernet is None:
            raise RuntimeError(
                "cryptography paketi yuklu degil. Lisans sifrelemesi icin 'cryptography' bagimliligini kurun."
            )
        self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)

    # -- Diskten oku/yaz ------------------------------------------------
    def _load(self):
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._licenses = json.load(f)
                self._mtime = self.path.stat().st_mtime
                self.log.info(f"  · Veritabani yuklendi -> licenses.json ({len(self._licenses)} kayit)")
            except (json.JSONDecodeError, OSError) as e:
                self.log.error(f"  · Veritabani okuma hatasi -> licenses.json: {e}")
                self._licenses = {}
        else:
            self.log.info("  · licenses.json bulunamadi, bos kayit listesiyle baslaniyor")
            self._licenses = {}

    def _reload_if_changed(self):
        """
        licenses.json baska bir surec tarafindan (ornegin license_admin.py
        CLI'i) degistirilmis olabilir - sunucu calisirken bellekteki kopya
        bunu otomatik gormez. Her istekte dosyanin degisim zamanini (mtime)
        kontrol edip degismisse yeniden okuyoruz. Kucuk bir dosya oldugu
        icin bu maliyet ihmal edilebilir duzeyde.
        """
        try:
            current_mtime = self.path.stat().st_mtime if self.path.exists() else 0.0
        except OSError:
            return
        if current_mtime != self._mtime:
            self._load()
            self.log.info("  · licenses.json diskte degismis, bellekteki kopya yenilendi")

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._licenses, f, indent=2, ensure_ascii=False)
            self._mtime = self.path.stat().st_mtime
            self.log.info(f"  · Veritabanina yazildi -> licenses.json ({len(self._licenses)} kayit, basarili)")
        except OSError as e:
            self.log.error(f"  · Veritabanina yazma hatasi -> licenses.json: {e}")
            raise

    # -- Admin islemleri (license_admin.py bunlari cagirir) --------------
    def issue(self, client_id: str, hostname: str, plan: str, valid_days: int) -> dict:
        now = datetime.now(timezone.utc)
        expires_at = now.replace(microsecond=0)
        expires_at = expires_at.fromtimestamp(expires_at.timestamp() + valid_days * 86400, tz=timezone.utc)
        record = {
            "hostname": hostname,
            "plan": plan,
            "status": "active",
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "last_check_in": None,
        }
        self.log.info(f"  · Veri alindi -> yeni lisans olusturuluyor (hostname={hostname}, plan={plan}, {valid_days} gun)")
        with _lock:
            self._licenses[client_id] = record
            self._save()
        self.log.info(f"  · Lisans basariyla eklendi (hostname={hostname})")
        return record

    def revoke(self, client_id: str) -> bool:
        short_id = client_id[:12] + "..." if len(client_id) > 12 else client_id
        with _lock:
            if client_id not in self._licenses:
                self.log.warning(f"  · Iptal islemi basarisiz: '{short_id}' icin kayitli lisans yok")
                return False
            self._licenses[client_id]["status"] = "revoked"
            self._save()
            self.log.info(f"  · Lisans basariyla iptal edildi ({short_id})")
            return True

    def list_all(self) -> dict:
        with _lock:
            return dict(self._licenses)

    # -- Client dogrulama akisi (server.py /api/license/validate cagirir) --
    def validate(self, client_id: str, hostname: str) -> dict:
        """
        Donen deger dogrudan HTTP response body'si olarak kullanilir:
          - lisans yoksa/gecersizse: {"status": "no_license"}   (SIFRELENMEMIS)
          - lisans gecerliyse: {"status": "active", "license_token": "<encrypted>"}
        """
        short_id = client_id[:12] + "..." if len(client_id) > 12 else client_id
        self.log.info(f"istek alindi -> POST /api/license/validate  (client={short_id}, host={hostname})")

        # clientID'yi coz: base64(uuid4()+hostname) -> icine gomulu hostname'i
        # cikarip, istegin govdesinde ayrica gelen hostname ile eslesiyor mu
        # kontrol et. Eslesmiyorsa (birisi baska bir client'in ID'sini farkli
        # bir hostname ile kullanmaya calisiyorsa) supheli sayilip reddedilir.
        embedded_hostname = self._decode_embedded_hostname(client_id)
        if embedded_hostname is not None and embedded_hostname != hostname:
            self._log_denial(
                short_id, hostname,
                f"hostname uyusmazligi (clientID icinde '{embedded_hostname}' gomulu, "
                f"istekte '{hostname}' geldi - olasi sahtecilik)"
            )
            return {"status": "no_license"}

        with _lock:
            self._reload_if_changed()
            record = self._licenses.get(client_id)

            if record is None:
                self._log_denial(short_id, hostname, "kayitli lisans yok")
                return {"status": "no_license"}

            if record.get("status") == "revoked":
                self._log_denial(short_id, hostname, "lisans iptal edilmis")
                return {"status": "no_license"}

            expires_at = _parse_iso(record.get("expires_at"))
            if expires_at is None or expires_at <= datetime.now(timezone.utc):
                self._log_denial(short_id, hostname, f"lisans suresi dolmus ({record.get('expires_at')})")
                return {"status": "no_license"}

            # Gecerli -> check-in zamanini guncelle (Security Center bunu gosterir)
            record["last_check_in"] = datetime.now(timezone.utc).isoformat()
            self._save()

            payload = {
                "client_id": client_id,
                "hostname": hostname,
                "plan": record.get("plan"),
                "status": "active",
                "issued_at": record.get("issued_at"),
                "expires_at": record.get("expires_at"),
            }
            token = self._fernet.encrypt(json.dumps(payload).encode("utf-8")).decode("ascii")
            self.log.info(
                f"  └─ yanit gonderildi -> HTTP 200, status=\"active\"  "
                f"(plan={record.get('plan')}, bitis={record.get('expires_at')}, token={len(token)} byte sifreli)"
            )
            return {"status": "active", "license_token": token}

    def _decode_embedded_hostname(self, client_id: str) -> Optional[str]:
        """
        clientID = base64(uuid4() + hostname). Decode edip hostname kismini
        cikarir. Bozuk/format-disi bir client_id gelirse (decode hatasi,
        uuid uzunlugundan kisa vb.) None doner - bu durumda cagiran taraf
        eslesme kontrolunu ATLAR (fail-open), cunku bu daha cok bozuk veri/
        eski format anlamina gelir, mutlaka sahtecilik degildir.
        """
        try:
            decoded = base64.b64decode(client_id).decode("utf-8")
        except Exception:
            self.log.warning(f"  · clientID base64 olarak coz\u00fclemedi, hostname kontrolu atlaniyor")
            return None
        if len(decoded) <= _UUID_STR_LENGTH:
            return None
        return decoded[_UUID_STR_LENGTH:]

    def _log_denial(self, short_id: str, hostname: str, reason: str):
        self.log.warning(f"  └─ yanit gonderildi -> HTTP 200, status=\"no_license\"  (sebep: {reason})")
        # Ayrica dashboard/denial takibi icin ayrı bir satirda net formatta:
        self.log.warning(f"[LICENSE DENIED] client={short_id} host={hostname} reason={reason}")

    # -- Dashboard icin ozet (server.py /api/license/status cagirir) -----
    def status_for_dashboard(self) -> list:
        now = datetime.now(timezone.utc)
        rows = []
        with _lock:
            self._reload_if_changed()
            for client_id, record in self._licenses.items():
                expires_at = _parse_iso(record.get("expires_at"))
                days_remaining = None
                effective_status = record.get("status", "unknown")

                if expires_at:
                    days_remaining = (expires_at - now).days
                    if effective_status == "active" and expires_at <= now:
                        effective_status = "expired"

                rows.append({
                    "hostname": record.get("hostname"),
                    "plan": record.get("plan"),
                    "status": effective_status,
                    "expires_at": record.get("expires_at"),
                    "days_remaining": days_remaining,
                    "last_check_in": record.get("last_check_in"),
                })
        rows.sort(key=lambda r: (r["days_remaining"] is None, r["days_remaining"]))
        return rows


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None