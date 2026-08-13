#!/usr/bin/env python3
"""
license_manager.py
-------------------
watcher.py'nin tarama islemlerine baslamadan once lisans kontrolu yapmasini
saglayan KUCUK ve BAGIMSIZ bir modul (central_reporter.py ile ayni felsefe:
watcher.py'nin tarama/karantina mantigina dokunmaz, sadece disaridan bir
"izin var mi" kapisi ekler).

Ne yapar:
  1. clientID uretir (UUID + hostname -> base64), BIR KERE, sonra cache'ten okur.
  2. Sunucuya (server.py -> /api/license/validate) periyodik olarak sorar.
  3. Sunucudan gelen SIFRELI lisans verisini cozup yerel bir sqlite
     veritabaninda (license_state.db) saklar.
  4. is_active() ile "su an tarama yapilabilir mi" sorusuna hizli (network'e
     gitmeden, cache'ten) cevap verir.

Hostname NEREDEN gelir?
  Bu projede hostname GERCEK sistemden degil, client_identity.json'dan
  (central_reporter.load_client_identity) okunuyor - cunku ayni fiziksel
  makinede birden fazla client simule ediliyor. clientID uretimi de bu
  ayni simule-edilmis hostname'i kullanir; boylece Client1/Client2/Client3
  farkli clientID'ler uretir, gercek donanimdan bagimsiz.

Sunucu erisilemezse (kapali, ag sorunu vb.) servis COKMEZ: en son bilinen
lisans durumu bir "grace period" (varsayilan 12 saat) boyunca gecerli
sayilir. Bu sure de dolarsa lisans PASIF kabul edilir ve tarama durur.
"""

import base64
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

try:
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore[reportMissingImports]
except ImportError:  # requirements.txt'e "cryptography" eklenmeli
    Fernet = None
    InvalidToken = Exception


CLIENT_ID_FILE_NAME = "client_id.json"
LICENSE_DB_FILE_NAME = "license_state.db"
ASSET_LICENSE_KEY_RELATIVE = Path("assets") / "license.key"  # base_dir'in bir ust dizininde: sentinEL/assets/license.key

DEFAULT_REFRESH_INTERVAL_MINUTES = 60      # sunucuya ne siklikla sorulacak
DEFAULT_GRACE_PERIOD_HOURS = 12            # sunucuya ulasilamazsa ne kadar "eski cevap" ile idare edilir
REQUEST_TIMEOUT_SECONDS = 5

# Sunucunun urettigi lisans token'i, refresh araligindan cok daha eski
# gelirse (birisi eski bir token'i tekrar oynatmaya calisiyorsa) reddedilir.
# Fernet'in kendi ttl mekanizmasini kullaniyoruz -> ayrica imza dogrulamasi
# da otomatik yapiliyor (AES-128-CBC + HMAC-SHA256, authenticated encryption).
TOKEN_TTL_MULTIPLIER = 3


# ---------------------------------------------------------------------------
# clientID uretimi (bir kere, sonra cache'ten okunur)
# ---------------------------------------------------------------------------
def get_or_create_client_id(base_dir: Path, hostname: str, log=None) -> str:
    """
    clientID = base64( uuid4() + hostname )

    Ilk calistirmada uretilir ve client_id.json'a yazilir. Sonraki her
    calistirmada dosyadan okunur - YENIDEN URETILMEZ (aksi halde sunucu
    her seferinde "yeni/bilinmeyen client" gorur ve lisans eslesmesi bozulur).
    """
    id_path = base_dir / CLIENT_ID_FILE_NAME

    if id_path.exists():
        try:
            with open(id_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                cached = data.get("client_id")
                if cached:
                    return cached
        except (json.JSONDecodeError, OSError):
            if log:
                log.warning("client_id.json okunamadi, yeniden uretiliyor.")

    raw = f"{uuid.uuid4()}{hostname}"
    client_id = base64.b64encode(raw.encode("utf-8")).decode("ascii")

    with open(id_path, "w", encoding="utf-8") as f:
        json.dump(
            {"client_id": client_id, "hostname": hostname, "generated_at": _now_iso()},
            f, indent=2, ensure_ascii=False,
        )

    if log:
        log.info(f"  · yeni clientID uretildi ve cache'lendi ({id_path.name})")
    return client_id


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_key_from_assets(base_dir: Path, log=None) -> Optional[str]:
    """
    sentinEL/assets/license.key dosyasindan anahtari okur. Boylece 4 ayri
    .env dosyasina (Server + Client1/2/3) ayni degeri elle yazmaya gerek
    kalmaz - tek bir dosya, klasor yapisi geregi zaten hepsinin ortak
    erisebildigi assets/ altinda tutulur.

    base_dir = .../sentinEL/Client1  ->  base_dir.parent = .../sentinEL
    ->  .../sentinEL/assets/license.key
    """
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


# ---------------------------------------------------------------------------
# Yerel "veritabani" (sqlite) - lisans durumunu sakla
# ---------------------------------------------------------------------------
class LicenseStore:
    """license_state.db icindeki tek satirlik lisans durumu tablosu."""

    def __init__(self, db_path: Path, log: Optional[logging.Logger] = None):
        self.db_path = db_path
        self.log = log or logging.getLogger("license_manager")
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS license (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        client_id TEXT,
                        status TEXT,
                        plan TEXT,
                        issued_at TEXT,
                        expires_at TEXT,
                        last_checked_at TEXT,
                        last_success_at TEXT
                    )
                """)
            self.log.info(f"  · Yerel veritabani hazir ({self.db_path.name})")
        except sqlite3.Error as e:
            self.log.error(f"  ✗ Yerel veritabani (license_state.db) baslatilamadi: {e}")
            raise

    def save(self, client_id: str, status: str, plan: Optional[str],
              issued_at: Optional[str], expires_at: Optional[str],
              last_success_at: Optional[str]):
        self.log.info(
            f"  · Veritabanina yaziliyor -> license_state.db (status={status}, plan={plan}, "
            f"expires_at={expires_at})"
        )
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO license (id, client_id, status, plan, issued_at, expires_at,
                                          last_checked_at, last_success_at)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        client_id=excluded.client_id,
                        status=excluded.status,
                        plan=excluded.plan,
                        issued_at=excluded.issued_at,
                        expires_at=excluded.expires_at,
                        last_checked_at=excluded.last_checked_at,
                        last_success_at=COALESCE(excluded.last_success_at, license.last_success_at)
                """, (client_id, status, plan, issued_at, expires_at, _now_iso(), last_success_at))
            self.log.info("  · Veritabani yazma islemi basarili")
        except sqlite3.Error as e:
            self.log.error(f"  ✗ Veritabani yazma hatasi (license_state.db): {e}")

    def load(self) -> Optional[dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM license WHERE id = 1").fetchone()
                result = dict(row) if row else None
            if result:
                self.log.info(f"  · Veritabanindan onceki lisans durumu okundu (status={result.get('status')})")
            return result
        except sqlite3.Error as e:
            self.log.error(f"  ✗ Veritabani okuma hatasi (license_state.db): {e}")
            return None


# ---------------------------------------------------------------------------
# LicenseManager - watcher.py'nin kullandigi ana arayuz
# ---------------------------------------------------------------------------
class LicenseManager:
    def __init__(
        self,
        base_dir: Path,
        server_url: str,
        identity: dict,
        encryption_key: Optional[str] = None,
        refresh_minutes: int = DEFAULT_REFRESH_INTERVAL_MINUTES,
        grace_period_hours: int = DEFAULT_GRACE_PERIOD_HOURS,
        log: Optional[logging.Logger] = None,
    ):
        self.base_dir = base_dir
        self.server_url = server_url.rstrip("/")
        self.identity = identity
        self.refresh_minutes = refresh_minutes
        self.grace_period_hours = grace_period_hours
        self.log = log or logging.getLogger("license_manager")

        self.client_id = get_or_create_client_id(base_dir, identity["hostname"], log=self.log)
        self.store = LicenseStore(base_dir / LICENSE_DB_FILE_NAME, log=self.log)

        key = encryption_key or _load_key_from_assets(base_dir, log=self.log) or os.getenv("LICENSE_ENCRYPTION_KEY")
        if Fernet is None:
            self.log.error("  ✗ 'cryptography' paketi kurulu degil (requirements.txt'e ekleyin). Lisans dogrulanamaz.")
            self._fernet = None
        elif not key:
            self.log.error(
                "  ✗ Sifreleme anahtari bulunamadi. "
                f"'{ASSET_LICENSE_KEY_RELATIVE}' dosyasini ya da .env icinde LICENSE_ENCRYPTION_KEY'i olusturun."
            )
            self._fernet = None
        else:
            self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)

        # Bellek-ici hizli erisim (her dosya taramasinda sqlite'a gitmemek icin)
        self._lock = threading.Lock()
        self._cached_status = "unknown"
        self._cached_expires_at: Optional[datetime] = None
        self._last_success_at: Optional[datetime] = None

        cached = self.store.load()
        if cached:
            self._cached_status = cached["status"]
            self._cached_expires_at = _parse_iso(cached["expires_at"])
            self._last_success_at = _parse_iso(cached["last_success_at"])

    # -- Sunucuya sorma -----------------------------------------------------
    def validate_now(self) -> bool:
        """
        Sunucuya clientID gonderir, cevabi isler. Donen deger: lisans
        su anda AKTIF mi (bu cagriya gore). Ag hatasinda grace period
        mantigi devreye girer (bkz. _apply_grace_period).
        """
        self.log.info("Lisans kontrolu basladi")
        url = f"{self.server_url}/api/license/validate"
        payload = {"client_id": self.client_id, "hostname": self.identity["hostname"]}
        self.log.info(f"  ├─ Sunucu baglantisi deneniyor -> POST {url}")
        self.log.info(f"  │        gonderilecek veri: client={self.client_id[:12]}..., host={self.identity['hostname']}")

        try:
            resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.exceptions.RequestException as e:
            self.log.error(f"  │        Sunucu baglantisi basarisiz ({e.__class__.__name__}: {e})")
            self.log.warning(f"  └─ son bilinen durum kullaniliyor (grace period devrede)")
            return self._apply_grace_period()

        if resp.status_code != 200:
            self.log.warning(f"  │        Yanit alindi -> beklenmeyen durum kodu: HTTP {resp.status_code}")
            self.log.warning(f"  └─ son bilinen durum kullaniliyor (grace period devrede)")
            return self._apply_grace_period()

        self.log.info(f"  │        Yanit alindi -> HTTP {resp.status_code}")

        body = resp.json()
        self.log.info(f"  │        sunucu lisans durumu dondu: status=\"{body.get('status')}\"")

        if body.get("status") != "active":
            # Sunucu acikca "lisans yok / gecersiz" dedi -> HEMEN pasif yap,
            # grace period UYGULANMAZ (bu sunucunun bilincli kararidir, ag
            # hatasi degildir).
            print("License not found")
            self.log.error("  └─ ✗ License not found (sunucu: lisans bulunamadi/gecersiz - govde sifrelenmemis geldi, cunku iletecek gizli veri yok)")
            self._set_state("inactive", plan=None, issued_at=None, expires_at=None,
                             last_success_at=_now_iso())
            return False

        self.log.info(f"  │        license_token alindi ({len(body.get('license_token') or '')} byte, sifreli) -> cozuluyor")
        token = body.get("license_token")
        payload = self._decrypt(token)
        if payload is None:
            self.log.error("  └─ ✗ token cozulemedi/dogrulanamadi, lisans PASIF kabul edildi")
            self._set_state("inactive", plan=None, issued_at=None, expires_at=None,
                             last_success_at=_now_iso())
            return False

        expires_at = payload.get("expires_at")
        plan = payload.get("plan")
        issued_at = payload.get("issued_at")
        self.log.info(f"  │        token cozuldu -> plan={plan}, issued_at={issued_at}, expires_at={expires_at}")

        active = _parse_iso(expires_at) is not None and _parse_iso(expires_at) > datetime.now(timezone.utc)
        status = "active" if active else "expired"

        self._set_state(status, plan=plan, issued_at=issued_at, expires_at=expires_at,
                         last_success_at=_now_iso())

        if status == "active":
            self.log.info(f"  └─ SONUC: lisans AKTIF (plan={plan}, bitis={expires_at})")
        else:
            print("License not found")
            self.log.error(f"  └─ ✗ License not found (lisans suresi dolmus: {expires_at})")

        return status == "active"

    def _decrypt(self, token: Optional[str]) -> Optional[dict]:
        if not token or self._fernet is None:
            return None
        try:
            ttl_seconds = self.refresh_minutes * 60 * TOKEN_TTL_MULTIPLIER
            raw = self._fernet.decrypt(token.encode("ascii"), ttl=ttl_seconds)
            return json.loads(raw.decode("utf-8"))
        except InvalidToken:
            self.log.error("  ✗ lisans verisi cozulemedi/dogrulanamadi (bozuk veya suresi gecmis token)")
            return None
        except Exception as e:
            self.log.error(f"  ✗ lisans verisi islenirken hata: {e}")
            return None

    def _apply_grace_period(self) -> bool:
        """Sunucuya ulasilamadi. Son basarili kontrolden bu yana grace period
        gecmediyse eski durumu kullanmaya devam et; gectiyse pasif yap."""
        with self._lock:
            if self._cached_status != "active" or self._last_success_at is None:
                return self._cached_status == "active"

            elapsed_hours = (datetime.now(timezone.utc) - self._last_success_at).total_seconds() / 3600
            if elapsed_hours > self.grace_period_hours:
                self.log.error(
                    f"  ✗ License not found (sunucuya {elapsed_hours:.1f} saattir ulasilamiyor, "
                    f"grace period {self.grace_period_hours}s asildi)"
                )
                print("License not found")
                self._cached_status = "inactive"
                self.store.save(self.client_id, "inactive", None, None, None,
                                 self._last_success_at.isoformat() if self._last_success_at else None)
                return False

            self.log.warning(
                f"  · grace period icinde ({elapsed_hours:.1f}/{self.grace_period_hours}sa), "
                f"lisans aktif kabul ediliyor"
            )
            return True

    def _set_state(self, status: str, plan, issued_at, expires_at, last_success_at):
        with self._lock:
            self._cached_status = status
            self._cached_expires_at = _parse_iso(expires_at)
            self._last_success_at = _parse_iso(last_success_at)
        self.store.save(self.client_id, status, plan, issued_at, expires_at, last_success_at)

    # -- watcher.py'nin her dosyada cagirdigi hizli kontrol -----------------
    def is_active(self) -> bool:
        """Network'e GITMEDEN, son bilinen durumu doner. Gercek dogrulama
        arka plandaki refresh thread'i tarafindan periyodik yapilir."""
        with self._lock:
            if self._cached_status != "active":
                return False
            if self._cached_expires_at and self._cached_expires_at <= datetime.now(timezone.utc):
                return False
            return True

    def status_summary(self) -> dict:
        with self._lock:
            return {
                "client_id": self.client_id,
                "status": self._cached_status,
                "expires_at": self._cached_expires_at.isoformat() if self._cached_expires_at else None,
            }

    # -- Arka plan yenileme thread'i -----------------------------------------
    def start_refresh_thread(self) -> threading.Thread:
        def _loop():
            while True:
                time.sleep(self.refresh_minutes * 60)
                self.validate_now()

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        return t


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None