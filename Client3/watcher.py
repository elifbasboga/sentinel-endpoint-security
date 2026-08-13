#!/usr/bin/env python3
"""
watcher.py
----------
Belirli bir klasoru surekli izler. Klasore yeni dosya dustugunde:
  - Uzantisi config.json'daki "scan_extensions" listesindeyse (exe, dmg, sh, vb.
    -> uygulama/betik turu dosyalar) -> dosya OLDUGU YERDE taranir (VirusTotal'a
    sorulur/gerekirse yuklenir). Sonuc ZARARLI (detected > 0) ise dosya
    'karantina/' klasorune tasinir; TEMIZ ise dosya oldugu yerde kalir.
  - "bypass_extensions" listesindeyse (docx, pdf, jpg vb. -> zararsiz kabul
    edilen turler) -> dokunulmaz, oldugu yerde kalir, sadece loglanir.
  - Listede olmayan bir uzanti gelirse config.json'daki
    "default_action_for_unknown_extension" degerine gore davranilir.

Sadece ZARARLI cikan dosyalar watched_files/karantina/ alt klasorune tasinir.
Temiz ve guvenli/bypass dosyalar hicbir yere tasinmaz, olduklari yerde kalir.

Hash Blacklist/Cache:
  Daha once VT'de sorgulanmis hash'lerin sonucu hash_cache.json'da tutulur.
  Ayni hash tekrar gelirse VT'ye hic sorgu atilmadan, dogrudan bu cache'ten
  ("bilinen zararli / bilinen temiz" olarak) cevap verilir. Bu hem cok daha
  hizlidir hem de VT API rate limit'ine takilma riskini azaltir.

Kullanim:
    python3 watcher.py

    (Durdurmak icin Ctrl+C)
"""

import json
import logging
import shutil
import sys
import time
import traceback
from pathlib import Path

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from central_reporter import load_client_identity, start_heartbeat_thread, report_threat
from license_manager import LicenseManager 

# vt_scan.py icindeki fonksiyonlari yeniden kullaniyoruz
from vt_scan import (
    API_KEY,
    BASE_URL,
    get_report_by_hash,
    get_remaining_quota,
    poll_analysis,
    sha256_of_file,
    upload_file,
)

from reporter import (
    get_computer_name,
    get_active_user,
    get_system_uptime,
    get_macos_version,
    format_duration,
    build_pdf_report,
    send_email_with_attachment,
)

SERVICE_START_TIME = time.time()

# Script'in bulunduğu klasor - config.json, .env, watched_files/ vb.
# hep buna gore bulunur; nereden calistirilirsa calistirilsin (terminal,
# VS Code Run butonu, farkli bir klasorden, PyInstaller ile derlenmis .exe) hep
# ayni yerlere bakar. PyInstaller --onefile derlemesinde __file__ gecici bir
# cikartma klasorunu (_MEIxxxx) gosterir; bu durumda sys.executable'in
# (gercek binary'nin) bulundugu klasoru kullanmamiz gerekir.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

# EICAR test dosyasinin bilinen SHA256'i - VT baglanti/API key testi icin kullanilir
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

CONFIG_PATH = BASE_DIR / "config.json"
LOG_PATH = BASE_DIR / "watcher.log"
REPORTS_DIR = BASE_DIR / "reports"

# Merkezi sunucu entegrasyonu (opsiyonel - config.json'da tanimli degilse
# hicbir sey degismez, watcher.py eskisi gibi tek-basina calisir)
CLIENT_IDENTITY = load_client_identity(BASE_DIR, log=None)

# ---------------------------------------------------------------------------
# Loglama: watcher.log'a duz metin, terminale renkli yazar
# ---------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    """Terminalde log seviyesine gore renkli cikti icin."""
    GREY = "\033[90m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BOLD_RED = "\033[1;31m"
    RESET = "\033[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: CYAN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, self.RESET)
        time_str = f"{self.GREY}{self.formatTime(record, '%H:%M:%S')}{self.RESET}"
        # Parantezler her zaman sikisik ([INFO], [WARNING]), hizalama icin
        # bosluk KAPALI PARANTEZDEN SONRA eklenir - parantez ici gerilmez.
        tag = f"[{record.levelname}]".ljust(10)
        level_str = f"{color}{tag}{self.RESET}"
        message = record.getMessage()
        return f"{time_str} {level_str} {message}"


class PlainAlignedFormatter(logging.Formatter):
    """watcher.log dosyasi icin renksiz ama ayni hizalama mantigiyla format."""

    def format(self, record):
        time_str = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        tag = f"[{record.levelname}]".ljust(10)
        message = record.getMessage()
        return f"{time_str} {tag} {message}"


file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
file_handler.setFormatter(PlainAlignedFormatter())

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColorFormatter())

logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
log = logging.getLogger("watcher")


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        log.error(f"config.json bulunamadi: {CONFIG_PATH.resolve()}")
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_hash_cache(cache_path: Path) -> dict:
    """
    Hash blacklist/cache dosyasini yukler.
    Format: { "<sha256>": {"malicious": <int>, "total": <int>,
                            "file_name": "...", "checked_at": "..."} }
    """
    if not cache_path.exists():
        return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        log.warning(f"hash_cache.json okunamadi, bos cache ile baslaniyor.")
        return {}


def save_hash_cache(cache_path: Path, cache: dict):
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def load_processed_state(state_path: Path) -> dict:
    """
    Daha once (bu calistirmada ya da onceki bir calistirmada) islenmis
    dosyalarin kaydini tutar. Format: { "<dosya_adi>": {"size": <int>,
    "mtime": <float>} }. Bu, TEMIZ ya da BYPASS edilen dosyalarin -
    karantinaya tasinan zararlilarin aksine - klasorde oldugu yerde
    kalmasi yuzunden servis her yeniden baslatildiginda tekrar tekrar
    "yeni dosya" gibi islenmesini engellemek icin kullanilir.
    """
    if not state_path.exists():
        return {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        log.warning("processed_files.json okunamadi, bos durum ile baslaniyor.")
        return {}


def save_processed_state(state_path: Path, state: dict):
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def check_vt_connection() -> bool:
    """
    Servis baslarken VirusTotal'a gercekten baglanabildigimizi ve API
    key'in gecerli oldugunu teyit eder. Bilinen bir hash (EICAR) sorgulanir.
    """
    log.info(f"istek atildi -> GET {BASE_URL}/files/{{eicar_hash}} (baglanti testi)")

    if not API_KEY:
        log.error("BAGLANTI BASARISIZ: VT_API_KEY bulunamadi (.env dosyasini kontrol et).")
        return False

    try:
        headers = {"x-apikey": API_KEY}
        resp = requests.get(f"{BASE_URL}/files/{EICAR_SHA256}", headers=headers, timeout=10)
        if resp.status_code == 200:
            log.info("yanit alindi -> baglanti teyit edildi (API key gecerli)")
            return True
        elif resp.status_code == 401:
            log.error("✗ BAGLANTI BASARISIZ: API key gecersiz (401 Unauthorized)")
            return False
        else:
            log.warning(f"yanit alindi -> beklenmeyen durum kodu: HTTP {resp.status_code}")
            return True  # sunucuya ulasildi, servis calismaya devam edebilir
    except requests.exceptions.RequestException as e:
        log.error(f"✗ BAGLANTI BASARISIZ: VirusTotal.com'a ulasilamiyor ({e})")
        return False


def decide_action(path: Path, config: dict) -> str:
    """
    Dosya uzantisina gore 'scan' ya da 'bypass' karari verir.
    Karar surecini de ayrintili loglar.
    """
    ext = path.suffix.lower() or "(uzantisiz)"
    scan_list = {e.lower() for e in config["scan_extensions"]}
    bypass_list = {e.lower() for e in config["bypass_extensions"]}

    log.info(f"  ├─ {'Uzanti':<10}: {ext}")

    if ext in scan_list:
        log.info(f"  └─ {'Karar':<10}: SCAN  (uzanti taranacaklar listesinde)")
        return "scan"
    if ext in bypass_list:
        log.info(f"  └─ {'Karar':<10}: BYPASS  (uzanti guvenli listesinde)")
        return "bypass"

    default = config.get("default_action_for_unknown_extension", "scan")
    log.info(f"  └─ {'Karar':<10}: {default.upper()}  (uzanti hicbir listede yok, varsayilan uygulandi)")
    return default


def wait_until_stable(path: Path, interval: int, retries: int) -> bool:
    """
    Dosya hala yaziliyor/kopyalaniyor olabilir (curl, Finder drag-drop vb.).
    Boyutu art arda 'retries' kere ayni kalana kadar bekler.
    Basarili olursa True, dosya bu sirada silinir/tasinirsa False doner.
    """
    last_size = -1
    stable_count = 0
    while stable_count < retries:
        if not path.exists():
            return False
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        if size == last_size:
            stable_count += 1
        else:
            stable_count = 0
            last_size = size
        time.sleep(interval)
    return True


def extract_suggested_threat_label(attrs: dict) -> str:
    """
    VirusTotal alanı:
      attributes.popular_threat_classification.suggested_threat_label
    """
    return (
        (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        or "Bilinmiyor"
    )


def write_json_report(
    file_name: str,
    file_hash: str,
    endpoints_used: list,
    malicious: int,
    undetected: int,
    total: int,
    detected_by: list,
    threat_label: str,
) -> Path:
    """Tarama sonucunu sade bir JSON rapor olarak reports/ altina yazar."""
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"{Path(file_name).stem}_{stamp}.json"

    data = {
        "file_name": file_name,
        "hash": file_hash,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "api_endpoints_used": endpoints_used,
        "detected": malicious,
        "undetected": undetected,
        "total_engines": total,
        "detected_by": detected_by,
        "threat_label": threat_label,
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return report_path


def scan_file(path: Path, config: dict, hash_cache: dict, cache_path: Path):
    """
    Tarama akisi (her adim loglanir, dosyaya rapor yazilmaz - hepsi log'da):
      1. Hash hesapla
      2. Lokal cache/blacklist'te var mi bak -> varsa VT'ye gitmeden sonucu kullan
      3. Yoksa VT'ye sor (GET), bulamazsa dosyayi yukle (POST) ve analizi bekle
      4. Sonucu logla, JSON rapor yaz (hangi antivirusler tespit etti dahil), cache'i guncelle

    Donus: (malicious, threat_label) ikilisi.
    Tarama basarisiz olursa (None, None).
    Karantinaya alma karari burada VERILMEZ, sonucu kullanan tarafa birakilir.
    """
    log.info(f"Tarama basladi -> {path.name}")

    if not API_KEY:
        log.error("  ✗ VT_API_KEY bulunamadi (.env dosyasini kontrol et). Tarama iptal.")
        return None, None

    endpoints_used = []

    try:
        log.info("  ├─ [1/3] hash hesaplaniyor (SHA256)")
        file_hash = sha256_of_file(path)
        log.info(f"  │        {file_hash}")

        log.info("  ├─ [2/3] cache/blacklist kontrol ediliyor")
        cached = hash_cache.get(file_hash)

        if cached:
            log.info(f"  │        HIT -> daha once kontrol edilmis ({cached['checked_at']}), VT'ye gidilmedi")
            malicious = cached["malicious"]
            undetected = cached["undetected"]
            total = cached["total"]
            threat_label = cached.get("threat_label", "Bilinmiyor")

            if malicious > 0:
                log.warning(f"  └─ SONUC: {malicious}/{total} DETECTED  |  {undetected}/{total} UNDETECTED  (cache'ten)")
            else:
                log.info(f"  └─ SONUC: 0/{total} DETECTED  |  {undetected}/{total} UNDETECTED  (temiz, cache'ten)")
            log.info("     rapor: yazilmadi (sonuc cache'ten geldi, VT'ye tekrar sorulmadi)")
            return malicious, threat_label

        log.info("  │        MISS -> VT'ye sorulacak")
        log.info(f"  ├─ [3/3] istek atildi -> GET {BASE_URL}/files/{{hash}}")
        endpoints_used.append("GET /files/{hash}")
        report = get_report_by_hash(file_hash)

        if report:
            log.info("  │        yanit alindi -> hash VT'de kayitli, sonuc kullanilacak")
        else:
            log.info("  │        yanit alindi -> hash VT'de yok, dosya yuklenecek")
            log.info(f"  │        istek atildi -> POST {BASE_URL}/files (upload)")
            endpoints_used.append("POST /files")
            analysis_id = upload_file(path)
            log.info(f"  │        yanit alindi -> yuklendi (id={analysis_id}), analiz bekleniyor")
            poll_analysis(
                analysis_id,
                interval=config.get("poll_interval_seconds", 10),
                timeout=config.get("poll_timeout_seconds", 180),
            )
            endpoints_used.append("GET /analyses/{id}")
            report = get_report_by_hash(file_hash)
            log.info("  │        yanit alindi -> analiz tamamlandi")

        attrs = report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or attrs.get("stats", {})
        malicious = stats.get("malicious", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values()) if stats else 0

        # Hangi antivirusler zararli isaretledi (sadece isimler, sade tutmak icin)
        results = attrs.get("last_analysis_results") or attrs.get("results", {})
        detected_by = [
            engine for engine, result in results.items()
            if result.get("category") == "malicious"
        ]

        # Zararlı türü: attributes.popular_threat_classification.suggested_threat_label
        threat_label = extract_suggested_threat_label(attrs)

        # Cache'e yaz (bir sonraki ayni-hash icin VT'ye gitmeye gerek kalmasin)
        hash_cache[file_hash] = {
            "malicious": malicious,
            "undetected": undetected,
            "total": total,
            "file_name": path.name,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_label": threat_label,
        }
        save_hash_cache(cache_path, hash_cache)

        if malicious > 0:
            log.warning(f"  └─ SONUC: {malicious}/{total} DETECTED  |  {undetected}/{total} UNDETECTED")
        else:
            log.info(f"  └─ SONUC: 0/{total} DETECTED  |  {undetected}/{total} UNDETECTED  (temiz)")

        report_path = write_json_report(
            path.name, file_hash, endpoints_used, malicious, undetected, total, detected_by, threat_label
        )
        log.info(f"     rapor: {report_path.name}")

        return malicious, threat_label

    except Exception as e:
        log.error(f"  └─ ✗ Tarama basarisiz ({path.name}): {e}")
        return None, None


class WatchHandler(FileSystemEventHandler):
    def __init__(self, config: dict, watch_folder: Path, hash_cache: dict, cache_path: Path,
                 detected_threats: list, scan_stats: dict, license_manager=None,
                 processed_state: dict = None, processed_state_path: Path = None):
        self.config = config
        self.watch_folder = watch_folder
        self.hash_cache = hash_cache
        self.cache_path = cache_path
        self.detected_threats = detected_threats  # SADECE zararli cikanlar (mail tablosu icin)
        self.scan_stats = scan_stats  # taranan TUM dosya sayisi
        self.license_manager = license_manager 
        self.quarantine_dir = watch_folder / "karantina"
        self.quarantine_dir.mkdir(exist_ok=True)
        self.processed_state = processed_state if processed_state is not None else {}
        self.processed_state_path = processed_state_path

        self.interval = config.get("stability_check_interval_seconds", 2)
        self.retries = config.get("stability_check_retries", 5)

    def _mark_processed(self, path: Path):
        """
        Dosya klasorde oldugu yerde kaldiginda (temiz cikti ya da bypass
        edildi) bunu processed_files.json'a kaydeder - boylece bir sonraki
        baslangic taramasi ayni degismemis dosyayi tekrar islemez. Dosya
        daha sonra degistirilirse (boyut/mtime farklilasirsa) yine yeni
        dosya gibi ele alinir.
        """
        if self.processed_state_path is None:
            return
        try:
            st = path.stat()
        except OSError:
            return
        self.processed_state[path.name] = {"size": st.st_size, "mtime": st.st_mtime}
        try:
            save_processed_state(self.processed_state_path, self.processed_state)
        except OSError as e:
            log.error(f"  · processed_files.json diske yazilamadi: {e}")

    def _is_relevant(self, path: Path) -> bool:
        # karantina/ alt klasorundeki hareketleri yoksay (yoksa sonsuz dongu olur)
        if self.quarantine_dir in path.parents:
            return False
        if not path.is_file():
            return False
        return True

    def _handle(self, path: Path):
        """
        DIKKAT: Bu metod watchdog'un arka plandaki observer/dispatch
        thread'i tarafindan cagrilir. Icinde yakalanmamis bir exception
        firlarsa o thread SESSIZCE olebilir - servis "calisiyor" gibi
        gorunmeye devam eder (ana dongu etkilenmez) ama bir DAHA HICBIR
        yeni dosya olayi (on_created/on_moved) islenmez, sanki servis
        yeni dosyalari "gormezden geliyormus" gibi bir izlenim verir.
        Bu yuzden asagidaki TUM isleme mantigi genis bir try/except ile
        sarilidir - beklenmeyen HERHANGI bir hata sadece loglanir,
        thread'i asla oldurmez, servis bir sonraki dosyayi normal
        sekilde islemeye devam eder.
        """
        if not self._is_relevant(path):
            return
        try:
            self._handle_inner(path)
        except Exception as e:
            log.error(f"  └─ ✗ Dosya islenirken beklenmeyen hata olustu ({path.name}): {e}")
            log.error(f"  └─ ✗ Hata detayi (traceback): {traceback.format_exc(limit=3)}")
        finally:
            log.info("─" * 60)

    def _handle_inner(self, path: Path):
        log.info(f"YENI DOSYA  : {path.name}")
        if not wait_until_stable(path, self.interval, self.retries):
            log.warning(f"  ✗ Dosya kayboldu/tasindi, atlaniyor: {path.name}")
            return
        log.info(f"  ├─ boyut sabitlendi: {path.stat().st_size} byte")

        action = decide_action(path, self.config)

        if action == "scan":
            if self.license_manager and not self.license_manager.is_active():
                print("License not found")
                log.error(f"  └─ ✗ License not found - tarama iptal edildi: {path.name}")
                return
            malicious, threat_label = scan_file(path, self.config, self.hash_cache, self.cache_path)
            self.scan_stats["total_scanned"] += 1

            if malicious is None:
                log.warning(f"  └─ tarama basarisiz oldu, dosya oldugu yerde birakildi: {path.name}")

            elif malicious > 0:
                dest = self.quarantine_dir / path.name
                # Once tehdit listesine ekle (mail tablosu icin - konum karantina sonrasi hali)
                self.detected_threats.append({
                    "file_name": path.name,
                    "location": str(dest.resolve()),
                    "threat_label": threat_label,
                })
                try:
                    shutil.move(str(path), str(dest))
                    log.warning(f"  └─ ZARARLI bulundu ({threat_label}) -> karantinaya alindi: karantina/{path.name}")
                except Exception as e:
                    log.error(f"  └─ ✗ karantina klasorune tasinamadi: {e}")

                server_url = self.config.get("central_server_url")
                if server_url:
                    report_threat(
                        server_url, CLIENT_IDENTITY, threat_label,
                        path.name, str(dest.resolve()), base_dir=BASE_DIR, log=log,
                    )
            else:
                log.info(f"  └─ temiz bulundu, dosya oldugu yerde kaldi: {path.name}")
                self._mark_processed(path)
        else:
            # Guvenli dosya - klasorunde oldugu yerde kalir, hicbir yere tasinmaz.
            log.info(f"  └─ guvenli turu ('{path.suffix}', orn. Word/PDF/resim) -> tarama atlandi, dosya oldugu yerde kaldi")
            self._mark_processed(path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle(Path(event.src_path))

    def on_moved(self, event):
        # Finder'da surukle-birak genelde 'moved' event'i olarak gelir
        if not event.is_directory:
            self._handle(Path(event.dest_path))


def _scan_existing_files(handler: "WatchHandler", watch_folder: Path, processed_state: dict):
    """
    ONEMLI: watchdog'un Observer'i SADECE observer.start() cagrisindan
    SONRA olusan dosya sistemi olaylarini (on_created/on_moved) yakalar.
    Servis kapaliyken (ya da bir onceki calistirmada kapatilirken/Ctrl+C
    ile durdurulurken) klasore birakilmis dosyalar icin HICBIR olay
    tetiklenmez - bu yuzden bu dosyalar sessizce "atlanmis" gibi kalirdi.

    Bu fonksiyon servis her baslatildiginda watch_folder'daki mevcut
    dosyalari (karantina/ alt klasoru haric) listeler. TEMIZ/BYPASS
    edilmis ve daha once islendigi processed_files.json'da kayitli olan
    (boyut+mtime degismemis) dosyalar TEKRAR islenmez - aksi halde her
    servis yeniden baslatildiginda ayni degismemis dosyalar sonsuza dek
    "yeni dosya" gibi tekrar tekrar taranir/loglanirdi. Sadece GERCEKTEN
    yeni olan (ya da daha once basarisiz/lisanssiz kaldigi icin kaydi
    olmayan) dosyalar islenir.
    """
    try:
        existing = sorted(p for p in watch_folder.iterdir() if p.is_file())
    except OSError as e:
        log.error(f"✗ Baslangic taramasi icin klasor listelenemedi: {e}")
        return

    if not existing:
        log.info("Baslangic taramasi: klasorde bekleyen dosya bulunamadi")
        return

    pending = []
    skipped = 0
    for path in existing:
        try:
            st = path.stat()
        except OSError:
            continue
        recorded = processed_state.get(path.name)
        if recorded and recorded.get("size") == st.st_size and recorded.get("mtime") == st.st_mtime:
            skipped += 1
            continue
        pending.append(path)

    if skipped:
        log.info(f"Baslangic taramasi: {skipped} dosya daha once islendigi ve degismedigi icin atlandi")

    if not pending:
        log.info("Baslangic taramasi: yeni/degismis dosya bulunamadi")
        return

    log.info("─" * 60)
    log.info(f"BASLANGIC TARAMASI: {len(pending)} bekleyen dosya bulundu "
              f"(servis kapaliyken/kapatilirken birakilmis olabilir)")
    for path in pending:
        handler._handle(path)
    log.info(f"BASLANGIC TARAMASI TAMAMLANDI ({len(pending)} dosya islendi)")
    log.info("─" * 60)


def main():
    log.info("╔" + "═" * 58 + "╗")
    log.info("║{:^58}║".format("SentinEL ENDPOINT SECURITY"))
    log.info("╚" + "═" * 58 + "╝")

    config = load_config()

    # Rapor e-postasinin alici adresi hala "ornek" degeriyle birakilmis mi
    # diye erkenden kontrol et - aksi halde SMTP sunucusu mesaji "kabul
    # edildi" der (log "basariyla iletildi" gosterir), ama alici gercekte
    # yoktur ve teslimat SAATLER SONRA, sessizce (script'in goremeyecegi
    # bir "iade/bounce" maili olarak) basarisiz olur.
    recipient = config.get("report_recipient_email", "")
    _PLACEHOLDER_RECIPIENTS = {"ornek_mail@gmail.com", "example@example.com", ""}
    if recipient in _PLACEHOLDER_RECIPIENTS:
        log.warning(
            f"config.json -> report_recipient_email HALA ORNEK/BOS DEGER ('{recipient}'). "
            "Rapor e-postalari SMTP sunucusu tarafindan 'kabul edildi' gorunecek ama "
            "gercek alici olmadigi icin teslim edilmeyecek (iade maili saatler sonra gelir, "
            "bu servis onu goremez). Lutfen gercek bir adresle degistirin."
        )

    watch_folder_value = config["watch_folder"]
    watch_folder = Path(watch_folder_value)
    if not watch_folder.is_absolute():
        watch_folder = BASE_DIR / watch_folder
    watch_folder.mkdir(exist_ok=True)

    cache_value = config.get("hash_cache_file", "hash_cache.json")
    cache_path = Path(cache_value)
    if not cache_path.is_absolute():
        cache_path = BASE_DIR / cache_path
    hash_cache = load_hash_cache(cache_path)

    processed_state_path = BASE_DIR / "processed_files.json"
    processed_state = load_processed_state(processed_state_path)

    connected = check_vt_connection()
    if not connected:
        log.error("✗ VirusTotal'a baglanilamadi. .env / internet baglantisini kontrol edip tekrar dene.")
        sys.exit(1)

    log.info("─" * 60)
    log.info(f"  {'Klasor':<16}: {watch_folder.resolve()}")
    log.info(f"  {'Taranacak':<16}: {len(config['scan_extensions'])} uzanti  ({', '.join(config['scan_extensions'][:6])}, ...)")
    log.info(f"  {'Guvenli/bypass':<16}: {len(config['bypass_extensions'])} uzanti  ({', '.join(config['bypass_extensions'][:6])}, ...)")
    log.info(f"  {'Hash cache':<16}: {len(hash_cache)} kayit")
    log.info(f"  {'Islenmis dosya':<16}: {len(processed_state)} kayit (processed_files.json)")
    log.info(f"  {'Poll araligi':<16}: {config.get('poll_interval_seconds', 10)}sn")

    license_manager = None
    server_url = config.get("central_server_url")
    if server_url:
        start_heartbeat_thread(server_url, CLIENT_IDENTITY, base_dir=BASE_DIR, log=log)
        log.info(f"  {'Merkezi sunucu':<16}: {server_url}  (client: {CLIENT_IDENTITY['hostname']})")

        license_manager = LicenseManager(
            BASE_DIR, server_url, CLIENT_IDENTITY,
            refresh_minutes=config.get("license_check_interval_minutes", 60),
            grace_period_hours=config.get("license_grace_period_hours", 12),
            log=log,
        )
        # Başlangıçta senkron bir kontrol - servis "hazır" demeden önce
        # lisans durumu netleşsin (ama servis lisanssızsa bile ÇÖKMEZ,
        # sadece tarama devre dışı kalır - heartbeat/report akışı etkilenmez).
        if license_manager.validate_now():
            log.info(f"  {'Lisans':<16}: AKTİF")
        else:
            log.error(f"  {'Lisans':<16}: BULUNAMADI/GEÇERSİZ - tarama devre dışı, düzeltilene kadar bekleniyor")
        license_manager.start_refresh_thread()

    log.info("─" * 60)
    log.info("Servis hazir, klasor izleniyor.")
    log.info("─" * 60)

    detected_threats = []  # SADECE zararli cikan dosyalar (mail tablosu icin)
    scan_stats = {"total_scanned": 0}  # taranan TUM dosya sayisi (temiz+zararli)
    handler = WatchHandler(
        config, watch_folder, hash_cache, cache_path, detected_threats, scan_stats,
        license_manager=license_manager,
        processed_state=processed_state, processed_state_path=processed_state_path,
    )

    # Observer arka planda izlemeyi baslatiyor:
    observer = Observer()
    observer.schedule(handler, str(watch_folder), recursive=False)
    observer.start()

    # Observer sadece BUNDAN SONRAKI olaylari yakalar - klasorde onceden
    # birakilmis, henuz islenmemis (ya da degismis) dosyalar varsa simdi
    # onlari isle. Daha once islenip degismeden kalan dosyalar atlanir.
    _scan_existing_files(handler, watch_folder, processed_state)

    # Iki ayri sayacimiz ve suremiz var:
    report_interval = config.get("report_interval_seconds", 300)
    heartbeat_interval = config.get("heartbeat_interval_seconds", 300)

    elapsed_since_report = 0
    elapsed_since_heartbeat = 0
    report_period_start = time.strftime("%H:%M")

    try:
        while True:
            time.sleep(1)
            elapsed_since_report += 1
            elapsed_since_heartbeat += 1

            # 1. HEARTBEAT KONTROLU
            if elapsed_since_heartbeat >= heartbeat_interval:
                log.info("· sistem sorunsuz calisiyor  (izleme aktif, bekleyen dosya yok)")
                elapsed_since_heartbeat = 0

            # 2. E-POSTA RAPORLAMA KONTROLU
            if elapsed_since_report >= report_interval:
                report_period_end = time.strftime("%H:%M")

                if scan_stats["total_scanned"] == 0:
                    log.info("· Rapor periyodu doldu, bu aralikta hic tarama yapilmadi. E-posta atlaniyor.")
                elif not detected_threats:
                    log.info(
                        f"· Rapor periyodu doldu. {scan_stats['total_scanned']} dosya tarandi, "
                        f"hicbiri zararli cikmadi. E-posta atlaniyor."
                    )
                else:
                    log.info(
                        f"· Rapor periyodu doldu. {len(detected_threats)} zararli tespit "
                        f"({scan_stats['total_scanned']} dosya tarandi), e-posta gonderiliyor..."
                    )

                    try:
                        meta_info = {
                            "computer_name": get_computer_name(),
                            "user": get_active_user(),
                            "system_uptime": get_system_uptime(),
                            "service_uptime": format_duration(time.time() - SERVICE_START_TIME),
                            "os_version": get_macos_version(),
                            "report_range": f"{report_period_start} - {report_period_end}",
                            "total_scanned": scan_stats["total_scanned"],
                        }

                        pdf_name = f"SentinEL_Raporu_{time.strftime('%Y%m%d_%H%M')}.pdf"
                        pdf_path = BASE_DIR / "reports" / pdf_name
                        build_pdf_report(detected_threats, meta_info, pdf_path)

                        subject = f"SentinEL Guvenlik Raporu - {meta_info['computer_name']}"
                        success = send_email_with_attachment(pdf_path, subject, config)

                        if success:
                            log.info(
                                f"  └─ E-posta SMTP sunucusuna teslim edildi (sunucu 'kabul edildi' yaniti verdi): {pdf_name}"
                            )
                            log.info(
                                "     · NOT: bu, mesajin nihai olarak alicinin kutusuna ULASTIGI anlamina GELMEZ - "
                                "adres hatali/yoksa iade (bounce) bildirimi SAATLER SONRA, ayri bir e-posta olarak "
                                "gelir ve bu servis tarafindan izlenmez. Alici adresini ve gelen kutusunu kontrol edin."
                            )
                            detected_threats.clear()
                            scan_stats["total_scanned"] = 0
                        else:
                            log.error(
                                "  └─ ✗ E-posta GONDERILEMEDI (.env / SMTP ayarlarini kontrol et). "
                                "Veriler korunuyor, bir sonraki periyotta tekrar denenecek."
                            )
                    except Exception as e:
                        # PDF uretimi ya da mail gonderimi ne sebeple olursa olsun patlarsa
                        # servis COKMESIN - sadece logla, bir sonraki periyotta tekrar dene.
                        log.error(f"  └─ ✗ Rapor uretme/gonderme sirasinda beklenmeyen hata: {e}")

                elapsed_since_report = 0
                report_period_start = report_period_end

    except KeyboardInterrupt:
        log.info("─" * 60)
        log.info("Servis durduruluyor...")
    observer.stop()
    observer.join()


if __name__ == "__main__":
    main()