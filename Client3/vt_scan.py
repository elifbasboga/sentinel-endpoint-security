#!/usr/bin/env python3
"""
vt_scan.py
----------
curl ile indirilen bir dosyayı VirusTotal API v3 üzerinden tarar ve
JSON + okunabilir metin (txt) rapor üretir.

Kullanım:
    # 1) Dosyayı curl ile indir (terminalde ayrı bir adım)
    curl -L -o supheli_dosya.exe "https://ornek-site.com/dosya.exe"

    # 2) Bu scripti çalıştır
    python vt_scan.py supheli_dosya.exe

Çıktılar:
    reports/<dosya_adi>_<tarih>.json   -> ham API cevabı
    reports/<dosya_adi>_<tarih>.txt    -> özet rapor
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

try:
    import importlib.util

    if importlib.util.find_spec("dotenv") is not None:
        from dotenv import load_dotenv
    else:
        def load_dotenv(*args, **kwargs):
            return False
except Exception:
    def load_dotenv(*args, **kwargs):
        return False

# Script'in bulunduğu klasor - .env, reports/ vb. hep buna gore bulunur,
# calistigin yer (terminal / VS Code Run butonu / farkli klasor) fark etmez.
# PyInstaller ile derlenmis halde calisiyorsak (--onefile), __file__ gecici
# bir cikartma klasorunu (_MEIxxxx) gosterir; bu durumda gercek .exe/binary
# dosyasinin bulundugu klasoru (sys.executable) kullanmamiz gerekir.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

load_dotenv(dotenv_path=BASE_DIR / ".env")

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
REPORTS_DIR = BASE_DIR / "reports"

# Dosya 32MB'tan büyükse VT'nin ayrı "büyük dosya" upload URL'i gerekir.
LARGE_FILE_THRESHOLD = 32 * 1024 * 1024


def sha256_of_file(path: Path) -> str:
    """Dosyanın SHA256 hash'ini hesaplar (dosyayı parça parça okuyarak)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_report_by_hash(file_hash: str) -> dict | None:
    """Hash daha önce VT'ye yüklenmişse mevcut raporu döner, yoksa None."""
    headers = {"x-apikey": API_KEY}
    resp = requests.get(f"{BASE_URL}/files/{file_hash}", headers=headers)
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        return None
    resp.raise_for_status()


def upload_file(path: Path) -> str:
    """Dosyayı VT'ye yükler ve analysis_id döner."""
    headers = {"x-apikey": API_KEY}
    size = path.stat().st_size

    if size > LARGE_FILE_THRESHOLD:
        # Büyük dosyalar için önce özel upload URL'i istenir
        url_resp = requests.get(f"{BASE_URL}/files/upload_url", headers=headers)
        url_resp.raise_for_status()
        upload_url = url_resp.json()["data"]
    else:
        upload_url = f"{BASE_URL}/files"

    with open(path, "rb") as f:
        files = {"file": (path.name, f)}
        resp = requests.post(upload_url, headers=headers, files=files)
    resp.raise_for_status()
    return resp.json()["data"]["id"]  # analysis id


def get_remaining_quota(log=None) -> dict | None:
    """
    VirusTotal hesabinin gunluk/saatlik/aylik API istek kotasini sorgular.
    Donus: {"daily_used": int, "daily_allowed": int, "daily_remaining": int,
            "hourly_used": int, "hourly_allowed": int, "hourly_remaining": int}
    Basarisiz olursa None doner (servis akisini durdurmaz).
    """
    if not API_KEY:
        return None

    url = f"{BASE_URL}/users/{API_KEY}"
    if log:
        log.info(f"  ├─ istek atildi -> GET {url} (kota sorgusu)")

    try:
        headers = {"x-apikey": API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            if log:
                log.warning(f"  │        yanit alindi -> beklenmeyen durum kodu: HTTP {resp.status_code}, kota gosterilemiyor")
            return None

        quotas = resp.json().get("data", {}).get("attributes", {}).get("quotas", {})
        daily = quotas.get("api_requests_daily", {})
        hourly = quotas.get("api_requests_hourly", {})

        result = {
            "daily_used": daily.get("used", 0),
            "daily_allowed": daily.get("allowed", 0),
            "daily_remaining": max(daily.get("allowed", 0) - daily.get("used", 0), 0),
            "hourly_used": hourly.get("used", 0),
            "hourly_allowed": hourly.get("allowed", 0),
            "hourly_remaining": max(hourly.get("allowed", 0) - hourly.get("used", 0), 0),
        }

        if log:
            log.info(
                f"  └─ yanit alindi -> gunluk: {result['daily_used']}/{result['daily_allowed']} "
                f"kullanildi ({result['daily_remaining']} sorgu kaldi)  |  "
                f"saatlik: {result['hourly_used']}/{result['hourly_allowed']} "
                f"({result['hourly_remaining']} kaldi)"
            )
        return result

    except requests.exceptions.RequestException as e:
        if log:
            log.warning(f"  │        kota sorgusu basarisiz ({e.__class__.__name__}), atlaniyor")
        return None


def poll_analysis(analysis_id: str, interval: int = 15, timeout: int = 300) -> dict:
    """Analiz tamamlanana kadar belirli aralıklarla sonucu sorgular."""
    headers = {"x-apikey": API_KEY}
    elapsed = 0
    while elapsed < timeout:
        resp = requests.get(f"{BASE_URL}/analyses/{analysis_id}", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        status = data["data"]["attributes"]["status"]
        print(f"  Analiz durumu: {status} ({elapsed}s)")
        if status == "completed":
            return data
        time.sleep(interval)
        elapsed += interval
    raise TimeoutError("Analiz zaman aşımına uğradı, VT tarafında hala kuyrukta olabilir.")


def summarize(report: dict, file_hash: str, file_name: str) -> str:
    """Rapor verisinden okunabilir bir özet metni üretir."""
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or attrs.get("stats", {})
    results = attrs.get("last_analysis_results") or attrs.get("results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    lines = []
    lines.append("=" * 60)
    lines.append("VIRUSTOTAL TARAMA RAPORU")
    lines.append("=" * 60)
    lines.append(f"Dosya adi     : {file_name}")
    lines.append(f"SHA256        : {file_hash}")
    lines.append(f"Tarih         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("-" * 60)
    lines.append(f"Zararli tespit     : {malicious}/{total}")
    lines.append(f"Supheli tespit     : {suspicious}/{total}")
    lines.append(f"Temiz (harmless)   : {harmless}/{total}")
    lines.append(f"Tespit edilemedi   : {undetected}/{total}")
    lines.append("-" * 60)

    if malicious > 0 or suspicious > 0:
        lines.append("Zararli/supheli olarak isaretleyen motorlar:")
        for engine, result in results.items():
            category = result.get("category")
            if category in ("malicious", "suspicious"):
                verdict = result.get("result") or "belirtilmemis"
                lines.append(f"  - {engine}: {category} ({verdict})")
    else:
        lines.append("Hicbir motor bu dosyayi zararli/supheli olarak isaretlemedi.")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Dosyayi VirusTotal ile tarar ve rapor uretir.")
    parser.add_argument("dosya", help="Taranacak yerel dosyanin yolu (curl ile indirilen dosya)")
    parser.add_argument("--force-upload", action="store_true",
                         help="Hash VT'de bulunsa bile dosyayi yeniden yukle")
    args = parser.parse_args()

    if not API_KEY:
        print("HATA: VT_API_KEY bulunamadi. .env dosyasini olustur ve API keyini gir.")
        sys.exit(1)

    path = Path(args.dosya)
    if not path.exists():
        print(f"HATA: Dosya bulunamadi: {path}")
        sys.exit(1)

    print(f"[1/4] Hash hesaplaniyor: {path.name}")
    file_hash = sha256_of_file(path)
    print(f"      SHA256: {file_hash}")

    report = None
    if not args.force_upload:
        print("[2/4] VirusTotal'da mevcut rapor kontrol ediliyor...")
        report = get_report_by_hash(file_hash)

    if report:
        print("      Mevcut rapor bulundu, yeniden yuklemeye gerek yok.")
    else:
        print("[2/4] Rapor bulunamadi, dosya VT'ye yukleniyor...")
        analysis_id = upload_file(path)
        print(f"      Yuklendi. analysis_id: {analysis_id}")
        print("[3/4] Analiz sonucu bekleniyor...")
        poll_analysis(analysis_id)
        # Analiz bitince guncel dosya raporunu hash uzerinden cekiyoruz
        report = get_report_by_hash(file_hash)

    print("[4/4] Rapor olusturuluyor...")
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{path.stem}_{stamp}"

    json_path = REPORTS_DIR / f"{base_name}.json"
    txt_path = REPORTS_DIR / f"{base_name}.txt"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    summary = summarize(report, file_hash, path.name)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(summary)

    print("\n" + summary)
    print(f"\nJSON rapor : {json_path}")
    print(f"Ozet rapor : {txt_path}")


if __name__ == "__main__":
    main()