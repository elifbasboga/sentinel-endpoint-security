#!/usr/bin/env python3
"""
license_admin.py
-----------------
Sunucu tarafinda lisans kaydi olusturmak/iptal etmek/listelemek icin basit
bir komut satiri araci. Sunucu (server.py) CALISIRKEN de calismiyorken de
kullanilabilir - dogrudan licenses.json'a yazar (server.py de ayni dosyayi
LicenseService uzerinden okur).

Kullanim:
    # Yeni lisans ver (client_id, client_id.json dosyasindan / dashboard'dan alinir)
    python3 license_admin.py issue --client-id "<base64...>" --hostname Client1 --plan pro --days 365

    # Iptal et
    python3 license_admin.py revoke --client-id "<base64...>"

    # Tum lisanslari listele
    python3 license_admin.py list
"""

import argparse
from pathlib import Path

from license_service import LicenseService

BASE_DIR = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="SentinEL lisans yonetim araci")
    sub = parser.add_subparsers(dest="command", required=True)

    p_issue = sub.add_parser("issue", help="Yeni lisans ver / mevcut olani guncelle")
    p_issue.add_argument("--client-id", required=True)
    p_issue.add_argument("--hostname", required=True)
    p_issue.add_argument("--plan", default="standard")
    p_issue.add_argument("--days", type=int, default=365)

    p_revoke = sub.add_parser("revoke", help="Lisansi iptal et")
    p_revoke.add_argument("--client-id", required=True)

    sub.add_parser("list", help="Tum lisanslari listele")

    args = parser.parse_args()
    service = LicenseService(BASE_DIR)

    if args.command == "issue":
        record = service.issue(args.client_id, args.hostname, args.plan, args.days)
        print(f"✓ Lisans verildi: {args.hostname} ({args.client_id[:16]}...)")
        print(f"  plan={record['plan']}  bitis={record['expires_at']}")

    elif args.command == "revoke":
        ok = service.revoke(args.client_id)
        print("✓ Lisans iptal edildi." if ok else "✗ Bu client_id icin kayit bulunamadi.")

    elif args.command == "list":
        rows = service.status_for_dashboard()
        if not rows:
            print("Hic lisans kaydi yok.")
        for r in rows:
            print(f"{r['hostname']:<15} {r['status']:<10} plan={r['plan']:<10} "
                  f"bitis={r['expires_at']}  kalan_gun={r['days_remaining']}")


if __name__ == "__main__":
    main()
