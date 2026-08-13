#!/usr/bin/env python3
"""
generate_license_key.py
------------------------
Sunucu ve butun client'larin ORTAK kullandigi Fernet sifreleme anahtarini
BIR KERE uretir ve sentinEL/assets/license.key dosyasina yazar. Bu dosya
zaten hepsinin erisebildigi ortak assets/ klasorunde oldugu icin, artik
her .env'e elle kopyalamaya gerek yok - license_manager.py ve
license_service.py otomatik olarak buradan okuyor.

Kullanim (sentinEL/ kok dizininden, ya da herhangi bir Client/Server
alt klasorunden - script kendi konumuna gore assets/'i bulur):

    python3 generate_license_key.py

Dosya zaten varsa UZERINE YAZMAZ (mevcut lisanslarin bozulmamasi icin) -
yeniden uretmek istiyorsan once dosyayi elle sil.
"""

from pathlib import Path
from cryptography.fernet import Fernet

# Bu script sentinEL/assets/ icine konursa: parent = sentinEL/
# Bir alt klasore (Server/, Client1/ vb.) konursa da calissin diye,
# once yaninda assets/ var mi bak, yoksa bir ust dizinde ara.
def _find_or_create_assets_dir() -> Path:
    here = Path(__file__).resolve().parent
    candidate = here / "assets"
    if candidate.is_dir():
        return candidate
    candidate = here.parent / "assets"
    if candidate.is_dir():
        return candidate
    # Hicbiri yoksa, sentinEL kok dizini varsayimiyla burada olustur
    fallback = here.parent / "assets"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def main():
    assets_dir = _find_or_create_assets_dir()
    key_path = assets_dir / "license.key"

    if key_path.exists():
        print(f"✗ {key_path} zaten var, uzerine yazilmadi.")
        print("  Yeniden uretmek istiyorsan once bu dosyayi elle sil.")
        return

    key = Fernet.generate_key().decode("ascii")
    key_path.write_text(key, encoding="utf-8")
    print(f"✓ Yeni anahtar uretildi: {key_path}")
    print("  Sunucu ve tum Client'lar bu dosyayi otomatik okuyacak (baska bir sey yapmana gerek yok).")


if __name__ == "__main__":
    main()