# SentinEL Endpoint Security

SentinEL, yerel ağlardaki uç noktaları (endpoint) gerçek zamanlı izleyen, dosya sistemindeki hareketleri analiz eden ve olası tehditleri VirusTotal API aracılığıyla tespit edip izole eden merkezi bir güvenlik mimarisidir.

Çoklu istemci (multi-client) yapısını destekleyen bu sistem, uç noktalardan gelen verileri canlı bir Security Operations Center (SOC) web panelinde toplar.

## 🚀 Temel Özellikler

- **Gerçek Zamanlı Dosya İzleme:** Belirlenen dizinlerde oluşturulan veya taşınan dosyaları anlık olarak yakalar.
- **Akıllı Tarama (Hash Caching):** Aynı dosyanın tekrar tekrar analiz edilmesini önlemek ve API kotalarını korumak için yerel bir SHA256 önbelleği kullanır.
- **Otomatik Karantina:** Tespit edilen zararlı yazılımları anında güvenli bir karantina dizinine taşır.
- **Merkezi SOC Paneli:** İstemcilerin aktif/pasif durumlarını (heartbeat) ve ağdaki genel tehdit haritasını 5 saniyede bir güncellenen web arayüzünde sunar.
- **Otomatik Yönetici Raporları:** Sistem metriklerini ve tespit edilen tehditleri derleyerek periyodik olarak PDF formatında e-posta ile gönderir.

## 🛠️ Kullanılan Teknolojiler

- **Dil:** Python 3
- **Backend & API:** FastAPI, Uvicorn, Requests
- **Sistem Gözlemi:** Watchdog
- **Raporlama:** ReportLab, smtplib
- **Tehdit İstihbaratı:** VirusTotal API v3

## ⚙️ Kurulum ve Çalıştırma

Projeyi macOS ortamında yerel olarak çalıştırmak için aşağıdaki adımları izleyebilirsiniz.

### 1. Depoyu Klonlayın

```bash
git clone https://github.com/elifbasboga/sentinel-endpoint-security.git
cd sentinel-endpoint-security
```

### 2. Gerekli Kütüphaneleri Yükleyin

```bash
pip3 install fastapi uvicorn requests watchdog reportlab python-dotenv
```

### 3. Çevre Değişkenlerini Ayarlayın

Proje ana dizininde `.env` dosyası oluşturun ve gerekli bilgileri girin:

```env
VT_API_KEY=senin_virustotal_api_anahtarin
SMTP_EMAIL=gonderici_mail@gmail.com
SMTP_APP_PASSWORD=gmail_uygulama_sifresi
```

> **Not:** `.env` dosyanızı GitHub'a yüklemeyin. API anahtarları ve uygulama şifreleri gibi hassas bilgileri güvenli tutun.

### 4. Sistemi Başlatın

Önce merkezi sunucuyu ayağa kaldırın:

```bash
python3 server.py
```

Ardından yeni bir terminal sekmesinde istemciyi başlatın:

```bash
python3 watcher.py
```

Merkezi güvenlik paneline erişmek için tarayıcınızda aşağıdaki adresi açabilirsiniz:

```text
http://localhost:8000
```

## 🏗️ Sistem Mimarisi

SentinEL, merkezi sunucu ve birden fazla istemciden oluşan bir mimariye sahiptir.

```text
┌─────────────────────┐
│   Endpoint Client   │
│     watcher.py      │
└──────────┬──────────┘
           │
           │ Threat Reports
           │ + Heartbeat
           ▼
┌─────────────────────┐
│   FastAPI Server    │
│     server.py       │
└──────────┬──────────┘
           │
           ├──────────────► SOC Dashboard
           │
           └──────────────► Threat Monitoring
           
        ┌─────────────────────┐
        │    VirusTotal API   │
        │    Threat Intel.    │
        └─────────────────────┘
```

### İstemci (Endpoint)

İstemci tarafındaki `watcher.py` dosyası:

- Dosya sistemi hareketlerini izler.
- Yeni veya taşınan dosyaları tespit eder.
- Dosyaların SHA256 hash değerlerini oluşturur.
- VirusTotal API üzerinden tehdit analizi gerçekleştirir.
- Zararlı dosyaları karantinaya alır.
- Tehdit raporlarını merkezi sunucuya gönderir.
- Sunucuyla iletişimini heartbeat mekanizmasıyla sürdürür.

### Sunucu (Server)

Sunucu tarafındaki `server.py` dosyası:

- İstemcilerden gelen bağlantıları yönetir.
- Aktif istemcileri heartbeat bilgileriyle takip eder.
- Tehdit raporlarını merkezi olarak toplar.
- İstemci ve tehdit durumlarını izler.
- SOC dashboard üzerinden gerçek zamanlı güvenlik verilerini sunar.

## 📊 SOC Dashboard

Merkezi dashboard üzerinden aşağıdaki bilgiler izlenebilir:

- Aktif istemci sayısı
- Pasif istemci sayısı
- Tespit edilen toplam tehdit sayısı
- Son tespit edilen tehditler
- İstemci bazlı güvenlik durumu
- Tehdit türleri
- Gerçek zamanlı sistem durumu

Dashboard verileri belirli aralıklarla güncellenerek güncel güvenlik durumunun takip edilmesini sağlar.

## 🔐 Güvenlik

SentinEL aşağıdaki güvenlik mekanizmalarını kullanır:

- SHA256 tabanlı dosya kimliklendirme
- Hash caching
- VirusTotal tabanlı tehdit istihbaratı
- Otomatik karantina
- Heartbeat tabanlı istemci takibi
- Çevre değişkenleri üzerinden hassas bilgilerin yönetimi

> **Önemli:** API anahtarları, SMTP şifreleri ve diğer hassas bilgileri kaynak kodu içerisinde doğrudan saklamayın.

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır.

Copyright (c) 2026 Dilan Elif Başboğa
