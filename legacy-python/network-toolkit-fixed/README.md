# 🚀 Lethas Toolkit v0.1

**NetMonToolkit** — Gelişmiş Python tabanlı ağ analiz aracı.  
Yerel ağlarda IP tarama, ARP dinleme, DNS çözümleme, ping ve traceroute gibi işlemleri GUI arayüzü üzerinden kolayca gerçekleştirmenizi sağlar.

---

## 🖥️ Özellikler

| Özellik             | Açıklama                                           |
|----------------------|----------------------------------------------------|
| 🔍 **IP Tarama**       | Ping ile cihazları bulur, hız tahmini yapar        |
| ⚡ **ARP İzleme**       | Gerçek zamanlı ARP paketlerini görüntüler          |
| 🧠 **Spoof Tespiti**    | Aynı IP için değişen MAC adreslerini uyarır        |
| 🌐 **DNS Lookup**      | IP'den cihaz ismi bulur veya tersi                |
| 🛰️ **Traceroute**      | Cihazın ağ yolunu ve gecikmeleri gösterir         |
| 📦 **GUI**             | CustomTkinter tabanlı modern arayüz               |

---

## 📸 Ekran Görüntüsü

![Arayüz Görüntüsü](screenshots/main.png)

---

## 🛠️ Kurulum

### 1. Gereksinimler
```bash
pip install -r requirements.txt
```

### 2. Çalıştır
```bash
python main.py
```

---

## 🔧 Derleme (opsiyonel)

Windows için `.exe` oluşturmak istersen:
```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name NetMonToolkit main.py
```

---

## 📂 Proje Yapısı

```
network-toolkit/
├── main.py
├── core/
│   ├── arp_monitor.py
│   └── port_scanner.py
├── gui/components/
│   ├── scanner_tab.py
│   ├── arp_tab.py
│   ├── test_tab.py
│   └── ip_scanner_tab.py
├── requirements.txt
└── README.md
```

---

## 🤝 Katkı ve Lisans

Bu proje bireysel öğrenme amaçlı geliştirilmiştir.  
Lisans: MIT  
Katkı sağlamak isteyenler pull request gönderebilir.

---

**Geliştirici:** [@lethas](https://github.com/)

