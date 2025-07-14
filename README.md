# 🚀 Lethas Toolkit v0.1

**Lethas Toolkit**, Python ile geliştirilmiş açık kaynaklı bir ağ analiz ve tanılama aracıdır.  
ARP izleme, DNS çözümleme, ping, traceroute ve IP tarama gibi işlemleri modern bir arayüz ile gerçekleştirmenizi sağlar.

---

## 🖥️ Özellikler

| Özellik             | Açıklama                                           |
|----------------------|----------------------------------------------------|
| 🔍 **IP Tarama**       | Belirli aralıkta ping ile canlı cihazları bulur, hız tahmini yapar |
| ⚡ **ARP İzleme**       | Ağdaki ARP paketlerini izler, IP-MAC eşleşmelerini listeler |
| 🧠 **Spoof Tespiti**    | Aynı IP için farklı MAC adresi tespit edilirse uyarı verir |
| 🌐 **DNS Lookup**      | Alan adını IP'ye veya IP'yi alan adına çözümler |
| 🛰️ **Traceroute**      | Ağ üzerindeki geçiş noktalarını listeler |
| 📊 **Hostname ve MAC Tespiti** | IP taramada cihaz adı ve MAC adresini gösterir |
| 🖼️ **Modern Arayüz**     | CustomTkinter ile tablı GUI tasarım |

---

## 📸 Ekran Görüntüsü

![Arayüz Görüntüsü](screenshots/Main.png)

---

## ⚙️ Kurulum

### 1. Gereksinimler
Python 3.10 veya 3.11 tavsiye edilir.

```bash
pip install -r requirements.txt
```

### 2. Uygulamayı Başlat
```bash
python main.py
```

---

## 🛠️ Derleme (Windows .exe yapmak için)

Aşağıdaki komutla tek tıklamalık bir `.exe` oluşturabilirsiniz:

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name LethasToolkit main.py
```

Çıktı: `dist/LethasToolkit.exe`

---

## 📁 Proje Yapısı

```
network-toolkit-fixed/
├── main.py
├── core/
│   ├── arp_monitor.py
│   └── port_scanner.py
├── gui/components/
│   ├── arp_tab.py
│   ├── scanner_tab.py
│   ├── test_tab.py
│   └── ip_scanner_tab.py
├── screenshots/
│   └── main.png
├── requirements.txt
└── README.md
```

---

## 🤝 Katkı ve Lisans

MIT lisansı ile açık kaynak.  
Katkı yapmak için fork edip pull request gönderebilirsiniz.

---

**Geliştirici:** [@lethas](https://github.com/mMobiusStrip)
