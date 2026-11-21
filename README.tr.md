# Meridian

**nmap** motorunun üzerinde çalışan canlı bir web arayüzü: tarama profilleri, radyal topoloji haritası, cihaz tablosu, risk puanı, bulunan yazılımlar için bilinen zafiyetler ve exploit'ler, tanımadığınız cihazları işaretleyen güvenilir cihaz listesi, farkları ve risk eğilimini gösteren tarama geçmişi, masaüstü bildirimli izleme modu, isteğe bağlı yapay zekâ analizi, markalı raporlar ve JSON / CSV / Markdown / HTML / PDF / Nmap-XML dışa aktarma. Yalnızca Python standart kütüphanesi, **pip bağımlılığı yok**. **Linux, macOS ve Windows**'ta, **English, Türkçe, Deutsch, Español ve Français** dilleriyle çalışır.

**[Canlı demo](https://aybiketutarr.github.io/meridian/)**: tamamen tarayıcınızda, örnek verilerle çalışır (tarama yapmaz).  ·  **[English README](README.md)**

> **Sorumlu kullanın.** Yalnızca sahibi olduğunuz veya test etmek için açık izniniz bulunan ağları tarayın.

## 0.5'te neler yeni

* **Tek tıkla kurulum:** Windows için `Meridian-Setup-<sürüm>.exe` (Python gerekmez), Debian, Ubuntu, Kali ve Mint için `meridian_<sürüm>_all.deb` (nmap birlikte kurulur). Terminal kurucuları duruyor ([Kurulum](#kurulum)).
* **Yapay zekâ analizi (isteğe bağlı, varsayılan olarak kapalı):** sade dille özet ve "önce bunu düzeltin" listesi. Ollama ve LM Studio (yerel) ya da Claude ve OpenAI (bulut) ile çalışır. IP, MAC veya cihaz adı asla gönderilmez ([ayrıntılar](#yapay-zekâ-analizi-isteğe-bağlı)).
* **Rapor markalama:** şirket veya ekip, müşteri, hazırlayan, gizlilik notu, vurgu rengi ve logo; HTML, PDF ve Markdown raporlarında görünür. Raporlar artık bir özetle başlar ve alt bilgiyle biter.
* **Yeni görünüm:** sol şeritli editoryal bir yerleşim, beş tema (Siyah, Beyaz, Mavi, Mor, Kor) ve her tema için güvenlik temalı bir arka plan. Yazı tipleri yereldir; internetten hiçbir şey yüklenmez.
* Windows ve macOS'ta **uygulama simgesi**, Windows'ta kendi görev çubuğu kimliği.

Önceki sürümler (diller, güvenilir cihazlar, çevrimdışı ipuçları, `meridian --doctor`, güvenlik sertleştirmeleri): [CHANGELOG](CHANGELOG.md).

## Kurulum

### Tek tıkla kurulum (Windows ve Linux)

Sisteminize uygun dosyayı [Releases sayfasından](https://github.com/aybiketutarr/meridian/releases) indirin. Windows'ta Python gerekmez.

| | Dosya | Nasıl |
|---|---|---|
| Windows 10/11 | `Meridian-Setup-<sürüm>.exe` | Çift tıklayın. Yönetici izni gerekmeden kullanıcınıza kurulur, Başlat Menüsü girişi ve isteğe bağlı masaüstü simgesi ekler. Dosya henüz imzalı olmadığı için Windows mavi bir **SmartScreen** sayfası gösterebilir: **Ek bilgi**, sonra **Yine de çalıştır** deyin. *Ayarlar > Uygulamalar* üzerinden kaldırılır. |
| Debian, Ubuntu, Kali, Mint | `meridian_<sürüm>_all.deb` | Çift tıklayın (yazılım merkezi açılır) ya da `sudo apt install ./meridian_<sürüm>_all.deb`. Kaldırmak için `sudo apt remove meridian`. nmap birlikte kurulur. |
| macOS | | Şimdilik yalnızca elle kurulum, aşağıya bakın. |

Gerçek taramalar için **nmap** gerekir. Linux paketi onu kurar; Windows kurulumu indirme sayfasını açmayı önerir. Taramalarınız, cihazlarınız ve ayarlarınız kendi klasörünüzde durur ve güncellemelerde korunur. Terminalle kurmayı sevenler için aşağıdaki kurulumlar da duruyor.

Geliştiriciler için: `python3 tools/build_deb.py` paketi üretir; `v0.5.1` gibi bir etiket gönderince GitHub iki dosyayı da kendisi derler (`.github/workflows/release.yml`).

### Elle kurulum (terminal)

**Python 3.10 veya yenisi** ve gerçek taramalar için **nmap** gerekir. Python paketi gerekmez. Her şey yalnızca kendi kullanıcınız için kurulur: root veya yönetici hakkı gerekmez. nmap olmadan da **Örnek veri** ile her şeyi deneyebilirsiniz.

| | Linux | macOS | Windows |
|---|---|---|---|
| nmap | `sudo apt install nmap` | `brew install nmap` | [nmap.org](https://nmap.org/download.html) kurucusu (Npcap dahil) |
| Kur | `python3 install.py` (veya `sh install.sh`) | `python3 install.py` | `install.bat` dosyasına çift tıklayın (veya `py install.py`) |
| Başlat | `meridian` | `meridian` veya Launchpad'den **Meridian** | `meridian` veya Başlat menüsünden **Meridian** |
| Tam LAN sonuçları | `sudo -E "$(command -v meridian)"` | `sudo -E meridian` | terminali **Yönetici olarak** açın, sonra `meridian` |
| Veri klasörü | `~/.local/share/meridian` | `~/Library/Application Support/Meridian` | `%LOCALAPPDATA%\Meridian` |
| Uygulama penceresi | Chromium / Chrome / Brave / Edge | Chrome / Edge / Brave / Chromium | Edge (hep vardır) / Chrome / Brave |

Chromium tabanlı bir tarayıcı yoksa Meridian varsayılan tarayıcınızı açar.

### Linux (adım adım)

Kali Linux'ta denendi; Debian ve Ubuntu'da da çalışır. **Normal kullanıcınızla** çalışın (root ile değil).

```sh
sudo apt update
sudo apt install -y git python3 nmap chromium      # chromium isteğe bağlı (uygulama penceresi); Ubuntu'da: chromium-browser
git clone https://github.com/aybiketutarr/meridian.git
cd meridian
python3 -m unittest discover -s tests              # isteğe bağlı; son satır OK demeli
python3 install.py                                  # 'meridian' komutunu ve menü girdisini kurar
meridian
```

`meridian` için "command not found" derse `~/.local/bin` klasörünü PATH'e bir kez ekleyin:
```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc    # bash kullanıyorsanız ~/.bashrc
source ~/.zshrc
```

### macOS

```sh
brew install nmap                  # Homebrew: https://brew.sh
git clone https://github.com/aybiketutarr/meridian.git && cd meridian
python3 install.py
meridian                           # veya Launchpad / Spotlight'tan Meridian'ı açın
```
`python3`, Xcode komut satırı araçlarıyla gelir ya da python.org'dan kurulur. Kurucu `~/Applications/Meridian.app` uygulamasını ve `~/.local/bin` içinde `meridian` komutunu oluşturur (kabuk bulamazsa o klasörü PATH'e ekleyin). ARP keşfi, işletim sistemi tespiti ve traceroute için `sudo -E meridian` ile başlatın.

### Windows

1. [python.org](https://www.python.org/downloads/) adresinden **Python 3.10+** (*Add python.exe to PATH* kutusunu işaretleyin) ve [nmap.org](https://nmap.org/download.html) adresinden **nmap** kurun.
2. Meridian'ı indirin veya klonlayın, sonra **`install.bat`** dosyasına çift tıklayın (ya da terminalde `py install.py` çalıştırın).
3. **Yeni** bir terminal açıp `meridian` yazın veya Başlat menüsünden **Meridian**'ı kullanın.

Kurucu klasörünü *kullanıcı* PATH'inize ekler (yönetici gerekmez; atlamak için `--no-path`). ARP keşfi, işletim sistemi tespiti ve traceroute için terminali **Yönetici olarak çalıştır** ile açın. Windows Defender Güvenlik Duvarı nmap'in ağı kullanmasına bir kez izin sorabilir.

### Kurulumunuzu denetleyin

```sh
meridian --doctor           # başka dil için --lang tr (veya de, es, fr)
```
Python, nmap, tarama yetkileri, tarayıcı, veri klasörü ve portu listeler; her sorunun nasıl giderileceğini söyler.

### Sürüm, seçenekler, güncelleme, kaldırma

```sh
meridian --version
meridian --help
```
Güncelleme: `git pull`, ardından `python3 install.py` komutunu yeniden çalıştırın (uygulama kopyasını değiştirir, verilerinizi korur). Kaldırma:
```sh
meridian --uninstall              # komutu, uygulama kopyasını, menü girdisini VE kayıtlı verilerinizi kaldırır
meridian --uninstall --keep-data  # verileri korur; soruyu atlamak için --yes ekleyin
```
Normal kullanıcınızla, sudo olmadan çalıştırın.

### Kurmadan çalıştırma

```sh
python3 server.py            # veya: python3 server.py --serve   (pencere yok; adresi yazar)
```
Meridian 8765 portunu kullanır (tema, ön ayar ve notlar hatırlansın diye); doluysa boş bir porta geçer. Ortam değişkenleri: `MERIDIAN_PORT`, `MERIDIAN_LANG`, `MERIDIAN_NMAP` (nmap yolu), `MERIDIAN_DATA_DIR` (kayıtlı verilerin yeri), `MERIDIAN_AI_KEY` (bulut yapay zekâ sağlayıcısı için API anahtarı).

### Docker (isteğe bağlı, Linux)

```sh
docker build -t meridian .
docker run --rm --net=host -e MERIDIAN_LANG=tr meridian     # sonra günlükte yazan bağlantıyı açın (http://127.0.0.1:8765/?k=..., bir kez çalışır)
```
Meridian yalnızca `127.0.0.1` üzerinde dinlediği için `--net=host` gerekir. Windows ve macOS'taki Docker Desktop kapsayıcıları sanal makine içinde çalıştırır ve gerçek ağınızı göremez: oralarda Meridian'ı doğrudan kurun.

### İlk tarama

1. Hedef kutusunun yanındaki **Otomatik** düğmesine tıklayın (yerel ağınızı doldurur, örneğin `192.168.1.0/24`).
2. Yetki onay kutusunu işaretleyin.
3. **Hızlı**'yı seçip **Tara**'ya basın.

VirtualBox sanal makinesinde bağdaştırıcıyı **Köprü (Bridged)** yapın; NAT ile makine yalnızca kendi sanal ağını görür.

## Diller

Meridian İngilizce başlar. Başka bir dil yalnızca üst çubuktan seçerseniz (hatırlanır) ya da `--lang` / `MERIDIAN_LANG` ile başlatırsanız kullanılır; tarayıcı veya sistem dili kullanılmaz. Dışa aktardığınız raporlar (HTML, Markdown) gördüğünüz dilde olur. Makine tarafından okunan çıktılar (JSON, CSV başlıkları, denetim günlüğü) bilerek İngilizce kalır.

### Yeni dil ekleme

`locales/en.json` dosyasını `locales/<kod>.json` olarak kopyalayın (örneğin `pt.json`), değerleri çevirin, `_name` alanına dilin kendi adını yazın. `{yer tutucuları}` ve `_one` / `_other` çiftlerini koruyun. Başka bir şey değişmez: dosya uygulama, terminal mesajları, kurucu ve demo üretimi tarafından otomatik alınır. `python3 -m unittest tests.test_i18n` eksik anahtar veya yer tutucu olup olmadığını denetler. Sağdan sola yazılan diller henüz desteklenmiyor.

## Özellikler

* Hızlı / Servisler / Tam / İşletim sistemi / Zafiyet / Traceroute / Özel taramalar (doğrulanmış seçenekler, ham nmap argümanı yok), durdurma düğmesi
* Risk puanı (Kritik / Yüksek / Orta / Düşük) ve bulgular, cihaz türü tahmini, MAC üreticisi
* **Bilinen zafiyetler (isteğe bağlı, çevrimiçi):** yazılım sürümleri CVE'ler ve herkese açık exploit'ler için denetlenir, önerilen eylemle birlikte ([ayrıntı](#bilinen-zafiyet-araması))
* **Çevrimdışı ipuçları (isteğe bağlı):** küçük dahili listeyle yerelde eşleştirilir, hiçbir şey gönderilmez ([ayrıntı](#çevrimdışı-ipuçları))
* **Güvenilir cihazlar:** yeniden başlatmalarda korunan liste; bilinmeyen cihazlar her yerde işaretlenir ([ayrıntı](#güvenilir-cihazlar))
* Radyal topoloji haritası, sıralanabilir ve süzülebilir cihaz tablosu, cihaza özel notlar, kayıtlı Özel ön ayarlar
* Yerelde saklanan tarama geçmişi; iki tarama arasındaki fark ve aynı hedefin tekrarlanan taramaları için **risk eğilimi**
* İzleme modu: hedefi 5 dakikadan 6 saate kadar aralıklarla yeniden tarar; yeni cihaz, bilinmeyen cihaz, yeni port ve kaybolan cihaz için uyarır, isteğe bağlı **masaüstü bildirimi** olarak (Meridian açıkken çalışır)
* **Yapay zekâ analizi (isteğe bağlı):** yerel veya bulut bir modelden özet ve öncelikli düzeltmeler; IP veya cihaz adı gönderilmez ([ayrıntılar](#yapay-zekâ-analizi-isteğe-bağlı))
* Dışa aktarma: JSON, CSV, Markdown, HTML, PDF (yazdır), ham Nmap XML, IP listesini kopyala. Dosyalar doğrudan İndirilenler klasörünüze kaydedilir (tam yol mesajla gösterilir)
* **Rapor markalama:** şirket, müşteri, hazırlayan, gizlilik notu, vurgu rengi ve logo HTML, PDF ve Markdown raporlarında (yalnızca tarayıcınızda saklanır)
* 5 tema (Siyah, Beyaz, Mavi, Mor, Kor); siz seçene kadar tema sistemi izler

### Kabul edilen hedefler
IPv4 adresi, CIDR (en fazla `/22`), son sekiz bit aralığı (`192.168.1.10-50`) veya ana makine adı. Birden çoğunu boşluk veya virgülle ayırın (en fazla 32 hedef, toplam 1024 adres). IPv6 henüz desteklenmiyor.

## Güvenilir cihazlar

Haritada bir cihazı açıp **Güvenilen cihaz** kutusunu işaretleyin (isteğe bağlı bir ad verin) ya da Cihazlar sekmesinde **Bulunan tüm cihazlara güven**'e basarak bugünkü ağı başlangıç noktanız yapın. Bundan sonra:

* güvenilir olmayan her cihaz **BİLİNMİYOR** rozeti, haritada kesikli halka, "Cihaz güvenilenler listenizde yok" bulgusu (Orta) alır ve beşinci sayaca eklenir;
* izleme modunda listenin dışında yeni bir cihaz, düz "yeni cihaz" yerine **BİLİNMEYEN CİHAZ** uyarısı üretir.

Cihazlar, nmap bir **MAC adresi** görebiliyorsa (LAN'ınızda root / Yönetici olarak çalıştırın) MAC ile, aksi halde değişebilen IP adresiyle tanınır. Liste veri klasöründeki `devices.json` dosyasında saklanır (özel dosya, atomik yazma). Hiç güvenilir cihaz yoksa hiçbir şey işaretlenmez; kullanmaya siz karar verene kadar gürültü olmaz.

## Çevrimdışı ipuçları

**Çevrimdışı ipuçları**'nı işaretlerseniz tarama servis sürümlerini de tespit eder (Servisler profili gibi) ve bunları Meridian içindeki küçük bir listeyle karşılaştırır: vsftpd 2.3.4 arka kapısı, Apache 2.4.49 / 2.4.50 dizin aşma, OpenSSH 7.7 ve öncesi kullanıcı adı sızıntısı, Samba "SambaCry", Exim 4.87-4.91, OpenSSL "Heartbleed" 1.0.1-1.0.1f, UnrealIRCd 3.2.8.1 arka kapısı ve ProFTPD 1.3.5 mod_copy. **Hiçbir yere hiçbir şey gönderilmez** ve onay gerekmez. İpuçları ÇEVRİMDIŞI diye etiketlenir ve çevrimiçi aramayla birleştirilebilir (her CVE bir kez listelenir). Bu ünlü vakaların kısa bir listesidir, zafiyet veritabanı değildir: ipucu yoksa güvenli demek değildir. Çevrimiçi aramada olduğu gibi, bir dağıtım yazılımı sürüm numarasını değiştirmeden yamalamış olabilir.

## Bilinen zafiyet araması

Açıkken, port denetleyen her tarama (Hızlı, Servisler, Tam TCP, İşletim sistemi, Traceroute, Zafiyet ve sürüm tespitli Özel) iki ek iş yapar:

1. nmap her açık portun arkasındaki **yazılımı ve sürümü** tespit eder (`-sV`; Hızlı ve Traceroute hızlı `--version-light` kullanır).
2. nmap ile gelen `vulners` NSE betiği o yazılımı vulners.com'da arar ve **CVE'leri, CVSS puanlarını ve herkese açık exploit kodu olup olmadığını** döndürür.

Meridian sonucu cihaz panelinde her portun altında gösterir (en kötüsü önce), **önerilen eylemi** içeren bir bulgu ekler, cihazın risk puanını yükseltir ve CVE'leri dışa aktarmalara ekler. **Cihaz keşfi bunu asla çalıştırmaz**, çünkü port denetlemez.

**Açma.** **Bilinen zafiyetleri denetle (çevrimiçi)** kutusunu her işaretlediğinizde, nelerin gönderildiğini açıklayan bir uyarı penceresi onay ister. Onay yalnızca sonraki tarama için geçerlidir: kutu o tarama başlayınca kendini temizler ve çalıştırmalar arasında hiçbir şey hatırlanmaz.

**Makinenizden ne çıkar.** vulners.com'a yalnızca yazılım adları ve sürümleri (örneğin `vsftpd 2.3.4`) gider; IP adresleri veya ana makine adları asla. nmap betiği parmak izi verilerini ayrıca GitHub'dan indirir. API anahtarı gerekmez ve kullanılmaz.

**Size ne söylemez**
* Eşleşmeler **sürüm metninden** gelir, yani doğrulanmış değil "olası"dır. Debian ve Ubuntu gibi dağıtımlar yazılımı sürüm numarasını değiştirmeden yamalar.
* Arama, bir sorunu **hangi sürümün düzelttiğini** bildirmez. Duyuru bağlantısını veya paket yöneticinizi kullanın (örneğin `apt changelog <paket>`).
* nmap sürüm numarası okuyamazsa hiçbir şey bulunmaz. Panel o port için bunu söyler.
* API anahtarı olmadan veride CISA "aktif sömürülüyor" işareti yoktur; herkese açık exploit işaretleri ve CVSS vardır. Meridian API kredisi harcamaz.
* Meridian exploit'lerin var olduğunu yalnızca **bildirir**. Exploit kodu çalıştırmaz veya indirmez.

## Yapay zekâ analizi (isteğe bağlı)

**AI** sekmesini açıp bir sağlayıcı seçin; o zamana kadar hiçbir şey kullanılmaz ve hiçbir şey gönderilmez.

| Sağlayıcı | Nerede çalışır | Ne gerekir |
|---|---|---|
| Ollama | bilgisayarınızda (`127.0.0.1:11434`) | Ollama çalışıyor ve bir model indirilmiş olmalı |
| LM Studio | bilgisayarınızda (`127.0.0.1:1234`) | LM Studio'nun yerel sunucusu açık olmalı |
| Claude, OpenAI | onların bulutunda | API anahtarı (sekmeye yapıştırın ya da `MERIDIAN_AI_KEY` tanımlayın) |

Meridian veriyi tarama sonucundan kendisi hazırlar ve her IP adresini, MAC adresini, cihaz adını, üreticiyi ve banner'ı çıkarır; yalnızca işletim sistemi, portlar, servisler, sürümler ve CVE numaraları H1, H2 gibi etiketlerle kalır. Bulut isteği önce tam olarak neyin gideceğini gösterir ve tek kullanımlık onay ister. Yanıt denetlenir, düz metin olarak gösterilir ve HTML ile Markdown raporlarında "üretilmiştir" diye işaretlenir: uygulamadan önce doğrulayın. Ayrıntılar [SECURITY.md](SECURITY.md) içinde.

## Güvenlik modeli
Yalnızca localhost'a bağlanma, çalıştırma başına belirteç (sabit zamanlı karşılaştırma), Host ve Origin denetimleri, sıkı CSP, beyaz listeli tarama seçenekleri, sıkı hedef doğrulaması, aynı anda tek tarama (tek bir `ScanManager`), 1 saatlik tarama sınırı, herkese açık hedef onayı, her taramadan önce yetki onay kutusu ve veri klasöründe yerel denetim günlüğü (1 MB'ta döner; geçmiş, cihazlar ve denetim günlüğü özel dosyalardır). Geçici dosyalar rastgele adlı özel bir klasörde durur ve her nmap kendi süreç grubunda (Windows'ta süreç ağacı) çalışır; durdurma, zaman sınırı, çıkış ve çökme kurtarmasında durdurulur ve toplanır. Windows'ta port özel olarak bağlanır, başka hiçbir program paylaşamaz. Bkz. [SECURITY.md](SECURITY.md).

Risk puanları açık servislerden ve NSE çıktısından gelen sezgisel değerlerdir; profesyonel bir değerlendirmenin yerini tutmaz.

## Sorun giderme

Önce `meridian --doctor` çalıştırın.

* **LAN'ımda yalnızca birkaç cihaz bulunuyor.** root / Yönetici ile çalıştırın (yukarıdaki tablo). Hedefin *sizin* ağınız olduğunu (**Otomatik**) ve sanal makinede bağdaştırıcının **Köprü** olduğunu da kontrol edin. Bazı yönlendiriciler cihazları birbirinden gizler (AP / istemci yalıtımı).
* Başlangıç satırında **`nmap: BULUNAMADI`**: nmap'i kurun (yukarıdaki tablo). Windows'ta kurduktan sonra *yeni* bir terminal açın; Meridian ayrıca `C:\Program Files (x86)\Nmap` klasörüne de bakar. `MERIDIAN_NMAP` ile herhangi bir nmap'i gösterebilirsiniz.
* **`command not found: meridian`** (Linux, macOS): `~/.local/bin` klasörünü PATH'e ekleyin. **Windows:** kurulumdan sonra yeni bir terminal açın.
* **Uygulama penceresi yok, normal bir tarayıcı sekmesi açıldı:** Chromium tabanlı tarayıcı bulunamadı. Chrome, Edge veya Brave kurun ya da sekmeyi kullanın.
* **macOS: "Meridian.app" Finder'dan açılmıyor.** `meridian`'ı bir kez terminalde çalıştırıp mesajı okuyun; `meridian --doctor` eksiği gösterir.
* **Terminalde `vaInitialize failed` veya başka Chromium mesajları** tarayıcının zararsız GPU uyarılarıdır.
* **Pencere root olarak açıldı:** Meridian pencereyi `sudo`'yu çalıştıran kullanıcı olarak açar. Gerçek root olarak giriş yaptıysanız yazdırılan adresi normal bir tarayıcıda açın.
* **Bir port için zafiyet listelenmiyor.** Panel nedenini söyler: "Sürüm numarası tespit edilemedi" aranacak bir şey olmadığı, "Bu sürüm için bilinen zafiyet döndürülmedi" aramanın çalışıp bir şey bulmadığı demektir. Tarama "Zafiyet verisi döndürülmedi" diyorsa makinenin vulners.com'a ulaşabildiğini kontrol edin.
* **Windows konsolunda bozuk harfler:** Meridian çıktısını UTF-8'e geçirir; konsol yazı tipinizde bir harf yoksa Windows Terminal kullanın.

## Geliştirme

```sh
python3 -m unittest discover -s tests -v
```
Her push'tan önce `python3 tools/preflight.py` çalıştırın: dosyaları, satır sonlarını, üretilen demoyu ve sürümü denetler, sonra testleri çalıştırır; böylece CI'daki kırmızı çarpı sürpriz olmaz.

CI aynı komutu **Ubuntu, macOS ve Windows**'ta Python 3.10 - 3.13 ile çalıştırır (`.github/workflows/tests.yml`). Platform mantığının çoğu platform taklit edilerek test edilir, bu yüzden testler her yerde çalışır; yalnızca Windows ve macOS'a özgü sistem çağrıları (kayıt defteri, PowerShell kısayolu, `ps`) taklitlerle kapsanır ve son kontrol için gerçek makine ister.

Sürümler: sürüm numarası `server.py` başındaki `VERSION` içindedir. Her sürümde artırın ve aynı numarayı GitHub'da etiketleyin (örneğin `v0.5.1`).

Yapı: `server.py` (HTTP sunucusu, `ScanManager`, nmap çalıştırıcı, ayrıştırıcı, doğrulama, platform yardımcıları, terminal dilleri), `ai.py` (isteğe bağlı yapay zekâ analizi), `index.html` (tek dosya arayüz), `locales/*.json` (tüm metinler), `install.py` (+ `install.sh`, `install.bat`), `installer/meridian.iss` (Windows kurulumu), `assets/` (simgeler), `docs/` (yalnızca tarayıcıda çalışan demo), `tools/` (`build_demo.py`, `build_deb.py`, `make_icons.py`, `preflight.py`), `.github/workflows/` (test ve sürüm), `tests/`, `Dockerfile`.

`docs/index.html` demosu `index.html`, `locales/` ve `docs/demo-shim.js` dosyalarından **üretilir**. Bunlardan birini değiştirince `python3 tools/build_demo.py` çalıştırın; eşitlik bozulursa bir test başarısız olur.

## Yol haritası
Sağdan sola diller, isteğe bağlı vulners API anahtarı ayarı ("aktif sömürülüyor" işaretini ekler), NSE betik seçici, IPv6 hedefleri, `pipx` paketi.

## Lisans
MIT - bkz. [LICENSE](LICENSE).
