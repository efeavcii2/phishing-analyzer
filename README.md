# Phishing Analiz Araci

Bir `.eml` dosyasini alip "bu phishing mi?" sorusuna kanita dayali bir risk
raporu ureten komut satiri araci. SOC analistinin gunluk phishing triyaji
isini otomatize etmeyi hedefler.

## Kullanim

```bash
python analyze.py samples/sample_phishing.eml
```

## Neden onemli

Phishing triyaji, SOC analistlerinin en sik tekrarlanan ve en cok zaman alan
islerinden biri. Bu arac, bir e-postanin basliklarindaki ve govdesindeki
teknik ipuclarini (gonderen uyumsuzlugu, SPF/DKIM/DMARC sonucu, link gizleme
vb.) otomatik olarak cikarip analisti hizlandirir.

## Ornek cikti

`samples/sample_phishing.eml` dosyasini analiz edersek (tam cikti
`samples/output_phishing_example.txt` icinde):

```
RISK SEVIYESI: YUKSEK (puan: 82)
...
BULGULAR (10)
  [YUKSEK] sender_mismatch: From domaini (paypa1-verify.com) ile Return-Path
           domaini (totally-different-domain.ru) uyusmuyor...
  [YUKSEK] spf_fail / dkim_fail / dmarc_fail: ucu de basarisiz
  [YUKSEK] link_mismatch: Gorunen link paypal.com gosteriyor ama gercekte
           paypa1-verify-secure.ru'e gidiyor
  [YUKSEK] lookalike_domain: paypa1-verify.com ve paypa1-verify-secure.ru,
           "paypal" markasini taklit ediyor
  [ORTA]   reply_to_mismatch + 2x suspicious_language (aciliyet, hesap tehdidi)

Ozet: YUKSEK: 7, ORTA: 3
```

Ayni arac `samples/sample_legit.eml` icin 0 bulgu, **DUSUK** risk donduruyor
- yani false positive uretmiyor.

**False positive hikayesi:** Araci kendi gercek GitHub bildirim mailimle
(`samples/sample_legit_github_notification.eml`) test ederken ilk versiyon
1 yanlis bulgu uretti: `reply_to_mismatch`. Sebebi, GitHub'in yanitlari
`reply.github.com` alt-domaininden islemesi - From ise `github.com`. Tam
domain karsilastirmasi bunu "farkli domain" sayiyordu. Duzeltme: domain
karsilastirmasini "temel domain"e (son iki etiket, `_base_domain()`)
indirdim, boylece `reply.github.com` ile `github.com` ayni sayiliyor ama
`totally-different-domain.ru` ile `paypa1-verify.com` hala farkli
sayiliyor. Gercek veriyle test etmeden bu hata fark edilmezdi.

## Durum

**Katman 1 (cekirdek) tamamlandi:**
- [x] `.eml` okuma + baslik ayristirma (From, Reply-To, Return-Path, Received)
- [x] Gonderen uyumsuzlugu tespiti (From vs Return-Path/Reply-To domain)
- [x] SPF/DKIM/DMARC yorumlama (Authentication-Results basligi)
- [x] Link cikarma + gizleme tespiti (gorunen metin vs gercek href)
- [x] Terminal raporu (siddete gore siralanmis, ozet satirli)

**Katman 2 (zenginlestirme) tamamlandi:**
- [x] Supheli dil desenleri (aciliyet, hesap tehdidi, sahte odul)
- [x] IP tabanli URL tespiti
- [x] Punycode / benzer-domain (typosquat) tespiti
- [x] URLhaus API entegrasyonu (auth.abuse.ch'den ucretsiz key)
- [x] VirusTotal ile ek hash sorgusu
- [x] Agirlikli risk skoru (DUSUK/ORTA/YUKSEK)

**Siradaki (Katman 3 - sunum, opsiyonel):**
- [ ] JSON cikti modu
- [ ] Basit HTML rapor
- [ ] Toplu analiz (bir klasordeki tum .eml'ler)

## Writeup notu

Katman 1'in cekirdek fikri: bir phishing e-postasinin **gorunen** kismi
(From adi, link metni) ile **gercek** kismi (Return-Path, href, SPF/DKIM/DMARC
sonucu) arasinda hemen hemen her zaman bir tutarsizlik vardir - cunku
saldirgan gorunen kismi istedigi gibi yazabilir ama alt yapisini (DNS, SMTP
zarf adresi) taklit etmesi cok daha zordur. Bu yuzden dort kontrolun hepsi
ayni soruyu farkli acilardan soruyor: "gorunen ile gercek ayni mi?" Dort
kontrolden biri bile pozitif cikarsa guclu bir sinyal; hepsi birden cikarsa
(bu ornekte oldugu gibi) tartismasiz bir phishing vakasi.

**Katman 2 writeup notu:** Katman 1'in "gorunen vs gercek" mantigini
genisleterek, Katman 2 artik "bu domain/dil/dosya daha once kotu niyetli
olarak gorulmus mu?" sorusunu da soruyor - hem yerel sezgisel kontrollerle
(dil kaliplari, IP/punycode/typosquat) hem de harici tehdit istihbarati
(URLhaus, VirusTotal) ile. Onemli bir muhendislik karari: butun bu
kontroller tek bir "faktor" degil, **agirlikli bir toplam** - tek bir dusuk
siddetli sinyal (ornek: eksik Authentication-Results basligi) basli basina
oldurucu degil ama birkac sinyal ust uste binince (sender mismatch + SPF
fail + lookalike domain) skor hizla YUKSEK'e cikiyor. Bu, gercek SOC
triyajinin da calisma mantigi: tek bir kirmizi bayrak degil, bayraklarin
birikimi.

API entegrasyonlarinda da onemli bir gercek-dunya dersi cikti: hem URLhaus
hem (zaten bilinen) VirusTotal, ucretsiz kullanim icin bile bir hesap/key
gerektiriyor - URLhaus bunu yakin zamanda zorunlu hale getirmis (abuse.ch
politika degisikligi). Ikisi de .env'den okunuyor, key yoksa arac crash
etmeden ilgili kontrolu BILGI seviyesinde "atlandi" diyerek geciyor.

## Guvenlik notu

Bu arac e-postalari **pasif** analiz eder, hicbir ek veya linki acmaz/takip
etmez. Zararli ornekleri izole bir ortamda test edin. API key'ler `.env`
dosyasinda tutulur, `.gitignore` ile repoya girmesi engellenir.
