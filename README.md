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
BULGULAR (6)
  [YUKSEK] sender_mismatch: From domaini (paypa1-verify.com) ile Return-Path
           domaini (totally-different-domain.ru) uyusmuyor...
  [YUKSEK] spf_fail / dkim_fail / dmarc_fail: ucu de basarisiz
  [YUKSEK] link_mismatch: Gorunen link paypal.com gosteriyor ama gercekte
           paypa1-verify-secure.ru'e gidiyor
  [ORTA]   reply_to_mismatch: yanitlar farkli bir domaine yonleniyor

Ozet: YUKSEK: 5, ORTA: 1
```

Ayni arac `samples/sample_legit.eml` icin 0 bulgu donduruyor - yani false
positive uretmiyor.

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

**Siradaki (Katman 2 - zenginlestirme):**
- [ ] Supheli dil desenleri (aciliyet, tehdit ifadeleri)
- [ ] IP tabanli URL / punycode / benzer-domain tespiti
- [ ] VirusTotal / URLhaus API entegrasyonu
- [ ] Ek hash'leme + tehdit veritabani sorgusu
- [ ] Toplam risk skoru (dusuk/orta/yuksek)

## Writeup notu

Katman 1'in cekirdek fikri: bir phishing e-postasinin **gorunen** kismi
(From adi, link metni) ile **gercek** kismi (Return-Path, href, SPF/DKIM/DMARC
sonucu) arasinda hemen hemen her zaman bir tutarsizlik vardir - cunku
saldirgan gorunen kismi istedigi gibi yazabilir ama alt yapisini (DNS, SMTP
zarf adresi) taklit etmesi cok daha zordur. Bu yuzden dort kontrolun hepsi
ayni soruyu farkli acilardan soruyor: "gorunen ile gercek ayni mi?" Dort
kontrolden biri bile pozitif cikarsa guclu bir sinyal; hepsi birden cikarsa
(bu ornekte oldugu gibi) tartismasiz bir phishing vakasi.

## Guvenlik notu

Bu arac e-postalari **pasif** analiz eder, hicbir ek veya linki acmaz/takip
etmez. Zararli ornekleri izole bir ortamda test edin.
