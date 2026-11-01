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

## Durum

Katman 1 (cekirdek) gelistiriliyor:
- [x] `.eml` okuma + baslik ayristirma (From, Reply-To, Return-Path, Received)
- [ ] Gonderen uyumsuzlugu tespiti
- [ ] SPF/DKIM/DMARC yorumlama
- [ ] Link cikarma + gizleme tespiti
- [ ] Terminal raporu

## Guvenlik notu

Bu arac e-postalari **pasif** analiz eder, hicbir ek veya linki acmaz/takip
etmez. Zararli ornekleri izole bir ortamda test edin.
