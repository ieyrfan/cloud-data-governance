# DataSentinel direct mode — current presentation brief

**Checked:** 2 November 2026 against source and live configuration. **Live entry:** `https://datasentinel.ifhx.my/`. For the component-by-component retention map, see [current mode and retention](CURRENT_MODE_AND_RETENTION.md).

## Bahasa Melayu

**Apa produk ini?** DataSentinel ialah penyelesaian untuk melindungi satu fail pada satu masa. Pengirim memuat naik fail, sistem mencari maklumat peribadi yang disokong, menutupnya dalam format fail yang sama, kemudian memulangkan fail terlindung terus untuk dimuat turun. Pengirim menyimpan dokumen asal. Jika penerima memerlukan maklumat asal, mereka perlu memintanya daripada pengirim.

**Aliran yang boleh didemonstrasikan sekarang**

1. Buka laman utama. Tiada akaun atau login diperlukan untuk aliran awam.
2. Pilih fail sehingga **3 MiB**. Format: PDF, JPG/JPEG, PNG, TXT, CSV, JSON dan format teks yang disenaraikan pada halaman. PDF imbasan terhad kepada **tiga halaman**.
3. Secara lalai, semua kategori sensitif yang disokong ditutup. Pilihan untuk mengekalkan kategori tertentu memerlukan pengesahan jelas. Pada imej, pengguna juga boleh menambah kawasan hitam secara manual sebelum menghantar.
4. API memproses bait fail dalam memori. Teks diekstrak; imej dan PDF imbasan menggunakan Amazon Textract OCR. Corak maklumat sensitif dikenal pasti, redaction dibuat, dan output diperiksa semula. Jika pengesanan atau liputan tidak cukup yakin, permintaan gagal tanpa mengeluarkan fail.
5. Respons API mengandungi fail terlindung serta metadata tanpa nilai peribadi. Pelayar memulakan muat turun secara automatik dan memaparkan resit sementara: jenis dokumen, cadangan klasifikasi, kategori dikesan/dilindungi/dikekalkan, OCR, semakan output bagi nilai yang dikesan, masa proses dan ID korelasi rawak. Resit ini tidak disimpan sebagai rekod dokumen; pautan **Download again** tersedia jika pelayar menghalang muat turun.

**Sempadan privasi.** Laluan semasa tidak menulis fail asal atau output ke S3 dan tidak mencipta rekod dokumen dalam DynamoDB. Hanya jumlah permintaan harian tanpa IP atau kandungan fail disimpan untuk mengehadkan servis percuma kepada 200 permintaan bagi setiap hari UTC. Tiada inventori pelanggan, akses asal atau butang “unredact” pada laman live. Infrastruktur S3/DynamoDB lama masih wujud dalam stack untuk kod alternatif; laluan pelanggan lama ditutup dengan HTTP 410. “Tiada simpanan fail oleh aplikasi” tidak bermaksud AWS tidak pernah menerima bait fail: API Gateway, Lambda dan Textract memprosesnya sementara, manakala log operasi tertakluk kepada polisi AWS. Jangan dakwa zero-knowledge, ketepatan 100%, atau zero retention di semua lapisan.

**Skrip demo ringkas.** “Kami hantar satu fail contoh sintetik. DataSentinel mengesan medan sensitif, menutupnya, dan memulangkan fail dalam format yang sama terus sebagai muat turun. Kami tidak memaparkan senarai dokumen pelanggan dan tidak menyimpan fail ini dalam storan aplikasi. Jika pemeriksaan tidak cukup yakin, sistem berhenti dan tidak mengeluarkan salinan yang mungkin bocor.”

## English

**What it does.** DataSentinel protects one submitted document at a time. It detects supported personal data, redacts it in the original format, and returns the protected file as a direct download. The sender retains the original and decides whether to disclose any unredacted information to a recipient.

**Live path.** Open the root page without signing in; select a file up to **3 MiB**; submit; receive the protected bytes from `POST /api/v1/protect`; the browser starts the download and shows a temporary, content-free processing receipt. It includes detected/redacted/kept categories, OCR use, a detected-value output check, elapsed time and a random correlation ID. Image and scanned PDF text is read with Amazon Textract. Scanned PDFs are limited to **three pages**. The free service has a shared **200-request UTC daily limit**. For images, uncertain OCR lines are conservatively covered and a second OCR pass may improve detection; scanned-PDF OCR remains strict. Unsupported, undetected, or unverified results fail without a download. Suggested classification does not authorize sharing.

**Privacy claim.** The current application path does not persist submitted or protected document bytes in S3 or create a DynamoDB document record. The old stored-document routes are disabled. This claim does not cover transient AWS processing, all provider retention, or a guarantee that every possible PII value is detected. The original remains with its sender.

**Present it honestly.** Say “application-side non-persistence with direct protected download,” not “AWS never receives data,” “zero knowledge,” or “perfect detection.” Use synthetic documents for booth demonstrations.

## Verification boundary

On 2 November 2026, 252 Python tests, seven frontend flow tests and lint passed locally. A read-only AWS check found both legacy document buckets empty (zero object versions and delete markers), enabled quota-table TTL, 1-day Lambda log retention, API Lambda concurrency 2/timeout 30 seconds, and a 1 request/second protect-route throttle. Seven alarms, including new API throttling and near-timeout alarms, were verified live after deployment. Two synthetic live requests returned protected files and content-free receipts; a rejected request returned no file. The Chrome extension lacked local-file access for an interactive browser upload, so that particular browser gate was not re-run. These are point-in-time checks. The complete active-mode boundaries are in [current mode and retention](CURRENT_MODE_AND_RETENTION.md).
