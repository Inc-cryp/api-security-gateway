# API Security Gateway

Gateway keamanan untuk API perbankan, ditulis dengan **pustaka standar Go saja**
(tanpa dependensi eksternal, tanpa `go.sum`). Gateway menerima permintaan masuk,
memverifikasi identitas pemanggil, menegakkan batas laju dan aturan alamat IP,
lalu meneruskannya ke layanan di belakangnya.

Cocok sebagai lapisan pelindung di depan layanan seperti `account`, `transfer`,
`payment`, dan `customer` — persis empat rute yang dipakai di
[`config.example.yaml`](config.example.yaml).

## Daftar isi

- [Fitur](#fitur)
- [Arsitektur](#arsitektur)
- [Urutan pemeriksaan](#urutan-pemeriksaan)
- [Mulai cepat](#mulai-cepat)
- [Referensi konfigurasi](#referensi-konfigurasi)
- [Skema autentikasi](#skema-autentikasi)
- [Contoh pemakaian](#contoh-pemakaian)
- [Kode galat](#kode-galat)
- [Batasan yang diketahui](#batasan-yang-diketahui)
- [Pengembangan](#pengembangan)

## Fitur

| Kontrol | Keterangan |
| --- | --- |
| **JWT** | HS256, memvalidasi `iss`, `aud`, `exp`, dan `nbf` dengan toleransi jam. `alg: none` serta RS/ES ditolak untuk mencegah *algorithm confusion*. |
| **API Key** | Header `X-Api-Key`, dibandingkan dengan waktu tetap (*constant time*). |
| **HMAC Signature** | Tanda tangan per permintaan atas metode, jalur, query, timestamp, client id, dan badan permintaan. Badan permintaan dipulihkan utuh setelah verifikasi. |
| **Rate Limiting** | *Token bucket* per rute, dikunci per alamat klien. Membalas `429` beserta `Retry-After` dan `X-RateLimit-Limit`. Bucket menganggur dibuang agar memori terbatas. |
| **IP Restriction** | Daftar `allowed_ips`/`denied_ips` per rute dengan pencocokan awalan terpanjang. `denied_ips` selalu menang. |
| **Request Logging** | Log akses JSON terstruktur: `request_id`, `method`, `path`, `client_ip`, `principal`, `route`, `service`, `status`, `bytes`, `duration`. Query dapat disunting otomatis. |
| **Circuit Breaker** | Per layanan. Terbuka setelah sekian respons `5xx` berturut-turut, mencoba satu probe setelah `open_timeout`, dan menutup lagi setelah `half_open_successes` probe berhasil. Respons `4xx` tidak pernah membuka breaker. |
| **Timeout** | Batas waktu per rute, dengan nilai bawaan global. Permintaan yang melewati batas dibalas `504`. |

Selain itu gateway juga: membatasi ukuran badan permintaan (`413`), menolak
metode yang tidak diizinkan (`405` beserta header `Allow`), menyetel header
keamanan pada **setiap** respons termasuk halaman galat, meneruskan
`X-Forwarded-*` berdasarkan alamat klien yang berhasil diresolusi, dan mematikan
diri secara rapi saat menerima `SIGTERM`.

## Arsitektur

```
cmd/gatewayd          titik masuk: memuat konfigurasi, menyusun komponen, menangani SIGTERM
internal/config       parser YAML subset tulis-sendiri, nilai bawaan, dan validasi
internal/router       pencocokan rute berdasarkan awalan segmen, filter IP per rute
internal/middleware   rantai pemeriksaan dan perekat antar komponen
internal/auth         verifier JWT, API key, dan HMAC
internal/ratelimit    token bucket dengan pengusiran bucket menganggur
internal/breaker      circuit breaker per layanan
internal/ipfilter     daftar CIDR izin/tolak
internal/proxy        penerusan permintaan ke layanan hulu
internal/logging      log akses JSON
internal/httpx        pembantu HTTP: pembungkus ResponseWriter, resolusi IP klien, galat
```

Totalnya sekitar 9.500 baris kode Go, 5.900 di antaranya berupa pengujian.
Tidak ada satu pun dependensi di luar pustaka standar.

## Urutan pemeriksaan

```
Recover → AccessLog → RequestID → IPFilter → RateLimit → Route → Auth → Proxy
```

Urutan ini disengaja:

- **Recover paling luar** supaya panic di mana pun menjadi respons `500`, bukan
  koneksi yang terputus begitu saja.
- **AccessLog berikutnya** supaya satu baris log tercatat untuk setiap hasil,
  termasuk hasil yang diproduksi tahap di dalamnya.
- **IPFilter dan RateLimit sebelum Auth** supaya menolak pemanggil yang menyalahi
  aturan hanya memakan satu pencarian peta, bukan verifikasi tanda tangan.
- **Kutipan fakta per permintaan** (request id, rute, layanan, principal) diambil
  dari satu penampung bersama yang diisi tiap tahap. Tahap di dalam meneruskan
  *request* turunan lewat `WithContext`, sehingga membaca konteks *request* paling
  luar akan selalu menghasilkan nilai kosong.

## Mulai cepat

Butuh Go 1.25 atau lebih baru.

```sh
git clone https://github.com/Inc-cryp/api-security-gateway.git
cd api-security-gateway

make build          # menghasilkan bin/gatewayd
cp config.example.yaml config.yaml
$EDITOR config.yaml # ganti setiap penanda CHANGE ME

./bin/gatewayd -config config.yaml
./bin/gatewayd -version
```

`config.yaml` **tidak** ikut ter-*commit* (lihat `.gitignore`), justru karena
berkas itulah yang berisi kredensial asli. Yang dilacak hanya
`config.example.yaml`.

## Referensi konfigurasi

Berkas contoh lengkap ada di [`config.example.yaml`](config.example.yaml).
Ringkasannya:

### `server`

| Kunci | Arti |
| --- | --- |
| `addr` | Alamat dengar, misalnya `:8080`. |
| `read_header_timeout`, `read_timeout`, `write_timeout`, `idle_timeout` | Batas waktu server HTTP. |
| `shutdown_timeout` | Tenggang saat mematikan diri secara rapi. |
| `max_body_bytes` | Batas badan permintaan; kelebihannya dibalas `413`. |

### `upstreams` dan `upstream`

`upstreams` memetakan nama layanan ke URL dasarnya. Setiap `service:` pada rute
harus ada di peta ini; kalau tidak, konfigurasi ditolak saat dimuat.

`upstream` mengatur perilaku penerusan: `timeout` bawaan, `max_idle_conns`,
`idle_conn_timeout`, dan blok `circuit_breaker` (`failure_threshold`,
`open_timeout`, `half_open_successes`).

### `security`

Blok `jwt`, `api_keys`, `hmac`, dan `client_ip`. Untuk `client_ip`, header
`forwarded_header` hanya dipercaya bila *peer* langsung berada di dalam
`trusted_proxies`; dari *peer* lain header tersebut diabaikan dan alamat soket
yang dipakai.

### `headers`

Header yang ditambahkan ke setiap respons, termasuk respons penolakan. Di sinilah
tempat header pengerasan seperti `X-Frame-Options`, `Content-Security-Policy`,
dan `Strict-Transport-Security`: halaman galat juga dirender oleh peramban.

### `logging`

`level` (`debug`, `info`, `warn`, `error`) dan `redact_query`. Saat
`redact_query: true`, query diganti menjadi `[redacted]`.

### `routes`

Setiap rute mendukung `path`, `service`, `authenticators`, `methods`,
`strip_prefix`, `timeout`, `rate_limit`, `rate_burst`, `allowed_ips`, dan
`denied_ips`.

- `methods` kosong berarti semua metode diizinkan. `HEAD` ikut diizinkan bila
  `GET` diizinkan.
- `rate_limit` wajib disertai `rate_burst`.
- Rute dicocokkan berdasarkan awalan pada batas segmen: `/account` cocok dengan
  `/account/42` tetapi **tidak** dengan `/accounting`. Rute terpanjang yang menang.

## Skema autentikasi

### JWT

```http
Authorization: Bearer <token>
```

Hanya HS256. `iss` dan `aud` diperiksa bila dikonfigurasi, begitu pula `exp` dan
`nbf` dengan toleransi `clock_skew`. Rahasia yang lebih pendek dari 16 byte
ditolak saat startup.

### API Key

```http
X-Api-Key: <key>
```

### HMAC

```http
X-Client-Id: partner-bank
X-Timestamp: 1758532800
X-Signature: <hex>
```

Tanda tangan dihitung atas teks kanonik berikut, dengan `\n` sebagai pemisah:

```
METHOD \n PATH \n RAWQUERY \n TIMESTAMP \n CLIENTID \n SHA256-HEX(body)
```

`PATH` adalah jalur permintaan tanpa query, dan `RAWQUERY` adalah query mentah
tanpa tanda `?`. `TIMESTAMP` adalah detik Unix dan harus berada di dalam
`max_skew`. Contoh di Python:

```python
import hashlib, hmac, time

body = b'{"amount": 100}'
ts = str(int(time.time()))
canonical = "\n".join([
    "POST", "/payment", "", ts, "partner-bank",
    hashlib.sha256(body).hexdigest(),
])
sig = hmac.new(b"shared-secret", canonical.encode(), hashlib.sha256).hexdigest()
```

## Contoh pemakaian

```sh
# API key
curl -H 'X-Api-Key: CHANGE-ME-account-reader' \
     http://127.0.0.1:8080/account/42

# JWT
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:8080/account/42

# HMAC (lihat contoh perhitungan tanda tangan di atas)
curl -X POST http://127.0.0.1:8080/payment \
     -H 'Content-Type: application/json' \
     -H 'X-Client-Id: partner-bank' \
     -H "X-Timestamp: $TS" \
     -H "X-Signature: $SIG" \
     -d '{"amount": 100}'
```

## Kode galat

Setiap galat memakai amplop JSON yang sama:

```json
{"error": {"code": "unauthorized", "message": "authentication failed"}}
```

| Status | `code` |
| --- | --- |
| 400 | `bad_request` |
| 401 | `unauthorized` |
| 403 | `forbidden` |
| 404 | `not_found` |
| 405 | `method_not_allowed` |
| 413 | `payload_too_large` |
| 429 | `rate_limited` |
| 502 | `bad_gateway` |
| 503 | `service_unavailable` |
| 504 | `timeout` |
| lainnya | `internal_error` |

Alasan sebuah kredensial ditolak tidak pernah dikembalikan ke pemanggil, hanya
dicatat di log. Kalau tidak, gateway berubah menjadi alat untuk menebak kunci dan
tanda tangan.

## Batasan yang diketahui

- **HMAC tidak punya perlindungan replay.** Sebuah permintaan yang tertangkap
  dapat diterima kembali sampai timestamp-nya keluar dari `max_skew`. Karena itu
  `max_skew` dibuat pendek, dan TLS wajib dipasang di depan gateway. Untuk
  ketahanan penuh, tambahkan nonce yang disimpan pada penyimpanan bersama.
- **Parser YAML adalah subset, bukan YAML penuh.** Yang didukung: mapping
  bersarang, sequence skalar, dan sequence of mapping yang kuncinya sejajar
  dengan kunci pertama setelah tanda `-`. Yang **tidak** didukung: flow mapping
  di dalam item sequence (`- {path: /a, service: b}`), anchor/alias, tag, blok
  literal, dan dokumen ganda. Kunci yang tidak dikenal diabaikan diam-diam.
- **Pemeriksaan rute ganda belum menormalkan garis miring di akhir.** `/account`
  dan `/account/` sama-sama dinormalkan menjadi `/account`, tetapi pemeriksaan
  duplikat memakai jalur mentah, sehingga keduanya lolos dan rute kedua menjadi
  tidak terpakai.
- **Rate limit dikunci per alamat klien**, dan alamat itu berasal dari header
  yang diteruskan bila *peer*-nya tepercaya. Kalau `trusted_proxies` terlalu
  longgar, satu klien dapat mengambil jatah klien lain. Persempit daftarnya.
- **Tidak ada penyimpanan bersama antar instans.** Rate limit dan circuit breaker
  hidup di dalam proses, jadi menjalankan beberapa replika berarti batasnya
  berlaku per replika.
- **Failover layanan hulu belum ada.** Satu nama layanan menunjuk ke satu URL.

## Pengembangan

```sh
make test        # go test -race -count=1 ./...
make test-cover  # sama, plus ringkasan cakupan
make vet
make fmt-check   # gagal bila ada berkas yang tidak gofmt-clean
make build
make help        # daftar seluruh target
```

Cakupan pengujian saat ini:

| Paket | Cakupan |
| --- | --- |
| `internal/logging` | 100.0% |
| `internal/httpx` | 97.7% |
| `internal/proxy` | 97.2% |
| `internal/middleware` | 96.5% |
| `internal/ratelimit` | 95.7% |
| `internal/ipfilter` | 94.1% |
| `internal/auth` | 93.8% |
| `internal/config` | 92.9% |
| `internal/breaker` | 92.7% |
| `internal/router` | 92.2% |
| `cmd/gatewayd` | 63.9% |

Selain itu ada uji asap *end-to-end* yang menjalankan biner hasil `make build`
terhadap empat layanan hulu tiruan: 46 pemeriksaan mencakup ketiga skema
autentikasi, penolakan tanda tangan dan timestamp, batas ukuran badan, batas
laju, penolakan IP, timeout rute, membuka dan menutupnya kembali circuit breaker,
serta redaksi query pada log.

## Lisensi

[MIT](LICENSE)
