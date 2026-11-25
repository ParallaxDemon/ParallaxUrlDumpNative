# ParallaxUrlDumpNative — ULTRA

**Pure-native C/C++ URL intelligence: har finding ke saath source, byte offset, ELF address space aur (jahan available ho) runtime address. No hooks, no interception, no traffic modification, no Java/Kotlin/Python business logic.**

Is repo me do layers hain:

1. **`liburldump.so`** — on-device, passive runtime dumper. URLs ke saath absolute address, mapping offsets, module base aur ASLR-stable `module+0xOFF` likhta hai.
2. **`parallax_dump`** — host/native static analysis CLI. APK/ZIP, DEX, ELF aur assets scan karta hai, runtime dump merge karta hai, aur JSON/CSV/HTML report banata hai.

## Native analysis suite (`parallax_dump`)

### Build aur test

```sh
cmake -S . -B build-host -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-host -j4
ctest --test-dir build-host --output-on-failure
```

### Usage

```sh
./build-host/parallax_dump target.apk \
  -o report --stem target \
  --extract \
  --runtime /sdcard/UrlDump/urls_12345.txt
```

Supported inputs: `.apk`/`.zip`, standalone `.dex`, standalone ELF (`.so`/executable), ya koi bhi raw file. CLI options:

| Option | Matlab |
| --- | --- |
| `-o, --out DIR` | report directory (default `parallax-report`) |
| `--stem NAME` | output basename |
| `--extract` | APK entries ko `<out>/extracted` me path-traversal-safe extract karta hai |
| `--runtime FILE` | `liburldump` ki `urls_*.txt/.csv/.jsonl` merge karta hai (repeatable) |
| `--no-xrefs` | code-reference analysis skip |
| `--min-len`, `--max-len` | URL length bounds |
| `--no-utf16`, `--no-utf32`, `--no-escaped` | encoding scanners band karein |
| `-v, --verbose` | saare findings print karein |

Outputs: `<stem>.json`, `<stem>.csv`, `<stem>.html`.

### Modules

| Module | Kaam |
| --- | --- |
| ZIP/APK reader | Built-in ZIP64 + zlib inflate; optional minizip-ng backend |
| DEX reader | Bounds-checked `string_ids` + MUTF-8; source offset har string ka |
| ELF reader | Built-in ELF32/ELF64, sections/segments/symbols; optional LIEF backend |
| URL engine | ASCII, UTF-16LE/BE, UTF-32LE/BE, escaped URLs; exact byte offsets |
| Address calculator | `file offset`, `VA`, `RVA`, `module offset`, `runtime address` alag-alag fields |
| Xref engine | Raw pointer scan + Capstone instruction-level references (ARM/ARM64/x86/x86-64) |
| Runtime merge | `liburldump` outputs ko same finding schema me convert karta hai |
| Reports | JSON, CSV aur dark HTML table with evidence columns |

### Address vocabulary

| Field | Meaning |
| --- | --- |
| `entry_offset` | unpacked APK entry / scanned buffer ke andar byte offset |
| `file_offset` | standalone file me byte offset; APK entries ke liye `entry_offset` ke barabar |
| `va` | ELF virtual address (PT_LOAD se derived) |
| `rva` | `va - image_base`; image base = lowest PT_LOAD `vaddr` |
| `module_offset` | `addr - load_bias`, yani ASLR-stable `lib.so+0xOFF` value |
| `runtime_addr` | `module_base + module_offset`; sirf runtime observations me available |

Ek hi URL alag-alag encodings me mil sakti hai; report usse alag finding ke taur par rakhta hai kyunki uska source offset alag hota hai. Static scanning guarantee nahi deta — URLs encrypted, generated, assembled ya remotely fetched ho sakti hain.

### Optional backends

CMake switches:

| Switch | Effect |
| --- | --- |
| `PARALLAX_WITH_CAPSTONE=ON` | Capstone milne par ARM/ARM64/x86 xref evidence (default ON) |
| `PARALLAX_WITH_MINIZIP_NG=ON` | minizip-ng ZIP backend, warna built-in ZIP64 |
| `PARALLAX_WITH_LIEF=ON` | LIEF ELF backend, warna built-in ELF parser |
| `PARALLAX_WITH_NLOHMANN_JSON=ON` | nlohmann/json writer, warna built-in JSON writer |
| `PARALLAX_BUILD_TOOLS=OFF` | sirf static library banana |
| `PARALLAX_BUILD_TESTS=OFF` | tests skip karein |

Missing optional dependencies build ko nahi todte; CLI report me actual `zip_backend`, `elf_backend` aur `xref_backend` likha jata hai. APK entries untrusted maan kar bounds checks, size caps aur safe extraction use hoti hain.

---

## Runtime dumper (`liburldump.so`)

`liburldump.so` load hote hi ek detached native thread shuru hota hai jo har `interval` second par process ki readable memory scan karta hai. Har mile hue URL ke saath ye likhta hai:

| Field | Matlab |
| --- | --- |
| `addr` | URL ka absolute virtual address (runtime me ASLR ke saath badalta hai) |
| `region` | `/proc/self/maps` mapping range + permissions |
| `r_off` | `addr - region_start` (mapping ke andar offset) |
| `f_off` | `mapping pgoff + r_off` (mapped file ke andar byte offset) |
| `module` | mapped file ka basename, ya `[anon]` / `[heap]` / `[stack]` |
| `base` | module ka ELF load bias (`start - pgoff` se nikalta hai) |
| `m_off` | `addr - base` — **ASLR-stable offset**, GameGuardian me `libX.so+0xOFF` ke taur par usable |
| `enc` | `ASCII`, `UTF16LE`, `UTF16BE`, `UTF32LE`, `UTF32BE`, `ESCAPED` |
| `hits` | kisi bhi address par URL kitni baar dekha gaya |

Example line (`urls_<pid>.txt`):

```text
[2026-11-25 18:50:29] https://api.example.com/v1/config?x=1 | addr=0x7a1b2c003418 region=0x7a1b2c000000-0x7a1b2c100000 r--p r_off=0x3418 f_off=0x1a418 module=libUE4.so base=0x7a1b2bf00000 m_off=0x4418 enc=UTF16LE hits=3
```

Aur offset-first file (`urls_<pid>_offsets.txt`):

```text
libUE4.so+0x4418  0x7a1b2c003418  https://api.example.com/v1/config?x=1  [UTF16LE f_off=0x1a418]
```

### Runtime scanner kya karta hai

- `/proc/self/maps` se readable mappings + unka `pgoff`, perms aur path parse karta hai.
- `/proc/self/mem` se chunked `pread` (1 MB chunks + 1 KB read-ahead overlap) — bade regions bhi safe.
- `https://`, `http://`, `wss://`, `ws://` dhoondta hai.
- **ASCII/UTF-8, UTF-16LE, UTF-16BE, UTF-32LE, UTF-32BE** aur escaped form (`https:\/\/host\/path`) scan karta hai.
- Single-pass search (`h`/`w` anchoring) — poorana 24-pattern wala scanner bahut slow tha.
- Trailing punctuation, `\/` aur `&amp;` normalize karta hai; junk strings reject karta hai.
- Har unique URL ke liye alag-alag offsets collect karta hai (`max_hits_per_url` tak), hit count aur last-seen time rakhta hai.
- Khud ke `liburldump.so` mapping ko skip karta hai — apne scheme constants khud hi na pakde.
- 32-bit ABIs ke liye `_FILE_OFFSET_BITS=64` ke saath 64-bit file offsets.

**Kya nahi karta:** koi function hook nahi, cURL/DNS/SSL intercept nahi, URL rewrite/redirect nahi, SSL bypass nahi, network par kuch nahi bhejta.

### Runtime output files

Sabse pehle writable directory (first wins):

1. `$URLDUMP_OUT_DIR` (env)
2. `out_dir` from config file
3. `/storage/emulated/0/Android/data/<pkg>/files/UrlDump`
4. `/storage/emulated/0/Download/UrlDump`
5. `/sdcard/UrlDump`
6. `/data/data/<pkg>/files/UrlDump`
7. `/data/local/tmp/UrlDump`
8. `./UrlDump`

Us directory me:

| File | Contents |
| --- | --- |
| `urls_<pid>.txt` | Human-readable, ek hit per line, saare offsets ke saath |
| `urls_<pid>_offsets.txt` | `module+0xOFF  addr  URL` — offset-first view |
| `urls_<pid>.csv` | Spreadsheet-friendly columns |
| `urls_<pid>.jsonl` | Machine-readable JSON (ek object per hit) |
| `status_<pid>.txt` | Live counters: scans, maps, bytes, URLs, hits, config |

### Runtime config

Pehle maujood config file use hota hai (sab keys optional):

```text
$URLDUMP_CONF
/sdcard/UrlDump/urldump.conf
/storage/emulated/0/UrlDump/urldump.conf
/data/local/tmp/urldump.conf
```

Sample: [`config/urldump.conf.example`](config/urldump.conf.example).

Important keys: `interval`, `chunk_bytes`, `overlap_bytes`, `max_region_bytes`, `min_url_len`, `max_url_len`, `max_urls`, `max_hits_per_url`, `scan_utf16`, `scan_utf32`, `scan_escaped`, `out_dir`. Env `URLDUMP_INTERVAL` bhi interval override karta hai.

### Optional control API (C / dlsym)

Java required nahi — agar host native code hai to `dlsym` se ye functions call kar sakte ho:

```c
void  urldump_scan_now(void);                  // abhi ek scan force karo
int   urldump_is_running(void);                // 1 / 0
void  urldump_set_interval(unsigned seconds);
size_t urldump_status(char *buf, size_t cap);  // one-line counters
void  urldump_flush(void);                     // fsync output files
```

### “No Java dependency”

Runtime library me koi Java class, JNI call ya Java reference nahi. Constructor se apne aap chal jata hai. Target app me load karne ka tareeqa aapka hai:

- APK ke `lib/<abi>/` me `liburldump.so` rakho aur app ke existing native loader se load karo.
- Ya host app me `System.loadLibrary("urldump")` (host code, is library ka dependency nahi).
- Ya rooted device par `LD_PRELOAD`.

## Build

Host suite (static analyzer + tests + CLI):

```sh
cmake -S . -B build-host -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-host -j4
ctest --test-dir build-host --output-on-failure
```

Android runtime library — local / Termux:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
./build.sh
```

GitHub Actions: `main`/`master` par push ya PR par **do jobs** chalte hain — host C++ suite (CMake + ctest) aur Android NDK build (4 ABIs). `liburldump-all.zip` artifact upload hota hai; `v*` tag par ZIP GitHub Release se attach hota hai.

Supported Android ABIs: `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.

## GameGuardian ke saath

`gg/BGMI_SDKOffsets_Dump.lua` (read-only GG script) memory se URLs aur loaded `.so` mappings dump karta hai, aur agar `liburldump.so` load ho to iski `UrlDump/*.txt` output bhi report me include karta hai. Nayi `urls_<pid>_offsets.txt` file seedhe `lib+0xOFF` format me hai — usse GG me search/jump ke liye use kar sakte ho. Script package-agnostic hai: `com.tencent.ig`, `com.pubg.krmobile`, `com.pubg.imobile` ya koi bhi selected target.

## Performance notes

- Default interval 2 second, chunk 1 MB, overlap 1 KB, per-region cap 64 MB, max 20k URLs aur 64 offsets per URL.
- Ek typical scan ~50–200 ms hoti hai (device par depend karta hai). CPU/battery kam rakhne ke liye `interval` badhao ya `max_region_bytes` ghatao.
- Ye **passive** scanner hai: jo URL scan ke waqt memory me hota hai woh milta hai. Turant ban kar free hone wali strings miss ho sakti hain.

## Legal / ethical use

Sirf apne apps ya explicitly authorized test apps par use karein. Ye project sirf local files me URLs likhta hai; na traffic redirect karta hai, na data bahar bhejta hai.

Maintained by **ParallaxDemon**. License: MIT.
