# ParallaxUrlDumpNative

**Pure-native Android URL recorder — `liburldump.so` only. No Java code, no Java classes, no JNI calls.**

Inspired by the hooking pipeline in [`ParallaxUrlStrenthChecking`](https://github.com/ParallaxDemon/ParallaxUrlStrenthChecking), but redesigned for one job: **record every URL the process touches into a plain `.txt` file on the device.**

---

## What it captures

| Layer | Hook | Captures |
|---|---|---|
| cURL API | `curl_easy_setopt(CURLOPT_URL)`, `curl_url_set` | Exact URLs passed to libcurl |
| DNS libc | `getaddrinfo`, `gethostbyname` | Hostnames even when no cURL is used |
| TLS | `SSL_write` | Plaintext HTTPS request line + `Host` header + URLs inside bodies |
| Plain sockets | `send`, `sendto` | Plaintext HTTP request line + `Host` header + URLs inside bodies |
| Late loads | `dlopen` + `/proc/self/maps` watcher | Libraries loaded after the `.so` starts |

Every captured URL is deduplicated and appended as one line per URL.

## Output file

The first writable path wins (no storage permission needed for the first one):

1. `/storage/emulated/0/Android/data/<package>/files/UrlDump/urls_<pid>.txt`
2. `/storage/emulated/0/Download/UrlDump/urls_<package>_<pid>.txt`
3. `/data/data/<package>/files/urls_<pid>.txt`

The package name and PID are read natively from `/proc/self/cmdline` and `getpid()` — no Android API calls.

Example line:

```text
https://api.example.com/v1/session?token=...
```

## “No Java dependency” — what that means

This repository builds **only a shared object**. The library does not contain, reference, or require any Java class. It is self-starting via `__attribute__((constructor))` the moment the dynamic linker loads it.

To make a target app load it, you still need one of these host-side loading methods (choose whichever you already use):

- Add `liburldump.so` to the APK's `lib/<abi>/` and let your existing native loader load it.
- One `System.loadLibrary("urldump")` call in the host app (this is host code, not a dependency of this project).
- `LD_PRELOAD` on a rooted device.

Nothing in `liburldump.so` calls into Java, and it never modifies or redirects traffic.

## Build locally

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
./build.sh
```

Outputs:

```text
app/src/main/libs/arm64-v8a/liburldump.so
app/src/main/libs/armeabi-v7a/liburldump.so
app/src/main/libs/x86/liburldump.so
app/src/main/libs/x86_64/liburldump.so
```

## Build with GitHub Actions

Push to `main`/`master`, or open a pull request — the workflow downloads Android NDK r25c, builds all four ABIs, and uploads `liburldump-all.zip` as an artifact.

Tag a release (`v1.0`, `v1.1`, ...) and the same ZIP is attached to the GitHub Release automatically.

## Legal / ethical use

Use this **only** on apps you own or are explicitly authorized to test. This project only writes URLs to local storage; it does not bypass SSL, redirect traffic, exfiltrate data, or hide itself.

## Credits

- [Dobby](https://github.com/jmpews/Dobby) inline-hook engine (prebuilt static libraries included per ABI).
- Hook architecture inspired by [ParallaxUrlStrenthChecking](https://github.com/ParallaxDemon/ParallaxUrlStrenthChecking).

Maintained by **ParallaxDemon**.
