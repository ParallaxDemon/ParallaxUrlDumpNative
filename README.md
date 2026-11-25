# ParallaxUrlDumpNative

**Pure-native, passive URL dumper for Android. Sirf `.txt` — no hooks, no interception, no traffic modification, no Java dependency.**

`liburldump.so` load hote hi ek detached native thread shuru hota hai jo har 2 second par process ki readable memory scan karta hai aur jo bhi URL-looking strings milte hain unhe dedupe karke ek plain text file me append karta hai.

## Kya karta hai

- `/proc/self/maps` se readable mappings nikalta hai.
- `/proc/self/mem` se un mappings ka content padhta hai (direct pointer access nahi, isliye crash kam).
- Har mapping me `https://`, `http://`, `wss://`, `ws://` prefixes dhoondta hai.
- **ASCII/UTF-8 aur UTF-16LE dono** scan karta hai — isliye Java/Kotlin strings, native hardcoded endpoints, cached responses aur JSON bodies pakde jate hain.
- Har unique URL ko line-by-line likh deta hai.

**Kya nahi karta:** koi function hook nahi, cURL/DNS/SSL intercept nahi, URL rewrite/redirect nahi, SSL bypass nahi, network par kuch nahi bhejta.

## Output file

Pehle writable path wins:

1. `/storage/emulated/0/Android/data/<package>/files/UrlDump/urls_<pid>.txt`
2. `/storage/emulated/0/Download/UrlDump/urls_<package>_<pid>.txt`
3. `/data/data/<package>/files/urls_<pid>.txt`

Package name aur PID natively `/proc/self/cmdline` + `getpid()` se aate hain. Koi Android API ya storage permission required nahi (pehla path app-specific hota hai).

## “No Java dependency”

Is repo se sirf `liburldump.so` banta hai. Isme koi Java class, JNI call ya Java reference nahi hai. Constructor se apne aap chal jata hai.

Target app me load karne ka tareeqa aapka hai:

- APK ke `lib/<abi>/` me `liburldump.so` rakho aur app ke existing native loader se load karo.
- Ya host app me ek `System.loadLibrary("urldump")` call (ye host code hai, is library ka dependency nahi).
- Ya rooted device par `LD_PRELOAD`.

## Build

Local:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
./build.sh
```

GitHub Actions: `main`/`master` par push ya PR par automatically 4 ABIs build hote hain aur `liburldump-all.zip` artifact upload hota hai. `v*` tag par ZIP GitHub Release se attach hota hai.

Supported ABIs: `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.

## Limit

Ye **passive** scanner hai — jo URL us waqt memory me maujood hote hain woh pakde jate hain. Agar koi string ban kar turant use ho kar free ho jaye aur scan ke doran memory me na ho, to woh miss ho sakti hai. Isliye scan har 2 second par repeat hota hai.

## Legal / ethical use

Sirf apne apps ya explicitly authorized test apps par use karein. Ye project sirf local file me URLs likhta hai; na traffic redirect karta hai, na data bahar bhejta hai.

Maintained by **ParallaxDemon**. License: MIT.
