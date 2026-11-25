/**
 * ParallaxUrlDumpNative
 * ---------------------
 * Pure-native Android URL recorder. No Java code, no Java classes, no JNI calls.
 *
 * Drop the resulting liburldump.so into an app's lib/<abi>/ folder and make the app
 * load it once (e.g. via System.loadLibrary("urldump"), LD_PRELOAD on rooted devices,
 * or any existing native loader). From then on every URL observed by the process is
 * appended to a plain-text file on the device.
 *
 * Hooks:
 *   - curl_easy_setopt(CURLOPT_URL) and curl_url_set  -> exact cURL URLs
 *   - getaddrinfo / gethostbyname                     -> DNS hostnames
 *   - SSL_write                                       -> plaintext HTTPS request data
 *   - send / sendto                                   -> plaintext HTTP socket data
 *   - dlopen + /proc/self/maps watcher                -> hooks libraries loaded later
 *
 * Output (first writable path wins):
 *   /storage/emulated/0/Android/data/<pkg>/files/UrlDump/urls_<pid>.txt
 *   /storage/emulated/0/Download/UrlDump/urls_<pkg>_<pid>.txt
 *   /data/data/<pkg>/files/urls_<pid>.txt
 *
 * Legal note: use only on apps you own or are explicitly authorized to test.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "Dobby/dobby.h"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static std::mutex g_file_mutex;
static std::mutex g_hook_mutex;
static std::unordered_set<std::string> g_seen_urls;
static std::unordered_set<void *> g_hooked_addresses;
static int g_out_fd = -1;
static std::string g_out_path;
static std::atomic<bool> g_initialized(false);

// ---------------------------------------------------------------------------
// Original function pointers
// ---------------------------------------------------------------------------

typedef int (*getaddrinfo_fn)(const char *, const char *,
                              const struct addrinfo *, struct addrinfo **);
typedef struct hostent *(*gethostbyname_fn)(const char *);
typedef void *(*dlopen_fn)(const char *, int);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);
typedef void *(*curl_setopt_fn)(void *, int, ...);
typedef int (*curl_url_set_fn)(void *, int, const char *, unsigned int);
typedef int (*ssl_write_fn)(void *, const void *, int);

static getaddrinfo_fn orig_getaddrinfo = nullptr;
static gethostbyname_fn orig_gethostbyname = nullptr;
static dlopen_fn orig_dlopen = nullptr;
static send_fn orig_send = nullptr;
static sendto_fn orig_sendto = nullptr;
static curl_setopt_fn orig_curl_setopt = nullptr;
static curl_url_set_fn orig_curl_url_set = nullptr;
static ssl_write_fn orig_ssl_write = nullptr;

// Forward declarations used by the hook installer.
static void *hooked_curl_setopt(void *, int, ...);
static int hooked_curl_url_set(void *, int, const char *, unsigned int);
static int hooked_ssl_write(void *, const void *, int);

// ---------------------------------------------------------------------------
// File output helpers
// ---------------------------------------------------------------------------

static std::string dirname_of(const std::string &path) {
    size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? std::string(".") : path.substr(0, slash);
}

static bool ensure_dir(const std::string &path) {
    std::string current;
    size_t pos = 0;
    while (pos < path.size()) {
        size_t next = path.find('/', pos);
        if (next == std::string::npos) next = path.size();
        current = path.substr(0, next);
        if (!current.empty() && mkdir(current.c_str(), 0777) != 0 && errno != EEXIST) {
            return false;
        }
        pos = next + 1;
    }
    return true;
}

static std::string package_name() {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "unknown";
    char buffer[512];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n <= 0) return "unknown";
    buffer[n] = '\0';
    return std::string(buffer);
}

/* Caller must hold g_file_mutex. */
static void ensure_output() {
    if (g_out_fd >= 0) return;

    const std::string pkg = package_name();
    const std::string pid = std::to_string(static_cast<long long>(getpid()));

    std::vector<std::string> candidates;
    candidates.push_back("/storage/emulated/0/Android/data/" + pkg +
                         "/files/UrlDump/urls_" + pid + ".txt");
    candidates.push_back("/storage/emulated/0/Download/UrlDump/urls_" +
                         pkg + "_" + pid + ".txt");
    candidates.push_back("/data/data/" + pkg + "/files/urls_" + pid + ".txt");

    for (const std::string &path : candidates) {
        if (!ensure_dir(dirname_of(path))) continue;
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
        if (fd < 0) continue;
        g_out_fd = fd;
        g_out_path = path;

        std::string header =
            "=== ParallaxUrlDumpNative ===\n"
            "pid=" + pid + " pkg=" + pkg +
            " time=" + std::to_string(static_cast<long long>(time(nullptr))) + "\n";
        ssize_t ignored = write(g_out_fd, header.data(), header.size());
        (void)ignored;
        return;
    }
}

static void write_line(const std::string &line) {
    if (g_out_fd < 0) return;
    std::string data = line + "\n";
    ssize_t ignored = write(g_out_fd, data.data(), data.size());
    (void)ignored;
}

static void record_url(const std::string &raw) {
    std::string url = raw;
    while (!url.empty() &&
           (url.back() == '.' || url.back() == ',' || url.back() == ';' ||
            url.back() == ')' || url.back() == ']')) {
        url.pop_back();
    }
    if (url.size() < 8) return;

    std::lock_guard<std::mutex> lock(g_file_mutex);
    if (g_seen_urls.find(url) != g_seen_urls.end()) return;
    ensure_output();
    if (g_out_fd < 0) return;
    g_seen_urls.insert(url);
    write_line(url);
}

// ---------------------------------------------------------------------------
// URL / HTTP parsing
// ---------------------------------------------------------------------------

static std::string extract_host(const std::string &input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(tolower(c)); });

    size_t pos = lower.find("host:");
    if (pos == std::string::npos) return "";

    pos += 5;
    while (pos < input.size() &&
           (input[pos] == ' ' || input[pos] == '\t')) pos++;

    size_t end = pos;
    while (end < input.size() && input[end] != '\r' && input[end] != '\n' &&
           input[end] != ' ' && input[end] != ';') end++;

    if (end > pos && input[pos] == '[' && input[end - 1] == ']') {
        return input.substr(pos + 1, end - pos - 2);
    }
    return input.substr(pos, end - pos);
}

static void record_http_blob(const void *data, size_t len) {
    if (data == nullptr || len == 0) return;
    const size_t n = std::min<size_t>(len, 16384);
    const std::string text(static_cast<const char *>(data), n);

    // Full URLs anywhere in the payload (URL option, JSON body, query string...).
    static const char *schemes[] = {"https://", "http://"};
    for (const char *scheme : schemes) {
        size_t pos = 0;
        const size_t scheme_len = strlen(scheme);
        while ((pos = text.find(scheme, pos)) != std::string::npos) {
            size_t end = text.find_first_of(" \t\r\n\"'<>\\),;", pos);
            if (end == std::string::npos) end = text.size();
            record_url(text.substr(pos, end - pos));
            pos = end == text.size() ? std::string::npos : end + 1;
        }
    }

    const std::string host = extract_host(text);

    // Plain HTTP request line, e.g. GET /api/v1 HTTP/1.1
    static const char *methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "
    };
    for (const char *method : methods) {
        const size_t method_len = strlen(method);
        if (text.rfind(method, 0) != 0) continue;
        size_t space = text.find(' ', method_len);
        if (space == std::string::npos) break;
        std::string path = text.substr(method_len, space - method_len);
        if (!path.empty() && path[0] == '/') {
            record_url("https://" + (host.empty() ? std::string("unknown.host") : host) + path);
        }
        break;
    }

    // Host header alone still reveals the endpoint.
    if (!host.empty()) record_url("https://" + host);
}

static void record_dns_host(const char *node, const char *service) {
    if (node == nullptr || node[0] == '\0') return;
    std::string host(node);
    if (host.find(' ') != std::string::npos) return;
    record_url("https://" + host);
    if (service != nullptr && strcmp(service, "80") == 0) {
        record_url("http://" + host);
    }
}

// ---------------------------------------------------------------------------
// Hook installation
// ---------------------------------------------------------------------------

static void install_hook(void *handle, const char *symbol,
                         void *replacement, void **original) {
    if (handle == nullptr || symbol == nullptr || replacement == nullptr) return;
    void *target = dlsym(handle, symbol);
    if (target == nullptr) return;

    std::lock_guard<std::mutex> lock(g_hook_mutex);
    if (g_hooked_addresses.find(target) != g_hooked_addresses.end()) return;
    if (DobbyHook(target, replacement, original) == 0) {
        g_hooked_addresses.insert(target);
    }
}

static void hook_network_symbols(void *handle) {
    install_hook(handle, "curl_easy_setopt",
                 reinterpret_cast<void *>(hooked_curl_setopt),
                 reinterpret_cast<void **>(&orig_curl_setopt));
    install_hook(handle, "curl_url_set",
                 reinterpret_cast<void *>(hooked_curl_url_set),
                 reinterpret_cast<void **>(&orig_curl_url_set));
    install_hook(handle, "SSL_write",
                 reinterpret_cast<void *>(hooked_ssl_write),
                 reinterpret_cast<void **>(&orig_ssl_write));
}

static std::vector<std::string> loaded_shared_objects() {
    std::vector<std::string> result;
    std::unordered_set<std::string> seen;
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return result;

    char line[1024];
    while (fgets(line, sizeof(line), maps) != nullptr) {
        char *space = strrchr(line, ' ');
        if (space == nullptr) continue;
        std::string path(space + 1);
        while (!path.empty() && (path.back() == '\n' || path.back() == '\r' ||
                                 path.back() == ' ')) {
            path.pop_back();
        }
        if (path.empty() || path[0] == '[' || path.find(".so") == std::string::npos) continue;
        if (seen.insert(path).second) result.push_back(path);
    }
    fclose(maps);
    return result;
}

static void scan_maps_once() {
    for (const std::string &path : loaded_shared_objects()) {
        void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (handle == nullptr &&
            (path.find("libcurl") != std::string::npos ||
             path.find("libssl") != std::string::npos ||
             path.find("boringssl") != std::string::npos ||
             path.find("conscrypt") != std::string::npos)) {
            handle = dlopen(path.c_str(), RTLD_NOW);
        }
        if (handle != nullptr) hook_network_symbols(handle);
    }
}

// ---------------------------------------------------------------------------
// Hooked functions
// ---------------------------------------------------------------------------

static int hooked_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res) {
    record_dns_host(node, service);
    return orig_getaddrinfo != nullptr
               ? orig_getaddrinfo(node, service, hints, res)
               : EAI_SYSTEM;
}

static struct hostent *hooked_gethostbyname(const char *name) {
    record_dns_host(name, nullptr);
    return orig_gethostbyname != nullptr ? orig_gethostbyname(name) : nullptr;
}

static void *hooked_dlopen(const char *filename, int flags) {
    void *handle = orig_dlopen != nullptr ? orig_dlopen(filename, flags) : nullptr;
    if (filename != nullptr && handle != nullptr) scan_maps_once();
    return handle;
}

static ssize_t hooked_send(int fd, const void *buf, size_t len, int flags) {
    record_http_blob(buf, len);
    return orig_send != nullptr ? orig_send(fd, buf, len, flags) : -1;
}

static ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                             const struct sockaddr *addr, socklen_t addrlen) {
    record_http_blob(buf, len);
    return orig_sendto != nullptr ? orig_sendto(fd, buf, len, flags, addr, addrlen) : -1;
}

static void *hooked_curl_setopt(void *curl, int option, ...) {
    va_list args;
    va_start(args, option);
    void *value = va_arg(args, void *);
    va_end(args);

    // CURLOPT_URL == 10002
    if (option == 10002 && value != nullptr) {
        const char *url = static_cast<const char *>(value);
        record_http_blob(url, strlen(url));
    }
    return orig_curl_setopt != nullptr ? orig_curl_setopt(curl, option, value) : nullptr;
}

static int hooked_curl_url_set(void *url_handle, int what,
                               const char *part, unsigned int flags) {
    if (part != nullptr) record_http_blob(part, strlen(part));
    return orig_curl_url_set != nullptr
               ? orig_curl_url_set(url_handle, what, part, flags)
               : 0;
}

static int hooked_ssl_write(void *ssl, const void *buf, int num) {
    if (buf != nullptr && num > 0) record_http_blob(buf, static_cast<size_t>(num));
    return orig_ssl_write != nullptr ? orig_ssl_write(ssl, buf, num) : -1;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

static void *watcher_thread(void *) {
    for (;;) {
        usleep(1500 * 1000);
        scan_maps_once();
    }
    return nullptr;
}

static void init_engine() {
    if (g_initialized.exchange(true)) return;

    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        ensure_output();
    }

    install_hook(RTLD_DEFAULT, "getaddrinfo",
                 reinterpret_cast<void *>(hooked_getaddrinfo),
                 reinterpret_cast<void **>(&orig_getaddrinfo));
    install_hook(RTLD_DEFAULT, "gethostbyname",
                 reinterpret_cast<void *>(hooked_gethostbyname),
                 reinterpret_cast<void **>(&orig_gethostbyname));
    install_hook(RTLD_DEFAULT, "dlopen",
                 reinterpret_cast<void *>(hooked_dlopen),
                 reinterpret_cast<void **>(&orig_dlopen));
    install_hook(RTLD_DEFAULT, "send",
                 reinterpret_cast<void *>(hooked_send),
                 reinterpret_cast<void **>(&orig_send));
    install_hook(RTLD_DEFAULT, "sendto",
                 reinterpret_cast<void *>(hooked_sendto),
                 reinterpret_cast<void **>(&orig_sendto));

    scan_maps_once();

    pthread_t thread;
    if (pthread_create(&thread, nullptr, watcher_thread, nullptr) == 0) {
        pthread_detach(thread);
    }
}

__attribute__((constructor)) static void on_library_load() {
    init_engine();
}

__attribute__((destructor)) static void on_library_unload() {
    std::lock_guard<std::mutex> lock(g_file_mutex);
    if (g_out_fd >= 0) {
        close(g_out_fd);
        g_out_fd = -1;
    }
}
