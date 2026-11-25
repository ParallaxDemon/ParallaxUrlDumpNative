/**
 * ParallaxUrlDumpNative
 * ---------------------
 * Pure-native, PASSIVE Android URL dumper. No Java code, no JNI calls, no hooks,
 * no interception, no traffic modification.
 *
 * A detached native thread periodically scans readable process mappings via
 * /proc/self/maps + /proc/self/mem and writes every URL-looking string it finds
 * to a plain .txt file on the device.
 *
 * Both ASCII/UTF-8 and UTF-16LE strings are scanned, so Java/Kotlin strings,
 * hardcoded native endpoints, cached responses and JSON bodies are covered.
 *
 * Output (first writable path wins):
 *   /storage/emulated/0/Android/data/<pkg>/files/UrlDump/urls_<pid>.txt
 *   /storage/emulated/0/Download/UrlDump/urls_<pkg>_<pid>.txt
 *   /data/data/<pkg>/files/urls_<pid>.txt
 *
 * Legal note: use only on apps you own or are explicitly authorized to test.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

static const unsigned int SCAN_INTERVAL_SECONDS = 2;
static const size_t MAX_REGION_BYTES = 64u * 1024u * 1024u;

static const char *URL_SCHEMES[] = {
    "https://", "http://", "wss://", "ws://"
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static std::mutex g_file_mutex;
static std::unordered_set<std::string> g_seen_urls;
static int g_out_fd = -1;
static std::atomic<bool> g_started(false);

// ---------------------------------------------------------------------------
// File output
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
        std::string header =
            "=== ParallaxUrlDumpNative (passive memory scan) ===\n"
            "pid=" + pid + " pkg=" + pkg +
            " time=" + std::to_string(static_cast<long long>(time(nullptr))) + "\n";
        ssize_t ignored = write(g_out_fd, header.data(), header.size());
        (void)ignored;
        return;
    }
}

static void record_url(const std::string &raw) {
    std::string url = raw;
    while (!url.empty() &&
           (url.back() == '.' || url.back() == ',' || url.back() == ';' ||
            url.back() == ')' || url.back() == ']' || url.back() == '}' ||
            url.back() == '"' || url.back() == '\'')) {
        url.pop_back();
    }
    if (url.size() < 8) return;

    std::lock_guard<std::mutex> lock(g_file_mutex);
    if (g_seen_urls.find(url) != g_seen_urls.end()) return;
    ensure_output();
    if (g_out_fd < 0) return;
    g_seen_urls.insert(url);

    std::string line = url + "\n";
    ssize_t ignored = write(g_out_fd, line.data(), line.size());
    (void)ignored;
}

// ---------------------------------------------------------------------------
// URL extraction helpers
// ---------------------------------------------------------------------------

static bool is_url_char(unsigned char c) {
    if (c <= 0x20) return false;
    return c != '"' && c != '\'' && c != '<' && c != '>' && c != '\\' &&
           c != '(' && c != ')' && c != '[' && c != ']' && c != '{' &&
           c != '}' && c != ';' && c != ',';
}

static size_t find_bytes(const char *data, size_t len,
                         const std::string &pattern, size_t from) {
    if (pattern.empty() || pattern.size() > len) return std::string::npos;
    for (size_t i = from; i + pattern.size() <= len; ++i) {
        if (memcmp(data + i, pattern.data(), pattern.size()) == 0) return i;
    }
    return std::string::npos;
}

static void scan_ascii(const char *data, size_t len, const std::string &scheme) {
    size_t pos = 0;
    while ((pos = find_bytes(data, len, scheme, pos)) != std::string::npos) {
        std::string url = scheme;
        size_t cur = pos + scheme.size();
        while (cur < len && is_url_char(static_cast<unsigned char>(data[cur]))) {
            url.push_back(data[cur]);
            ++cur;
        }
        record_url(url);
        pos = cur > pos ? cur : pos + 1;
    }
}

static void scan_utf16le(const char *data, size_t len, const std::string &scheme) {
    std::string pattern;
    for (char c : scheme) {
        pattern.push_back(c);
        pattern.push_back('\0');
    }

    size_t pos = 0;
    while ((pos = find_bytes(data, len, pattern, pos)) != std::string::npos) {
        std::string url = scheme;
        size_t cur = pos + pattern.size();
        while (cur + 1 < len) {
            const char low = data[cur];
            const char high = data[cur + 1];
            if (high != '\0') break;
            if (!is_url_char(static_cast<unsigned char>(low))) break;
            url.push_back(low);
            cur += 2;
        }
        record_url(url);
        pos = cur > pos ? cur : pos + 1;
    }
}

static void scan_buffer(const char *data, size_t len) {
    for (const char *scheme : URL_SCHEMES) {
        scan_ascii(data, len, scheme);
        scan_utf16le(data, len, scheme);
    }
}

// ---------------------------------------------------------------------------
// Passive memory scanner
// ---------------------------------------------------------------------------

static void scan_process_memory() {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return;

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0) {
        fclose(maps);
        return;
    }

    std::vector<char> buffer;
    char line[1024];

    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        if (end <= start) continue;

        // Do not pick up the scheme constants compiled into this library.
        if (strstr(line, "liburldump.so") != nullptr) continue;

        size_t region = static_cast<size_t>(end - start);
        if (region > MAX_REGION_BYTES) region = MAX_REGION_BYTES;

        buffer.resize(region);
        ssize_t got = pread(mem_fd, buffer.data(), region, static_cast<off_t>(start));
        if (got > 0) scan_buffer(buffer.data(), static_cast<size_t>(got));
    }

    close(mem_fd);
    fclose(maps);
}

static void *scanner_thread(void *) {
    for (;;) {
        scan_process_memory();
        sleep(SCAN_INTERVAL_SECONDS);
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Lifecycle — no hooks, no Java, just start the scanner
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void on_library_load() {
    if (g_started.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(g_file_mutex);
        ensure_output();
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, scanner_thread, nullptr) == 0) {
        pthread_detach(thread);
    }
}

__attribute__((destructor)) static void on_library_unload() {
    std::lock_guard<std::mutex> lock(g_file_mutex);
    if (g_out_fd >= 0) {
        close(g_out_fd);
        g_out_fd = -1;
    }
}
