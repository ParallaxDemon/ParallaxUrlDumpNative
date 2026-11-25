/**
 * ParallaxUrlDumpNative - ULTRA
 * -----------------------------
 * Pure-native, PASSIVE Android URL dumper with ADDRESS + OFFSET reporting.
 * No Java code, no JNI calls, no hooks, no interception, no traffic changes.
 *
 * A detached native thread periodically walks /proc/self/maps, reads readable
 * regions through /proc/self/mem and extracts URL-looking strings. Every URL is
 * reported together with WHERE IT WAS FOUND:
 *
 *   addr      absolute virtual address of the first byte
 *   r_off     offset inside the /proc/self/maps mapping (addr - map_start)
 *   f_off     file offset inside the mapped file (maps pgoff + r_off)
 *   module    basename of the mapped file (or [anon] / [heap] / [stack])
 *   base      ELF load bias of that module, derived from start - pgoff
 *   m_off     addr - base  ->  ASLR-stable offset, e.g. libUE4.so+0x1A2B3C
 *
 * Encodings: ASCII/UTF-8, UTF-16LE, UTF-16BE, UTF-32LE, UTF-32BE and
 * JSON/Java escaped-slashed URLs (https:\/\/host\/path).
 *
 * Output files (first writable output directory wins):
 *   urls_<pid>.txt            human readable, one hit per line WITH offsets
 *   urls_<pid>_offsets.txt    offset-first view: module+0xOFF  addr  URL
 *   urls_<pid>.csv            machine readable columns
 *   urls_<pid>.jsonl          one JSON object per hit
 *   status_<pid>.txt          live counters / config (rewritten every scan)
 *
 * Runtime config (all optional):
 *   /sdcard/UrlDump/urldump.conf
 *   /data/local/tmp/urldump.conf
 *   $URLDUMP_CONF
 *   env URLDUMP_OUT_DIR, URLDUMP_INTERVAL
 *
 * Legal note: use only on apps you own or are explicitly authorized to test.
 */

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ---------------------------------------------------------------------------
// Configuration (overridable at runtime via urldump.conf / environment)
// ---------------------------------------------------------------------------

// Kept as a POD with constant initialization: the library constructor must be
// able to read defaults before any C++ dynamic initialization has run.
struct Config {
    unsigned int interval_sec;
    size_t max_region_bytes;
    size_t chunk_bytes;
    size_t overlap_bytes;
    size_t min_url_len;
    size_t max_url_len;
    size_t max_urls;
    size_t max_hits_per_url;
    bool scan_utf16;
    bool scan_utf32;
    bool scan_escaped;
    char out_dir[512];
};

static const Config kDefaultConfig = {
    2,
    64u * 1024u * 1024u,
    1024u * 1024u,
    1024u,
    8,
    512,
    20000,
    64,
    true,
    true,
    true,
    {0}
};

static const char *URL_SCHEMES[] = {"https://", "http://", "wss://", "ws://"};
static const size_t URL_SCHEME_COUNT = sizeof(URL_SCHEMES) / sizeof(URL_SCHEMES[0]);

static Config g_cfg = kDefaultConfig;
// POD lock: safe to use even before C++ dynamic initialization runs.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

class LockGuard {
public:
    LockGuard() { pthread_mutex_lock(&g_lock); }
    ~LockGuard() { pthread_mutex_unlock(&g_lock); }
    LockGuard(const LockGuard &) = delete;
    LockGuard &operator=(const LockGuard &) = delete;
};
static std::atomic<bool> g_started(false);
static std::atomic<bool> g_stop(false);
static std::atomic<bool> g_scanning(false);
static pthread_t g_thread;
static bool g_thread_valid = false;

// ---------------------------------------------------------------------------
// Runtime statistics (guarded by g_lock)
// ---------------------------------------------------------------------------

struct Stats {
    unsigned long long scans;
    unsigned long long maps_seen;
    unsigned long long maps_read;
    unsigned long long bytes_read;
    unsigned long long candidates;
    unsigned long long urls;
    unsigned long long hits;
    unsigned long long rejected;
    unsigned long long read_errors;
    unsigned long long last_scan_ms;
    unsigned long long started_at;
    unsigned long long last_scan_at;
    bool cap_warned;
};

static const Stats kZeroStats = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false};

static Stats g_stats = kZeroStats;

// ---------------------------------------------------------------------------
// Finding model
// ---------------------------------------------------------------------------

struct Hit {
    uintptr_t addr = 0;            // absolute virtual address
    uintptr_t region_start = 0;    // /proc/self/maps start
    uintptr_t region_end = 0;      // /proc/self/maps end
    unsigned long long r_off = 0;  // addr - region_start
    unsigned long long f_off = 0;  // maps pgoff + r_off
    std::string perms;
    std::string module;            // basename or [anon]
    uintptr_t module_base = 0;     // 0 when unknown
    unsigned long long m_off = 0;  // addr - module_base (ASLR stable)
    std::string encoding;
    std::string module_full;
    uint64_t first_seen = 0;
    uint64_t last_seen = 0;
};

struct UrlRecord {
    std::vector<Hit> hits;
    std::unordered_set<uintptr_t> hit_addrs;
    unsigned long long observations = 0;
};

// Function-local static: initialized on first use, independent of .init_array.
static std::unordered_map<std::string, UrlRecord> &url_map() {
    static std::unordered_map<std::string, UrlRecord> *map =
        new std::unordered_map<std::string, UrlRecord>();
    return *map;
}

struct Region {
    uintptr_t start = 0;
    uintptr_t end = 0;
    unsigned long long pgoff = 0;
    std::string perms;
    std::string path;       // full path from maps, may be empty
    std::string module;     // basename or [anon]
    uintptr_t module_base = 0;
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

static std::string trim_copy(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

static std::string base_name(const std::string &path) {
    if (path.empty()) return "[anon]";
    size_t slash = path.find_last_of('/');
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    size_t del = name.find(" (deleted)");
    if (del != std::string::npos) name.erase(del);
    return name.empty() ? std::string("[anon]") : name;
}

static uint64_t now_seconds() {
    return static_cast<uint64_t>(time(nullptr));
}

static uint64_t mono_ms() {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
           static_cast<uint64_t>(ts.tv_nsec / 1000000L);
}

static std::string human_time(uint64_t epoch) {
    char buf[32];
    time_t t = static_cast<time_t>(epoch);
    struct tm tm_buf;
    if (localtime_r(&t, &tm_buf) == nullptr) {
        snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(epoch));
    } else {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }
    return std::string(buf);
}

static std::string hex64(uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    static const char *HEX = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(static_cast<char>(c));
        } else if (c < 0x20 || c == 0x7f) {
            out += "\\u00";
            out.push_back(HEX[c >> 4]);
            out.push_back(HEX[c & 0xf]);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

static bool write_all(int fd, const std::string &data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n > 0) {
            off += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static bool ensure_dir(const std::string &path) {
    std::string cur;
    size_t pos = 0;
    while (pos < path.size()) {
        size_t next = path.find('/', pos);
        if (next == std::string::npos) next = path.size();
        cur = path.substr(0, next);
        if (!cur.empty() && mkdir(cur.c_str(), 0777) != 0 && errno != EEXIST) {
            return false;
        }
        pos = next + 1;
    }
    return true;
}

static std::string package_name() {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "unknown";
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "unknown";
    buf[n] = '\0';
    std::string pkg(buf);
    size_t z = pkg.find('\0');
    if (z != std::string::npos) pkg.erase(z);
    return pkg.empty() ? std::string("unknown") : pkg;
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

static size_t parse_size(const std::string &v, size_t fallback) {
    char *end = nullptr;
    unsigned long long n = strtoull(v.c_str(), &end, 0);
    if (end == v.c_str() || n == 0) return fallback;
    return static_cast<size_t>(n);
}

static void apply_config_line(const std::string &line) {
    size_t eq = line.find('=');
    if (eq == std::string::npos) return;
    std::string key = trim_copy(line.substr(0, eq));
    std::string val = trim_copy(line.substr(eq + 1));
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });
    std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });
    if (key == "interval" || key == "interval_sec") {
        g_cfg.interval_sec = static_cast<unsigned int>(parse_size(val, g_cfg.interval_sec));
    } else if (key == "max_region_bytes") {
        g_cfg.max_region_bytes = parse_size(val, g_cfg.max_region_bytes);
    } else if (key == "chunk_bytes") {
        g_cfg.chunk_bytes = parse_size(val, g_cfg.chunk_bytes);
    } else if (key == "overlap_bytes") {
        g_cfg.overlap_bytes = parse_size(val, g_cfg.overlap_bytes);
    } else if (key == "min_url_len") {
        g_cfg.min_url_len = parse_size(val, g_cfg.min_url_len);
    } else if (key == "max_url_len") {
        g_cfg.max_url_len = parse_size(val, g_cfg.max_url_len);
    } else if (key == "max_urls") {
        g_cfg.max_urls = parse_size(val, g_cfg.max_urls);
    } else if (key == "max_hits_per_url") {
        g_cfg.max_hits_per_url = parse_size(val, g_cfg.max_hits_per_url);
    } else if (key == "scan_utf16") {
        g_cfg.scan_utf16 = (val == "1" || val == "true" || val == "yes");
    } else if (key == "scan_utf32") {
        g_cfg.scan_utf32 = (val == "1" || val == "true" || val == "yes");
    } else if (key == "scan_escaped") {
        g_cfg.scan_escaped = (val == "1" || val == "true" || val == "yes");
    } else if (key == "out_dir") {
        snprintf(g_cfg.out_dir, sizeof(g_cfg.out_dir), "%s", val.c_str());
    }
}

static void load_config() {
    std::vector<std::string> paths;
    if (const char *env = getenv("URLDUMP_CONF")) paths.push_back(env);
    paths.push_back("/sdcard/UrlDump/urldump.conf");
    paths.push_back("/storage/emulated/0/UrlDump/urldump.conf");
    paths.push_back("/data/local/tmp/urldump.conf");

    for (const std::string &path : paths) {
        if (path.empty()) continue;
        FILE *f = fopen(path.c_str(), "re");
        if (f == nullptr) continue;
        char line[1024];
        while (fgets(line, sizeof(line), f) != nullptr) {
            std::string s = trim_copy(line);
            if (s.empty() || s[0] == '#' || s[0] == ';') continue;
            apply_config_line(s);
        }
        fclose(f);
        break;  // first existing config wins
    }

    if (const char *env = getenv("URLDUMP_INTERVAL")) {
        g_cfg.interval_sec = static_cast<unsigned int>(parse_size(env, g_cfg.interval_sec));
    }
    if (g_cfg.interval_sec == 0) g_cfg.interval_sec = 1;
    if (g_cfg.chunk_bytes < 4096) g_cfg.chunk_bytes = 4096;
    if (g_cfg.overlap_bytes > g_cfg.chunk_bytes / 2) {
        g_cfg.overlap_bytes = g_cfg.chunk_bytes / 2;
    }
    if (g_cfg.min_url_len < 4) g_cfg.min_url_len = 4;
    if (g_cfg.max_url_len < g_cfg.min_url_len) g_cfg.max_url_len = g_cfg.min_url_len;
}

// ---------------------------------------------------------------------------
// Output files
// ---------------------------------------------------------------------------

enum OutFile { OUT_TXT = 0, OUT_OFF, OUT_CSV, OUT_JSON, OUT_STATUS, OUT_COUNT };

static int g_out_fds[OUT_COUNT] = {-1, -1, -1, -1, -1};
// POD buffers: the library constructor runs before C++ dynamic initialization.
static char g_out_dir[512] = {0};
static char g_pkg[256] = {0};
static char g_pid[32] = {0};
static bool g_headers_written = false;

static std::string output_path(OutFile which) {
    const std::string base = std::string(g_out_dir) + "/";
    const std::string pid(g_pid);
    switch (which) {
        case OUT_TXT: return base + "urls_" + pid + ".txt";
        case OUT_OFF: return base + "urls_" + pid + "_offsets.txt";
        case OUT_CSV: return base + "urls_" + pid + ".csv";
        case OUT_JSON: return base + "urls_" + pid + ".jsonl";
        case OUT_STATUS: return base + "status_" + pid + ".txt";
        default: return base + "urls_" + pid + ".txt";
    }
}

/* Caller must hold g_lock. */
static bool ensure_output() {
    if (g_out_fds[OUT_TXT] >= 0) return true;

    std::vector<std::string> candidates;
    if (const char *env = getenv("URLDUMP_OUT_DIR")) candidates.push_back(env);
    if (g_cfg.out_dir[0]) candidates.push_back(g_cfg.out_dir);
    candidates.push_back(std::string("/storage/emulated/0/Android/data/") + g_pkg + "/files/UrlDump");
    candidates.push_back("/storage/emulated/0/Download/UrlDump");
    candidates.push_back("/sdcard/UrlDump");
    candidates.push_back(std::string("/data/data/") + g_pkg + "/files/UrlDump");
    candidates.push_back("/data/local/tmp/UrlDump");
    candidates.push_back("./UrlDump");

    std::string chosen;
    for (const std::string &dir : candidates) {
        if (dir.empty()) continue;
        if (!ensure_dir(dir)) continue;
        std::string probe = dir + "/.urldump_probe";
        int fd = open(probe.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) continue;
        close(fd);
        unlink(probe.c_str());
        chosen = dir;
        break;
    }
    if (chosen.empty()) return false;
    snprintf(g_out_dir, sizeof(g_out_dir), "%s", chosen.c_str());

    for (int i = 0; i < OUT_COUNT; ++i) {
        g_out_fds[i] = open(output_path(static_cast<OutFile>(i)).c_str(),
                            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    }
    if (g_out_fds[OUT_TXT] < 0) return false;

    std::string started = human_time(g_stats.started_at);
    std::string header =
        "=== ParallaxUrlDumpNative ULTRA v2 | passive memory scan ===\n"
        "pid=" + std::string(g_pid) + " pkg=" + g_pkg + " started=" + started +
        " epoch=" + std::to_string(g_stats.started_at) + "\n"
        "LEGEND: time | URL | addr=absolute VA | region=map range + perms | "
        "r_off=addr-region_start | f_off=region pgoff + r_off | "
        "module=mapped file | base=ELF load bias | m_off=addr-base "
        "(ASLR-stable, use as lib+0xOFF in GameGuardian) | enc=encoding | hits=observations\n"
        "Files: urls_<pid>.txt, urls_<pid>_offsets.txt, urls_<pid>.csv, "
        "urls_<pid>.jsonl, status_<pid>.txt\n";
    write_all(g_out_fds[OUT_TXT], header);

    write_all(g_out_fds[OUT_OFF],
              "# ParallaxUrlDumpNative ULTRA | module+0xOFFSET  ADDR  URL  [encoding]\n");
    write_all(g_out_fds[OUT_CSV],
              "timestamp,url,address,region_start,region_end,perms,r_off,f_off,"
              "module,module_base,m_off,encoding,hits\n");
    g_headers_written = true;
    return true;
}

static void append_hit(const std::string &url, const Hit &h,
                       unsigned long long observations) {
    if (!g_headers_written) return;
    const std::string ts = human_time(h.last_seen);
    const std::string addr = hex64(h.addr);
    const std::string rstart = hex64(h.region_start);
    const std::string rend = hex64(h.region_end);
    const std::string base = h.module_base ? hex64(h.module_base) : std::string("-");
    const std::string roff = hex64(h.r_off);
    const std::string foff = hex64(h.f_off);
    const std::string moff = hex64(h.m_off);

    std::string txt = "[" + ts + "] " + url +
        " | addr=" + addr +
        " region=" + rstart + "-" + rend + " " + h.perms +
        " r_off=" + roff +
        " f_off=" + foff +
        " module=" + h.module +
        " base=" + base +
        " m_off=" + moff +
        " enc=" + h.encoding +
        " hits=" + std::to_string(observations) + "\n";
    write_all(g_out_fds[OUT_TXT], txt);

    std::string off = h.module + "+" + moff + "  " + addr + "  " + url +
        "  [" + h.encoding + " f_off=" + foff + "]\n";
    write_all(g_out_fds[OUT_OFF], off);

    std::string csv = ts + "," + url + "," + addr + "," + rstart + "," + rend +
        "," + h.perms + "," + roff + "," + foff + "," + h.module + "," + base +
        "," + moff + "," + h.encoding + "," +
        std::to_string(observations) + "\n";
    write_all(g_out_fds[OUT_CSV], csv);

    std::string json = "{\"time\":\"" + ts + "\",\"url\":\"" + json_escape(url) +
        "\",\"addr\":\"" + addr + "\",\"region_start\":\"" + rstart +
        "\",\"region_end\":\"" + rend + "\",\"perms\":\"" + h.perms +
        "\",\"r_off\":\"" + roff + "\",\"f_off\":\"" + foff +
        "\",\"module\":\"" + json_escape(h.module) +
        "\",\"module_base\":\"" + base + "\",\"m_off\":\"" + moff +
        "\",\"encoding\":\"" + h.encoding +
        "\",\"hits\":" + std::to_string(observations) +
        ",\"module_path\":\"" + json_escape(h.module_full) + "\"}\n";
    write_all(g_out_fds[OUT_JSON], json);
}

/* Caller must hold g_lock. */
static void write_status() {
    if (!g_headers_written) return;
    int fd = open(output_path(OUT_STATUS).c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return;
    std::string s =
        "=== ParallaxUrlDumpNative ULTRA - live status ===\n"
        "time=" + human_time(now_seconds()) + "\n"
        "pkg=" + std::string(g_pkg) + " pid=" + g_pid + " out_dir=" + g_out_dir + "\n"
        "scans=" + std::to_string(g_stats.scans) +
        " maps_seen=" + std::to_string(g_stats.maps_seen) +
        " maps_read=" + std::to_string(g_stats.maps_read) +
        " bytes_read=" + std::to_string(g_stats.bytes_read) + "\n"
        "candidates=" + std::to_string(g_stats.candidates) +
        " urls=" + std::to_string(g_stats.urls) +
        " hits=" + std::to_string(g_stats.hits) +
        " rejected=" + std::to_string(g_stats.rejected) +
        " read_errors=" + std::to_string(g_stats.read_errors) + "\n"
        "last_scan_ms=" + std::to_string(g_stats.last_scan_ms) +
        " last_scan=" + human_time(g_stats.last_scan_at) + "\n"
        "interval_sec=" + std::to_string(g_cfg.interval_sec) +
        " chunk_bytes=" + std::to_string(g_cfg.chunk_bytes) +
        " overlap_bytes=" + std::to_string(g_cfg.overlap_bytes) +
        " max_region_bytes=" + std::to_string(g_cfg.max_region_bytes) + "\n"
        "min_url_len=" + std::to_string(g_cfg.min_url_len) +
        " max_url_len=" + std::to_string(g_cfg.max_url_len) +
        " max_urls=" + std::to_string(g_cfg.max_urls) +
        " max_hits_per_url=" + std::to_string(g_cfg.max_hits_per_url) + "\n"
        "utf16=" + std::to_string(g_cfg.scan_utf16) +
        " utf32=" + std::to_string(g_cfg.scan_utf32) +
        " escaped=" + std::to_string(g_cfg.scan_escaped) + "\n";
    write_all(fd, s);
    close(fd);
}

// ---------------------------------------------------------------------------
// URL normalization / validation
// ---------------------------------------------------------------------------

static bool is_url_char(unsigned char c, bool allow_backslash) {
    if (c <= 0x20 || c >= 0x7f) return false;
    if (allow_backslash && c == '\\') return true;
    switch (c) {
        case '"': case '\'': case '<': case '>': case '(' : case ')':
        case '[': case ']': case '{': case '}': case ';': case ',':
        case '`': case '|': case '^':
            return false;
        default:
            return true;
    }
}

static std::string normalize_url(std::string u) {
    // JSON / Java escaped slash: https:\/\/example.com\/a
    std::string out;
    out.reserve(u.size());
    for (size_t i = 0; i < u.size(); ++i) {
        if (u[i] == '\\' && i + 1 < u.size() && u[i + 1] == '/') {
            out.push_back('/');
            ++i;
        } else {
            out.push_back(u[i]);
        }
    }
    u.swap(out);
    // HTML entity form of ampersand.
    for (;;) {
        size_t p = u.find("&amp;");
        if (p == std::string::npos) break;
        u.replace(p, 5, "&");
    }
    while (!u.empty()) {
        char c = u.back();
        if (c == '.' || c == ',' || c == ';' || c == ')' || c == ']' ||
            c == '}' || c == '>' || c == '"' || c == '\'' || c == '\\') {
            u.pop_back();
        } else {
            break;
        }
    }
    return u;
}

static bool valid_url(const std::string &u) {
    if (u.size() < g_cfg.min_url_len || u.size() > g_cfg.max_url_len) return false;
    size_t scheme_end = u.find("://");
    if (scheme_end == std::string::npos) return false;
    size_t host = scheme_end + 3;
    if (host >= u.size()) return false;
    unsigned char c = static_cast<unsigned char>(u[host]);
    if (!isalnum(c) && c != '[' && c != '%') return false;
    for (unsigned char ch : u) {
        if (ch <= 0x20 || ch >= 0x7f) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Pattern search
// ---------------------------------------------------------------------------

static std::vector<unsigned char> make_pattern(const std::string &scheme, int encoding) {
    std::vector<unsigned char> p;
    switch (encoding) {
        case 0:  // ASCII / UTF-8
            for (char c : scheme) p.push_back(static_cast<unsigned char>(c));
            break;
        case 1:  // UTF-16LE
            for (char c : scheme) {
                p.push_back(static_cast<unsigned char>(c));
                p.push_back(0);
            }
            break;
        case 2:  // UTF-16BE
            for (char c : scheme) {
                p.push_back(0);
                p.push_back(static_cast<unsigned char>(c));
            }
            break;
        case 3:  // UTF-32LE
            for (char c : scheme) {
                p.push_back(static_cast<unsigned char>(c));
                p.push_back(0);
                p.push_back(0);
                p.push_back(0);
            }
            break;
        case 4:  // UTF-32BE
            for (char c : scheme) {
                p.push_back(0);
                p.push_back(0);
                p.push_back(0);
                p.push_back(static_cast<unsigned char>(c));
            }
            break;
        case 5:  // escaped ASCII: https:\/\/host
            for (char c : scheme) {
                if (c == '/') p.push_back('\\');
                p.push_back(static_cast<unsigned char>(c));
            }
            break;
        default:
            break;
    }
    return p;
}

static const char *encoding_name(int enc) {
    switch (enc) {
        case 1: return "UTF16LE";
        case 2: return "UTF16BE";
        case 3: return "UTF32LE";
        case 4: return "UTF32BE";
        case 5: return "ESCAPED";
        default: return "ASCII";
    }
}

// Extract bytes after a matched pattern, decoding the requested encoding.
// Returns absolute byte offset (relative to buffer start) where extraction stopped.
static size_t extract_string(const unsigned char *data, size_t len, size_t cur,
                             int encoding, std::string &out) {
    const size_t step = (encoding == 1 || encoding == 2) ? 2 :
                        (encoding == 3 || encoding == 4) ? 4 : 1;
    const bool allow_backslash = (encoding == 5);
    while (cur + step <= len && out.size() < g_cfg.max_url_len) {
        unsigned char c = 0;
        bool ok = true;
        if (step == 1) {
            c = data[cur];
        } else if (encoding == 1) {  // LE: low byte then zeros
            c = data[cur];
            for (size_t k = 1; k < step; ++k) ok &= (data[cur + k] == 0);
        } else if (encoding == 2) {  // BE: zeros then low byte
            c = data[cur + step - 1];
            for (size_t k = 0; k + 1 < step; ++k) ok &= (data[cur + k] == 0);
        } else if (encoding == 3) {
            c = data[cur];
            for (size_t k = 1; k < step; ++k) ok &= (data[cur + k] == 0);
        } else {
            c = data[cur + 3];
            for (size_t k = 0; k < 3; ++k) ok &= (data[cur + k] == 0);
        }
        if (!ok || !is_url_char(c, allow_backslash)) break;
        out.push_back(static_cast<char>(c));
        cur += step;
    }
    return cur;
}

// ---------------------------------------------------------------------------
// Recording a candidate hit
// ---------------------------------------------------------------------------

static void record_hit(const std::string &raw, const Region &reg, uintptr_t addr,
                       const char *encoding, uint64_t ts, bool at_buffer_end) {
    (void)at_buffer_end;
    if (++g_stats.candidates == 0) g_stats.candidates = ULLONG_MAX;

    std::string url = normalize_url(raw);
    if (!valid_url(url)) {
        ++g_stats.rejected;
        return;
    }

    LockGuard lock;
    if (!ensure_output()) return;

    auto it = url_map().find(url);
    bool is_new_url = (it == url_map().end());
    if (is_new_url) {
        if (url_map().size() >= g_cfg.max_urls) {
            if (!g_stats.cap_warned) {
                g_stats.cap_warned = true;
                std::string note = "# URL cap (" + std::to_string(g_cfg.max_urls) +
                                   ") reached; new URLs suppressed.\n";
                write_all(g_out_fds[OUT_TXT], note);
            }
            ++g_stats.rejected;
            return;
        }
        it = url_map().emplace(url, UrlRecord()).first;
        ++g_stats.urls;
    }

    UrlRecord &rec = it->second;
    ++rec.observations;
    ++g_stats.hits;

    if (rec.hit_addrs.find(addr) != rec.hit_addrs.end()) {
        // Same physical occurrence seen again; keep the count, avoid duplicate lines.
        return;
    }
    if (rec.hits.size() >= g_cfg.max_hits_per_url) {
        return;
    }

    Hit h;
    h.addr = addr;
    h.region_start = reg.start;
    h.region_end = reg.end;
    h.r_off = static_cast<unsigned long long>(addr - reg.start);
    h.f_off = reg.pgoff + h.r_off;
    h.perms = reg.perms;
    h.module = reg.module;
    h.module_full = reg.path;
    h.module_base = reg.module_base;
    h.m_off = reg.module_base ? static_cast<unsigned long long>(addr - reg.module_base)
                              : h.r_off;
    h.encoding = encoding;
    h.first_seen = ts;
    h.last_seen = ts;

    rec.hit_addrs.insert(addr);
    rec.hits.push_back(h);
    append_hit(url, h, rec.observations);
}

// ---------------------------------------------------------------------------
// Buffer / region scanning
// ---------------------------------------------------------------------------

struct PatternSet {
    int encoding;
    std::string scheme;
    std::vector<unsigned char> bytes;
};

static std::vector<PatternSet> build_patterns() {
    std::vector<PatternSet> sets;
    std::vector<int> encodings = {0};
    if (g_cfg.scan_utf16) {
        encodings.push_back(1);
        encodings.push_back(2);
    }
    if (g_cfg.scan_utf32) {
        encodings.push_back(3);
        encodings.push_back(4);
    }
    if (g_cfg.scan_escaped) encodings.push_back(5);

    for (size_t s = 0; s < URL_SCHEME_COUNT; ++s) {
        for (int enc : encodings) {
            PatternSet ps;
            ps.encoding = enc;
            ps.scheme = URL_SCHEMES[s];
            ps.bytes = make_pattern(ps.scheme, enc);
            if (!ps.bytes.empty()) sets.push_back(ps);
        }
    }
    return sets;
}

static void scan_chunk(const unsigned char *data, size_t len, const Region &reg,
                       uintptr_t chunk_addr, size_t region_total_left,
                       const std::vector<PatternSet> &patterns, uint64_t ts) {
    // Single pass: every scheme starts with 'h' or 'w', so two memchr calls
    // replace one full-buffer search per scheme/encoding combination.
    size_t i = 0;
    while (i < len) {
        const unsigned char *hp = static_cast<const unsigned char *>(
            memchr(data + i, 'h', len - i));
        const unsigned char *wp = static_cast<const unsigned char *>(
            memchr(data + i, 'w', len - i));
        size_t pos = std::string::npos;
        if (hp != nullptr) pos = static_cast<size_t>(hp - data);
        if (wp != nullptr) {
            size_t wpos = static_cast<size_t>(wp - data);
            if (pos == std::string::npos || wpos < pos) pos = wpos;
        }
        if (pos == std::string::npos) break;

        for (const PatternSet &ps : patterns) {
            if (ps.bytes.empty() || ps.bytes[0] != data[pos]) continue;
            if (pos + ps.bytes.size() > len) continue;
            if (memcmp(data + pos, ps.bytes.data(), ps.bytes.size()) != 0) continue;

            std::string raw = ps.scheme;
            size_t end = extract_string(data, len, pos + ps.bytes.size(),
                                        ps.encoding, raw);
            // If extraction stops exactly at the read-ahead boundary and more
            // region data follows, let the next chunk record the full string.
            bool truncated = (end == len) && (region_total_left > len);
            if (!truncated) {
                record_hit(raw, reg, chunk_addr + pos,
                           encoding_name(ps.encoding), ts, truncated);
            }
        }
        i = pos + 1;
    }
}

static bool read_fully(int fd, unsigned char *dst, size_t want, uintptr_t addr,
                       size_t &got) {
    got = 0;
    while (got < want) {
        ssize_t n = pread(fd, dst + got, want - got, static_cast<off_t>(addr + got));
        if (n > 0) {
            got += static_cast<size_t>(n);
        } else if (n == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return got > 0;
}

static void scan_region(int mem_fd, const Region &reg,
                        const std::vector<PatternSet> &patterns, uint64_t ts) {
    size_t span = static_cast<size_t>(reg.end - reg.start);
    if (span > g_cfg.max_region_bytes) span = g_cfg.max_region_bytes;
    if (span == 0) return;

    const size_t overlap = std::min(g_cfg.overlap_bytes, span);
    std::vector<unsigned char> buffer(g_cfg.chunk_bytes + overlap);

    size_t done = 0;
    while (done < span) {
        size_t want = std::min(g_cfg.chunk_bytes, span - done);
        size_t remaining_after = span - done - want;
        size_t read_len = want + (remaining_after > 0 ? overlap : 0);
        size_t got = 0;
        bool ok = read_fully(mem_fd, buffer.data(), read_len, reg.start + done, got);
        if (!ok) {
            ++g_stats.read_errors;
            break;
        }
        {
            LockGuard lock;
            g_stats.bytes_read += got;
            ++g_stats.maps_read;
        }
        if (got > 0) {
            scan_chunk(buffer.data(), got, reg, reg.start + done,
                       remaining_after, patterns, ts);
        }
        done += want;
    }
}

static std::vector<Region> read_regions() {
    std::vector<Region> regions;
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return regions;

    char line[2048];
    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long long start = 0, end = 0, pgoff = 0, inode = 0;
        char perms[16] = {0}, dev[64] = {0};
        int used = 0;
        int n = sscanf(line, "%llx-%llx %15s %llx %63s %llu %n",
                       &start, &end, perms, &pgoff, dev, &inode, &used);
        if (n < 5 || end <= start) continue;

        Region r;
        r.start = static_cast<uintptr_t>(start);
        r.end = static_cast<uintptr_t>(end);
        r.pgoff = pgoff;
        r.perms = perms;
        if (used > 0) {
            while (line[used] == ' ' || line[used] == '\t') ++used;
            std::string p = trim_copy(line + used);
            r.path = p;
        }

        // Never scan our own code/constants: the scheme literals live here.
        uintptr_t self = reinterpret_cast<uintptr_t>(&read_regions);
        if (r.start <= self && self < r.end) continue;
        if (r.path.find("liburldump") != std::string::npos) continue;
        if (perms[0] != 'r') continue;

        r.module = r.path.empty() ? std::string("[anon]") : base_name(r.path);

        // Module load bias: for every mapping of a real ELF file, start - pgoff
        // is the ASLR load bias. Taking the minimum across mappings is robust.
        // Pseudo mappings ([heap], [stack], [anon:...]) are not ELF files: for
        // those we keep m_off == r_off, which is the meaningful offset.
        const bool is_elf_path = !r.path.empty() && r.path[0] != '[' &&
                                 r.path.find('/') != std::string::npos;
        static std::unordered_map<std::string, uintptr_t> bases;
        if (is_elf_path && pgoff <= start) {
            uintptr_t bias = r.start - static_cast<uintptr_t>(pgoff);
            auto it = bases.find(r.path);
            if (it == bases.end() || bias < it->second) {
                bases[r.path] = bias;
                for (Region &prev : regions) {
                    if (prev.path == r.path) prev.module_base = bias;
                }
                r.module_base = bias;
            } else {
                r.module_base = it->second;
            }
        }
        regions.push_back(r);
    }
    fclose(maps);
    return regions;
}

static void scan_process_memory() {
    bool expected = false;
    if (!g_scanning.compare_exchange_strong(expected, true)) return;

    const uint64_t ts = now_seconds();
    const uint64_t t0 = mono_ms();
    std::vector<Region> regions = read_regions();

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd >= 0) {
        std::vector<PatternSet> patterns = build_patterns();
        for (const Region &r : regions) {
            {
                LockGuard lock;
                ++g_stats.maps_seen;
            }
            scan_region(mem_fd, r, patterns, ts);
        }
        close(mem_fd);
    } else {
        LockGuard lock;
        ++g_stats.read_errors;
    }

    {
        LockGuard lock;
        g_stats.scans++;
        g_stats.last_scan_at = ts;
        g_stats.last_scan_ms = mono_ms() - t0;
        write_status();
    }
    g_scanning.store(false);
}

// ---------------------------------------------------------------------------
// Public control API (optional; dlsym-able, still no Java dependency)
// ---------------------------------------------------------------------------

extern "C" __attribute__((visibility("default")))
void urldump_scan_now() {
    scan_process_memory();
}

extern "C" __attribute__((visibility("default")))
int urldump_is_running() {
    return g_started.load() && !g_stop.load() ? 1 : 0;
}

extern "C" __attribute__((visibility("default")))
void urldump_set_interval(unsigned int seconds) {
    LockGuard lock;
    g_cfg.interval_sec = seconds ? seconds : 1;
    write_status();
}

extern "C" __attribute__((visibility("default")))
size_t urldump_status(char *buf, size_t cap) {
    if (buf == nullptr || cap == 0) return 0;
    LockGuard lock;
    int n = snprintf(buf, cap,
                     "running=%d scans=%llu urls=%llu hits=%llu "
                     "bytes=%llu errors=%llu out_dir=%s\n",
                     urldump_is_running(), g_stats.scans, g_stats.urls,
                     g_stats.hits, g_stats.bytes_read, g_stats.read_errors,
                     g_out_dir);
    return n < 0 ? 0 : static_cast<size_t>(n);
}

extern "C" __attribute__((visibility("default")))
void urldump_flush() {
    LockGuard lock;
    for (int i = 0; i < OUT_COUNT; ++i) {
        if (g_out_fds[i] >= 0) fsync(g_out_fds[i]);
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

static void *scanner_thread(void *) {
    while (!g_stop.load()) {
        scan_process_memory();
        for (unsigned int i = 0; i < g_cfg.interval_sec && !g_stop.load(); ++i) {
            sleep(1);
        }
    }
    return nullptr;
}

__attribute__((constructor)) static void on_library_load() {
    if (g_started.exchange(true)) return;
    g_stats.started_at = now_seconds();
    load_config();
    snprintf(g_pkg, sizeof(g_pkg), "%s", package_name().c_str());
    snprintf(g_pid, sizeof(g_pid), "%lld", static_cast<long long>(getpid()));
    // Single-threaded here: no need to touch g_lock before its dynamic init.
    ensure_output();
    write_status();
    if (pthread_create(&g_thread, nullptr, scanner_thread, nullptr) == 0) {
        g_thread_valid = true;
    }
}

__attribute__((destructor)) static void on_library_unload() {
    g_stop.store(true);
    if (g_thread_valid) {
        pthread_join(g_thread, nullptr);
        g_thread_valid = false;
    }
    LockGuard lock;
    write_status();
    for (int i = 0; i < OUT_COUNT; ++i) {
        if (g_out_fds[i] >= 0) {
            close(g_out_fds[i]);
            g_out_fds[i] = -1;
        }
    }
}
