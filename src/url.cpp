#include "parallax/url.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_set>

namespace parallax {
namespace {

const char *const kSchemes[] = {"https://", "http://", "wss://", "ws://"};
const size_t kSchemeCount = sizeof(kSchemes) / sizeof(kSchemes[0]);

struct Pattern {
    int encoding = 0;
    std::string scheme;
    std::vector<uint8_t> bytes;
    size_t anchor_offset = 0;  // index of the 'h'/'w' byte used for anchoring
};

bool is_url_char(unsigned char c, bool allow_backslash) {
    if (c <= 0x20 || c >= 0x7f) return false;
    if (allow_backslash && c == '\\') return true;
    switch (c) {
        case '"': case '\'': case '<': case '>': case '(': case ')':
        case '[': case ']': case '{': case '}': case ';': case ',':
        case '`': case '|': case '^':
            return false;
        default:
            return true;
    }
}

std::vector<uint8_t> make_pattern(const std::string &scheme, int encoding) {
    std::vector<uint8_t> p;
    switch (encoding) {
        case 0:
            for (char c : scheme) p.push_back(static_cast<uint8_t>(c));
            break;
        case 1:  // UTF-16LE
            for (char c : scheme) { p.push_back(static_cast<uint8_t>(c)); p.push_back(0); }
            break;
        case 2:  // UTF-16BE
            for (char c : scheme) { p.push_back(0); p.push_back(static_cast<uint8_t>(c)); }
            break;
        case 3:  // UTF-32LE
            for (char c : scheme) {
                p.push_back(static_cast<uint8_t>(c)); p.push_back(0); p.push_back(0); p.push_back(0);
            }
            break;
        case 4:  // UTF-32BE
            for (char c : scheme) {
                p.push_back(0); p.push_back(0); p.push_back(0); p.push_back(static_cast<uint8_t>(c));
            }
            break;
        case 5:  // escaped ASCII, e.g. https:\/\/host
            for (char c : scheme) {
                if (c == '/') p.push_back('\\');
                p.push_back(static_cast<uint8_t>(c));
            }
            break;
        default:
            break;
    }
    return p;
}

size_t anchor_offset(const std::vector<uint8_t> &pattern) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] == 'h' || pattern[i] == 'w') return i;
    }
    return 0;
}

const char *encoding_name(int enc) {
    switch (enc) {
        case 1: return "UTF16LE";
        case 2: return "UTF16BE";
        case 3: return "UTF32LE";
        case 4: return "UTF32BE";
        case 5: return "ESCAPED";
        default: return "ASCII";
    }
}

size_t extract_string(const uint8_t *data, size_t len, size_t cur, int encoding,
                      size_t max_len, std::string &out) {
    const size_t step = (encoding == 1 || encoding == 2) ? 2 :
                        (encoding == 3 || encoding == 4) ? 4 : 1;
    const bool allow_backslash = (encoding == 5);
    while (cur + step <= len && out.size() < max_len) {
        unsigned char c = 0;
        bool ok = true;
        if (step == 1) {
            c = data[cur];
        } else if (encoding == 1 || encoding == 3) {
            c = data[cur];
            for (size_t k = 1; k < step; ++k) ok = ok && data[cur + k] == 0;
        } else {
            c = data[cur + step - 1];
            for (size_t k = 0; k + 1 < step; ++k) ok = ok && data[cur + k] == 0;
        }
        if (!ok || !is_url_char(c, allow_backslash)) break;
        out.push_back(static_cast<char>(c));
        cur += step;
    }
    return cur;
}

std::string xor_encoding_name(uint8_t key) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "XOR8:%02X", key);
    return buf;
}

// A single-byte-XOR blob is often packed immediately before a normal ASCII
// string. XOR-decoding that following string produces garbage, so stop when
// the raw bytes start looking like an ordinary printable string (space/colon
// within the first dozen bytes).
bool looks_like_plain_text_boundary(const uint8_t *data, size_t len, size_t pos) {
    size_t printable = 0;
    for (size_t j = 0; j < 12 && pos + j < len; ++j) {
        unsigned char c = data[pos + j];
        if (c < 0x20 || c >= 0x7f) break;
        ++printable;
        if (c == ' ' || c == ':') return printable >= 6;
    }
    return false;
}

size_t extract_string_xor(const uint8_t *data, size_t len, size_t cur, uint8_t key,
                          size_t max_len, std::string &out) {
    while (cur < len && out.size() < max_len) {
        if (looks_like_plain_text_boundary(data, len, cur)) break;
        unsigned char c = static_cast<unsigned char>(data[cur] ^ key);
        if (c == 0 || !is_url_char(c, false)) break;
        out.push_back(static_cast<char>(c));
        ++cur;
    }
    return cur;
}

bool is_ip_literal(const std::string &host) {
    bool digits = false, dots = false;
    for (char c : host) {
        if (c >= '0' && c <= '9') digits = true;
        else if (c == '.') dots = true;
        else if (c != ':') return false;
    }
    return digits && (dots || host.find(':') != std::string::npos);
}

}  // namespace

std::string normalize_url(std::string raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size() && raw[i + 1] == '/') {
            out.push_back('/');
            ++i;
        } else {
            out.push_back(raw[i]);
        }
    }
    raw.swap(out);
    for (;;) {
        size_t p = raw.find("&amp;");
        if (p == std::string::npos) break;
        raw.replace(p, 5, "&");
    }
    while (!raw.empty()) {
        char c = raw.back();
        if (c == '.' || c == ',' || c == ';' || c == ')' || c == ']' ||
            c == '}' || c == '>' || c == '"' || c == '\'' || c == '\\') {
            raw.pop_back();
        } else {
            break;
        }
    }
    return raw;
}

bool is_probable_url(const std::string &url, const UrlScanOptions &opts) {
    if (url.size() < opts.min_len || url.size() > opts.max_len) return false;
    size_t sep = url.find("://");
    if (sep == std::string::npos || sep + 3 >= url.size()) return false;
    unsigned char first = static_cast<unsigned char>(url[sep + 3]);
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
          (first >= '0' && first <= '9') || first == '[' || first == '%')) {
        return false;
    }
    for (unsigned char c : url) {
        if (c <= 0x20 || c >= 0x7f) return false;
    }
    return true;
}

double url_confidence(const std::string &url, const std::string &encoding) {
    double score = 0.62;
    size_t sep = url.find("://");
    std::string scheme = sep == std::string::npos ? "" : url.substr(0, sep);
    std::string rest = sep == std::string::npos ? "" : url.substr(sep + 3);
    std::string host = rest.substr(0, rest.find_first_of("/?#"));
    if (host.find('.') != std::string::npos) score += 0.12;
    if (is_ip_literal(host)) score += 0.08;
    if (rest.find('/') != std::string::npos) score += 0.04;
    if (rest.find('?') != std::string::npos) score += 0.03;
    if (scheme == "https" || scheme == "wss") score += 0.03;
    if (encoding == "UTF16LE" || encoding == "UTF16BE") score += 0.04;
    if (encoding == "UTF32LE" || encoding == "UTF32BE") score += 0.02;
    if (encoding == "ESCAPED") score -= 0.10;
    return std::max(0.0, std::min(1.0, score));
}

std::vector<Finding> UrlScanner::scan(const uint8_t *data, size_t len, uint64_t base_offset,
                                      SourceKind kind, const std::string &source_path,
                                      uint64_t file_base) const {
    std::vector<Finding> results;
    if (data == nullptr || len == 0) return results;

    std::vector<int> encodings = {0};
    if (options_.scan_utf16) { encodings.push_back(1); encodings.push_back(2); }
    if (options_.scan_utf32) { encodings.push_back(3); encodings.push_back(4); }
    if (options_.scan_escaped) encodings.push_back(5);

    std::vector<Pattern> patterns;
    for (size_t s = 0; s < kSchemeCount; ++s) {
        for (int enc : encodings) {
            Pattern p;
            p.encoding = enc;
            p.scheme = kSchemes[s];
            p.bytes = make_pattern(p.scheme, enc);
            if (!p.bytes.empty()) {
                p.anchor_offset = anchor_offset(p.bytes);
                patterns.push_back(p);
            }
        }
    }

    std::unordered_set<std::string> seen;
    size_t i = 0;
    while (i < len) {
        const uint8_t *hp = static_cast<const uint8_t *>(std::memchr(data + i, 'h', len - i));
        const uint8_t *wp = static_cast<const uint8_t *>(std::memchr(data + i, 'w', len - i));
        size_t pos = std::string::npos;
        if (hp != nullptr) pos = static_cast<size_t>(hp - data);
        if (wp != nullptr) {
            size_t wpos = static_cast<size_t>(wp - data);
            if (pos == std::string::npos || wpos < pos) pos = wpos;
        }
        if (pos == std::string::npos) break;

        for (const Pattern &p : patterns) {
            if (pos < p.anchor_offset) continue;
            size_t start = pos - p.anchor_offset;
            if (start + p.bytes.size() > len) continue;
            if (std::memcmp(data + start, p.bytes.data(), p.bytes.size()) != 0) continue;

            std::string raw = p.scheme;
            extract_string(data, len, start + p.bytes.size(), p.encoding,
                           options_.max_len, raw);
            std::string url = normalize_url(raw);
            if (!is_probable_url(url, options_)) continue;

            Finding f;
            f.url = url;
            f.source = kind;
            f.source_path = source_path;
            f.entry_offset = base_offset + start;
            f.file_offset = file_base + f.entry_offset;
            f.encoding = encoding_name(p.encoding);
            f.confidence = url_confidence(url, f.encoding);
            std::string key = f.url + "|" + std::to_string(f.entry_offset);
            if (seen.insert(key).second) results.push_back(f);
        }
        i = pos + 1;
    }
    if (options_.scan_xor) {
        std::vector<Finding> xored = scan_xor(data, len, base_offset, kind, source_path, file_base);
        results.insert(results.end(), xored.begin(), xored.end());
    }
    return results;
}

std::vector<Finding> UrlScanner::scan_xor(const uint8_t *data, size_t len, uint64_t base_offset,
                                          SourceKind kind, const std::string &source_path,
                                          uint64_t file_base) const {
    std::vector<Finding> results;
    if (data == nullptr || len < 8) return results;

    // Tail bytes after the scheme's first character. Deriving the key from the
    // anchor byte lets us test every single-byte key in one linear pass.
    static const char *const kSchemes[4] = {"https://", "http://", "wss://", "ws://"};
    static const char *const kTails[4] = {"ttps://", "ttp://", "ss://", "s://"};

    std::unordered_set<std::string> seen;
    for (size_t i = 0; i + 2 < len; ++i) {
        unsigned char first = data[i];
        if (first == 'h' || first == 'w') continue;  // the plain scanner owns these
        for (size_t s = 0; s < 4; ++s) {
            uint8_t key = static_cast<uint8_t>(first ^ static_cast<unsigned char>(kSchemes[s][0]));
            if (key == 0) continue;
            const char *tail = kTails[s];
            size_t tn = std::strlen(tail);
            if (i + 1 + tn > len) continue;
            bool match = true;
            for (size_t j = 0; j < tn; ++j) {
                if (data[i + 1 + j] != static_cast<uint8_t>(tail[j] ^ key)) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;

            std::string raw = kSchemes[s];
            extract_string_xor(data, len, i + std::strlen(kSchemes[s]), key,
                               options_.max_len, raw);
            std::string url = normalize_url(raw);
            if (!is_probable_url(url, options_)) continue;

            Finding f;
            f.url = url;
            f.source = kind;
            f.source_path = source_path;
            f.entry_offset = base_offset + i;
            f.file_offset = file_base + f.entry_offset;
            f.encoding = xor_encoding_name(key);
            f.xor_key = key;
            f.confidence = std::min(0.90, url_confidence(url, f.encoding) + 0.10);
            f.note = "single-byte XOR " + f.encoding + " decoded at " + hex(f.file_offset);
            std::string dedup = f.url + "|" + std::to_string(f.entry_offset) + "|" + f.encoding;
            if (seen.insert(dedup).second) results.push_back(f);
        }
    }
    return results;
}

}  // namespace parallax
