#pragma once

#include "parallax/common.hpp"

namespace parallax {

struct UrlScanOptions {
    size_t min_len = 8;
    size_t max_len = 512;
    bool scan_utf16 = true;
    bool scan_utf32 = true;
    bool scan_escaped = true;
};

std::string normalize_url(std::string raw);
bool is_probable_url(const std::string &url, const UrlScanOptions &opts);
double url_confidence(const std::string &url, const std::string &encoding);

// Scans an in-memory buffer and reports a byte-exact offset for every hit.
class UrlScanner {
public:
    explicit UrlScanner(UrlScanOptions options = UrlScanOptions()) : options_(options) {}

    std::vector<Finding> scan(const uint8_t *data, size_t len, uint64_t base_offset,
                              SourceKind kind, const std::string &source_path,
                              uint64_t file_base = 0) const;

private:
    UrlScanOptions options_;
};

}  // namespace parallax
