#pragma once

#include "parallax/common.hpp"
#include "parallax/url.hpp"

#include <vector>

namespace parallax {

struct AnalyzeOptions {
    UrlScanOptions url;
    bool xrefs = true;
    bool extract_entries = false;
    std::string extract_dir;
    std::vector<std::string> runtime_files;
};

// Dispatcher: APK/ZIP -> entries -> DEX/ELF/raw, standalone ELF, standalone
// DEX, or raw file. All findings share one address/offset vocabulary.
std::vector<Finding> analyze_path(const std::string &path, const AnalyzeOptions &options = {});

}  // namespace parallax
