#include "parallax/analyzer.hpp"

#include "parallax/address.hpp"
#include "parallax/dex.hpp"
#include "parallax/elf.hpp"
#include "parallax/obfuscation.hpp"
#include "parallax/report.hpp"
#include "parallax/runtime.hpp"
#include "parallax/zip.hpp"
#include "parallax/xref.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace parallax {
namespace {

bool looks_zip(const std::vector<uint8_t> &b) {
    return b.size() >= 4 && b[0] == 'P' && b[1] == 'K' &&
           (b[2] == 3 || b[2] == 5 || b[2] == 7);
}

bool looks_elf(const std::vector<uint8_t> &b) {
    return b.size() >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F';
}

bool looks_dex(const std::vector<uint8_t> &b) {
    return b.size() >= 4 && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n';
}

bool ends_with(const std::string &s, const char *suffix) {
    size_t n = std::strlen(suffix);
    return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

void merge(std::vector<Finding> &dst, const std::vector<Finding> &src) {
    std::unordered_set<std::string> keys;
    keys.reserve(dst.size());
    for (const Finding &f : dst) keys.insert(finding_key(f));
    for (const Finding &f : src) {
        if (keys.insert(finding_key(f)).second) dst.push_back(f);
    }
}

void scan_elf(const std::vector<uint8_t> &bytes, const std::string &source_path,
              uint64_t file_base, const AnalyzeOptions &options, std::vector<Finding> &out) {
    std::unique_ptr<IElfReader> elf = open_elf(bytes);
    if (!elf) return;
    AddressCalculator addresses(*elf);
    UrlScanner scanner(options.url);
    std::vector<Finding> local;
    for (const ElfSection &sec : elf->sections()) {
        if (sec.size == 0 || sec.type == 8) continue;  // skip SHT_NOBITS
        std::vector<uint8_t> data = elf->section_data(sec);
        if (data.empty()) continue;
        std::vector<Finding> found = scanner.scan(data.data(), data.size(), sec.offset,
                                                  SourceKind::ElfSection,
                                                  source_path + "!" + sec.name, file_base);
        for (Finding &f : found) {
            f.module = source_path;
            addresses.annotate(f);  // va + rva; runtime address stays 0 for static files
        }
        merge(local, found);
    }
    if (options.code_built) {
        std::vector<Finding> rebuilt = scan_code_built_strings(
            *elf, bytes, options.url, source_path, file_base, options.code_built_options);
        for (Finding &f : rebuilt) {
            f.module = source_path;
            addresses.annotate(f);
        }
        // A generic XOR hit on the same blob is only a truncated prefix; the
        // string rebuilt from code immediates is the complete one.
        for (const Finding &r : rebuilt) {
            local.erase(std::remove_if(local.begin(), local.end(), [&](const Finding &f) {
                return f.xor_key != 0 && f.entry_offset == r.entry_offset;
            }), local.end());
        }
        merge(local, rebuilt);
    }
    if (options.xrefs && !local.empty()) {
        XrefEngine xrefs(*elf);
        xrefs.annotate(local);
    }
    merge(out, local);
}

void scan_dex(const std::vector<uint8_t> &bytes, const std::string &source_path,
              uint64_t file_base, const AnalyzeOptions &options, std::vector<Finding> &out) {
    DexReader dex(bytes);
    if (!dex.valid()) return;
    UrlScanner scanner(options.url);
    for (const DexString &s : dex.strings()) {
        if (s.value.empty()) continue;
        std::vector<Finding> found = scanner.scan(
            reinterpret_cast<const uint8_t *>(s.value.data()), s.value.size(),
            s.data_offset, SourceKind::DexString, source_path, file_base);
        for (Finding &f : found) f.confidence = std::min(1.0, f.confidence + 0.08);
        merge(out, found);
    }
}

void scan_raw(const std::vector<uint8_t> &bytes, const std::string &source_path,
              uint64_t file_base, const AnalyzeOptions &options, std::vector<Finding> &out) {
    UrlScanner scanner(options.url);
    merge(out, scanner.scan(bytes.data(), bytes.size(), 0, SourceKind::RawFile,
                            source_path, file_base));
}

}  // namespace

std::vector<Finding> analyze_path(const std::string &path, const AnalyzeOptions &options) {
    std::vector<Finding> results;
    std::vector<uint8_t> bytes = read_whole_file(path);
    if (bytes.empty()) return results;

    if (looks_zip(bytes)) {
        std::unique_ptr<IZipArchive> zip = open_zip(path);
        if (!zip) return results;
        for (const ZipEntry &entry : zip->entries()) {
            if (options.extract_entries) {
                extract_entry_safely(*zip, entry, options.extract_dir);
            }
            std::vector<uint8_t> data;
            if (!zip->read(entry, data) || data.empty()) continue;
            // Offsets are reported inside the uncompressed APK entry. The ZIP
            // local_offset is a container offset and is not meaningful once an
            // entry is deflated, so it is deliberately not mixed in here.
            if (ends_with(entry.name, ".dex")) {
                scan_dex(data, entry.name, 0, options, results);
            } else if (ends_with(entry.name, ".so")) {
                scan_elf(data, entry.name, 0, options, results);
            } else if (!entry.is_directory) {
                scan_raw(data, entry.name, 0, options, results);
            }
        }
    } else if (looks_elf(bytes)) {
        scan_elf(bytes, path, 0, options, results);
    } else if (looks_dex(bytes)) {
        scan_dex(bytes, path, 0, options, results);
    } else {
        scan_raw(bytes, path, 0, options, results);
    }

    for (const std::string &runtime : options.runtime_files) {
        merge(results, parse_runtime_dump(runtime));
    }

    std::sort(results.begin(), results.end(), [](const Finding &a, const Finding &b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.file_offset < b.file_offset;
    });
    return results;
}

}  // namespace parallax
