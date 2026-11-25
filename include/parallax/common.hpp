#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace parallax {

enum class SourceKind {
    ApkEntry,
    DexString,
    ElfSection,
    NativeModule,
    RuntimeDump,
    RawFile
};

const char *to_string(SourceKind kind);

std::string hex(uint64_t value);

// One observed URL-shaped string with every address space made explicit.
struct Finding {
    std::string url;
    SourceKind source = SourceKind::RawFile;
    std::string source_path;        // APK entry, module, section or file path
    uint64_t entry_offset = 0;      // offset inside the scanned entry/buffer
    uint64_t file_offset = 0;       // offset inside the container file (if known)
    std::string encoding;           // ASCII, UTF16LE, UTF32BE, ESCAPED, ...
    double confidence = 0.5;        // 0..1 heuristic, not a guarantee
    uint64_t va = 0;                // ELF virtual address (when mapped)
    uint64_t rva = 0;               // va - image base
    uint64_t runtime_addr = 0;      // module_base + module_offset (runtime only)
    uint64_t module_base = 0;       // ELF load bias from /proc/self/maps
    uint64_t module_offset = 0;     // ASLR-stable addr - module_base (ELF VA)
    std::string module;
    std::vector<std::string> xrefs;
    uint64_t hits = 1;
    uint64_t first_seen = 0;
    uint64_t last_seen = 0;
};

// Stable identity: same URL at the same place is the same finding.
std::string finding_key(const Finding &f);

std::vector<uint8_t> read_whole_file(const std::string &path, size_t limit = 512u * 1024u * 1024u);
bool write_whole_file(const std::string &path, const std::string &data);

}  // namespace parallax
