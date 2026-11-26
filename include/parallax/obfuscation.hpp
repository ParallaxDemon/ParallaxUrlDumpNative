#pragma once

#include "parallax/common.hpp"
#include "parallax/elf.hpp"
#include "parallax/url.hpp"

namespace parallax {

struct CodeBuiltOptions {
    size_t max_instructions = 500000;
    size_t max_buffer_bytes = 1024;
};

inline std::string code_built_backend() {
#if defined(PARALLAX_HAVE_CAPSTONE)
    return "capstone-arm64-immediate-reconstruction";
#else
    return "unavailable";
#endif
}

// Some libraries do not store the whole obfuscated URL in .rodata: they load
// part of it from data and append the rest with mov/movk immediates into a
// global buffer, then XOR-decode before calling curl. This pass follows those
// stores on AArch64 and recovers the complete plaintext URL.
// A no-op when Capstone is unavailable or the ELF is not AArch64.
std::vector<Finding> scan_code_built_strings(const IElfReader &elf,
                                             const std::vector<uint8_t> &elf_bytes,
                                             const UrlScanOptions &opts,
                                             const std::string &source_path,
                                             uint64_t file_base,
                                             const CodeBuiltOptions &options = CodeBuiltOptions());

}  // namespace parallax
