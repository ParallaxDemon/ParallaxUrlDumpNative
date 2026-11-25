#pragma once

#include "parallax/common.hpp"
#include "parallax/elf.hpp"

namespace parallax {

struct XrefOptions {
    bool use_capstone = true;
    size_t max_code_bytes_per_section = 32u * 1024u * 1024u;
    size_t max_instructions_per_section = 200000;
};

inline std::string xref_backend(bool enabled) {
    if (!enabled) return "disabled";
#if defined(PARALLAX_HAVE_CAPSTONE)
    return "capstone+raw-pointer";
#else
    return "raw-pointer";
#endif
}

// Associates string findings with code that references their address.
// Raw pointer scanning always works; Capstone adds instruction-level evidence.
class XrefEngine {
public:
    XrefEngine(const IElfReader &elf, XrefOptions options = XrefOptions());
    void annotate(std::vector<Finding> &findings) const;
    std::string backend() const;

private:
    const IElfReader &elf_;
    XrefOptions options_;
};

}  // namespace parallax
