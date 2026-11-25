#pragma once

#include "parallax/common.hpp"
#include "parallax/elf.hpp"

namespace parallax {

// Keeps file offset, ELF VA, RVA and runtime address as separate values.
// Conversion basis: PT_LOAD segments; image base = lowest PT_LOAD vaddr.
class AddressCalculator {
public:
    explicit AddressCalculator(const IElfReader &elf);

    uint64_t image_base() const { return image_base_; }
    bool file_offset_to_va(uint64_t offset, uint64_t &va) const;
    bool va_to_rva(uint64_t va, uint64_t &rva) const;
    bool rva_to_runtime(uint64_t rva, uint64_t module_base, uint64_t &runtime) const;
    bool module_offset_to_runtime(uint64_t module_offset, uint64_t module_base,
                                  uint64_t &runtime) const;

    // Fills va/rva/module_offset from the best available source. runtime_addr
    // is filled only when the finding carries a runtime module_base.
    void annotate(Finding &finding) const;
    std::string describe(const Finding &finding) const;

private:
    const IElfReader &elf_;
    uint64_t image_base_ = 0;
};

}  // namespace parallax
