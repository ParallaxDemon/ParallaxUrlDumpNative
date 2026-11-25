#include "parallax/address.hpp"

#include <algorithm>
#include <limits>

namespace parallax {

AddressCalculator::AddressCalculator(const IElfReader &elf) : elf_(elf) {
    image_base_ = std::numeric_limits<uint64_t>::max();
    for (const ElfSegment &s : elf_.segments()) {
        if (s.type == 1 && s.memsz > 0) image_base_ = std::min(image_base_, s.vaddr);
    }
    if (image_base_ == std::numeric_limits<uint64_t>::max()) image_base_ = 0;
}

bool AddressCalculator::file_offset_to_va(uint64_t offset, uint64_t &va) const {
    return elf_.offset_to_va(offset, va);
}

bool AddressCalculator::va_to_rva(uint64_t va, uint64_t &rva) const {
    if (va < image_base_) return false;
    rva = va - image_base_;
    return true;
}

bool AddressCalculator::rva_to_runtime(uint64_t rva, uint64_t module_base,
                                       uint64_t &runtime) const {
    // module_base is the ELF load bias; an RVA is relative to image_base.
    runtime = module_base + image_base_ + rva;
    return true;
}

bool AddressCalculator::module_offset_to_runtime(uint64_t module_offset,
                                                 uint64_t module_base,
                                                 uint64_t &runtime) const {
    // m_off from liburldump is addr - load_bias, i.e. the ELF virtual address.
    runtime = module_base + module_offset;
    return true;
}

void AddressCalculator::annotate(Finding &finding) const {
    if (finding.va == 0 && file_offset_to_va(finding.file_offset, finding.va)) {
        // derived from file offset
    }
    if (finding.va == 0 && finding.module_offset != 0) finding.va = finding.module_offset;
    if (finding.va != 0) va_to_rva(finding.va, finding.rva);
    if (finding.module_offset == 0 && finding.va != 0) finding.module_offset = finding.va;

    if (finding.module_base != 0) {
        uint64_t offset = finding.module_offset != 0 ? finding.module_offset : finding.va;
        if (offset != 0) {
            module_offset_to_runtime(offset, finding.module_base, finding.runtime_addr);
        } else if (finding.rva != 0) {
            rva_to_runtime(finding.rva, finding.module_base, finding.runtime_addr);
        }
    }
}

std::string AddressCalculator::describe(const Finding &f) const {
    return "file=" + hex(f.file_offset) + " va=" + hex(f.va) + " rva=" + hex(f.rva) +
           " module_offset=" + hex(f.module_offset) + " runtime=" + hex(f.runtime_addr);
}

}  // namespace parallax
