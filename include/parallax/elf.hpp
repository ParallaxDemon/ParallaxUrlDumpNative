#pragma once

#include "parallax/common.hpp"

#include <memory>
#include <vector>

namespace parallax {

struct ElfSection {
    std::string name;
    uint32_t type = 0;
    uint64_t flags = 0;
    uint64_t addr = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t link = 0;
    uint64_t entsize = 0;
};

struct ElfSegment {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t offset = 0;
    uint64_t vaddr = 0;
    uint64_t filesz = 0;
    uint64_t memsz = 0;
};

struct ElfSymbol {
    std::string name;
    uint64_t value = 0;
    uint64_t size = 0;
    uint16_t section_index = 0;
};

class IElfReader {
public:
    virtual ~IElfReader() = default;
    virtual bool valid() const = 0;
    virtual const std::vector<ElfSection> &sections() const = 0;
    virtual const std::vector<ElfSegment> &segments() const = 0;
    virtual const std::vector<ElfSymbol> &symbols() const = 0;
    virtual uint16_t machine() const = 0;
    virtual bool is64() const = 0;
    virtual bool offset_to_va(uint64_t offset, uint64_t &va) const = 0;
    virtual bool va_to_offset(uint64_t va, uint64_t &offset) const = 0;
    virtual std::vector<uint8_t> section_data(const ElfSection &section) const = 0;
    virtual std::string backend() const = 0;
};

inline const char *elf_backend() {
#if defined(PARALLAX_HAVE_LIEF)
    return "LIEF";
#else
    return "builtin-elf32-elf64";
#endif
}

// LIEF-backed when PARALLAX_HAVE_LIEF is defined, otherwise the built-in
// endian-safe ELF32/ELF64 parser (no external dependency).
std::unique_ptr<IElfReader> open_elf(const std::vector<uint8_t> &bytes);

#if defined(PARALLAX_HAVE_LIEF)
std::unique_ptr<IElfReader> open_elf_lief(const std::vector<uint8_t> &bytes);
#endif

}  // namespace parallax
