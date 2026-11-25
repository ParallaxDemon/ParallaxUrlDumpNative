// Optional LIEF backend (LIEF 0.14+). Enabled with -DPARALLAX_WITH_LIEF=ON.
#include "parallax/elf.hpp"

#if defined(PARALLAX_HAVE_LIEF)
#include <LIEF/ELF.hpp>

#include <memory>

namespace parallax {
namespace {

class LiefElf : public IElfReader {
public:
    explicit LiefElf(std::unique_ptr<LIEF::ELF::Binary> binary) : binary_(std::move(binary)) {
        for (const auto &seg : binary_->segments()) {
            ElfSegment s;
            s.type = static_cast<uint32_t>(seg.type());
            s.flags = static_cast<uint32_t>(seg.flags());
            s.offset = seg.file_offset();
            s.vaddr = seg.virtual_address();
            s.filesz = seg.physical_size();
            s.memsz = seg.virtual_size();
            segments_.push_back(s);
        }
        for (const auto &sec : binary_->sections()) {
            ElfSection s;
            s.name = sec.name();
            s.type = static_cast<uint32_t>(sec.type());
            s.flags = static_cast<uint64_t>(sec.flags());
            s.addr = sec.virtual_address();
            s.offset = sec.offset();
            s.size = sec.size();
            sections_.push_back(s);
        }
        for (const auto &sym : binary_->symbols()) {
            ElfSymbol s;
            s.name = sym.name();
            s.value = sym.value();
            s.size = sym.size();
            symbols_.push_back(s);
        }
        machine_ = static_cast<uint16_t>(binary_->header().machine());
        is64_ = binary_->header().is_64();
    }

    bool valid() const override { return binary_ != nullptr; }
    const std::vector<ElfSection> &sections() const override { return sections_; }
    const std::vector<ElfSegment> &segments() const override { return segments_; }
    const std::vector<ElfSymbol> &symbols() const override { return symbols_; }
    uint16_t machine() const override { return machine_; }
    bool is64() const override { return is64_; }
    std::string backend() const override { return "LIEF"; }

    bool offset_to_va(uint64_t offset, uint64_t &va) const override {
        for (const auto &s : segments_) {
            if (s.type != 1 || s.filesz == 0) continue;
            if (offset >= s.offset && offset - s.offset < s.filesz) {
                va = s.vaddr + (offset - s.offset);
                return true;
            }
        }
        return false;
    }

    bool va_to_offset(uint64_t address, uint64_t &offset) const override {
        for (const auto &s : segments_) {
            if (s.type != 1 || s.filesz == 0) continue;
            if (address >= s.vaddr && address - s.vaddr < s.filesz) {
                offset = s.offset + (address - s.vaddr);
                return true;
            }
        }
        return false;
    }

    std::vector<uint8_t> section_data(const ElfSection &section) const override {
        for (const auto &sec : binary_->sections()) {
            if (sec.name() == section.name) return sec.content();
        }
        return {};
    }

private:
    std::unique_ptr<LIEF::ELF::Binary> binary_;
    std::vector<ElfSection> sections_;
    std::vector<ElfSegment> segments_;
    std::vector<ElfSymbol> symbols_;
    uint16_t machine_ = 0;
    bool is64_ = true;
};

}  // namespace

std::unique_ptr<IElfReader> open_elf_lief(const std::vector<uint8_t> &bytes) {
    if (bytes.size() > 1024u * 1024u * 1024u) return nullptr;
    auto binary = LIEF::ELF::Parser::parse(bytes.data(), bytes.size());
    if (!binary) return nullptr;
    return std::unique_ptr<IElfReader>(new LiefElf(std::move(binary)));
}

}  // namespace parallax

#endif  // PARALLAX_HAVE_LIEF
