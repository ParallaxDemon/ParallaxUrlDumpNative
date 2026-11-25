#include "parallax/elf.hpp"

#include "detail/endian.hpp"

#include <algorithm>
#include <cstring>
#include <memory>

namespace parallax {
namespace {

constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint16_t SHN_XINDEX = 0xffff;

class BuiltinElf : public IElfReader {
public:
    explicit BuiltinElf(std::shared_ptr<std::vector<uint8_t>> bytes)
        : bytes_(std::move(bytes)) {
        if (!parse_header()) return;
        parse_segments();
        parse_sections();
        parse_symbols();
    }

    bool valid() const override { return valid_; }
    const std::vector<ElfSection> &sections() const override { return sections_; }
    const std::vector<ElfSegment> &segments() const override { return segments_; }
    const std::vector<ElfSymbol> &symbols() const override { return symbols_; }
    uint16_t machine() const override { return machine_; }
    bool is64() const override { return is64_; }
    std::string backend() const override { return "builtin-elf32-elf64"; }

    bool offset_to_va(uint64_t offset, uint64_t &va) const override {
        for (const ElfSegment &s : segments_) {
            if (s.type != PT_LOAD || s.filesz == 0) continue;
            if (offset >= s.offset && offset - s.offset < s.filesz) {
                va = s.vaddr + (offset - s.offset);
                return true;
            }
        }
        for (const ElfSection &s : sections_) {
            if (s.addr == 0 || s.size == 0) continue;
            if (offset >= s.offset && offset - s.offset < s.size) {
                va = s.addr + (offset - s.offset);
                return true;
            }
        }
        return false;
    }

    bool va_to_offset(uint64_t address, uint64_t &offset) const override {
        for (const ElfSegment &s : segments_) {
            if (s.type != PT_LOAD || s.filesz == 0) continue;
            if (address >= s.vaddr && address - s.vaddr < s.filesz) {
                offset = s.offset + (address - s.vaddr);
                return true;
            }
        }
        for (const ElfSection &s : sections_) {
            if (s.addr == 0 || s.size == 0) continue;
            if (address >= s.addr && address - s.addr < s.size) {
                offset = s.offset + (address - s.addr);
                return true;
            }
        }
        return false;
    }

    std::vector<uint8_t> section_data(const ElfSection &section) const override {
        std::vector<uint8_t> out;
        if (!has(static_cast<size_t>(section.offset), static_cast<size_t>(section.size))) return out;
        const uint8_t *p = bytes_->data() + section.offset;
        return std::vector<uint8_t>(p, p + section.size);
    }

private:
    bool has(size_t off, size_t need) const {
        return off <= bytes_->size() && need <= bytes_->size() - off;
    }
    uint16_t r16(size_t off) const { return be_ ? detail::rd16be(&(*bytes_)[off]) : detail::rd16(&(*bytes_)[off]); }
    uint32_t r32(size_t off) const { return be_ ? detail::rd32be(&(*bytes_)[off]) : detail::rd32(&(*bytes_)[off]); }
    uint64_t r64(size_t off) const { return be_ ? detail::rd64be(&(*bytes_)[off]) : detail::rd64(&(*bytes_)[off]); }
    uint64_t rword(size_t off) const { return is64_ ? r64(off) : r32(off); }

    bool parse_header() {
        if (bytes_->size() < 16) return false;
        const uint8_t *p = bytes_->data();
        if (!(p[0] == 0x7f && p[1] == 'E' && p[2] == 'L' && p[3] == 'F')) return false;
        if (p[4] != 1 && p[4] != 2) return false;
        if (p[5] != 1 && p[5] != 2) return false;
        is64_ = p[4] == 2;
        be_ = p[5] == 2;
        size_t ehsize = is64_ ? 64 : 52;
        if (!has(0, ehsize)) return false;
        machine_ = r16(18);
        if (is64_) {
            phoff_ = r64(32); shoff_ = r64(40);
            phentsize_ = r16(54); phnum_ = r16(56);
            shentsize_ = r16(58); shnum_ = r16(60); shstrndx_ = r16(62);
        } else {
            phoff_ = r32(28); shoff_ = r32(32);
            phentsize_ = r16(42); phnum_ = r16(44);
            shentsize_ = r16(46); shnum_ = r16(48); shstrndx_ = r16(50);
        }
        valid_ = true;
        return true;
    }

    void parse_segments() {
        size_t need = is64_ ? 56 : 32;
        if (phoff_ == 0 || phentsize_ < need || phnum_ == 0 || phnum_ > 65535) return;
        for (size_t i = 0; i < phnum_; ++i) {
            size_t p = static_cast<size_t>(phoff_) + i * phentsize_;
            if (!has(p, need)) break;
            ElfSegment s;
            s.type = r32(p);
            if (is64_) {
                s.flags = r32(p + 4);
                s.offset = r64(p + 8);
                s.vaddr = r64(p + 16);
                s.filesz = r64(p + 32);
                s.memsz = r64(p + 40);
            } else {
                s.offset = r32(p + 4);
                s.vaddr = r32(p + 8);
                s.filesz = r32(p + 16);
                s.memsz = r32(p + 20);
                s.flags = r32(p + 24);
            }
            segments_.push_back(s);
        }
    }

    void parse_sections() {
        size_t need = is64_ ? 64 : 40;
        if (shoff_ == 0 || shentsize_ < need) return;
        uint64_t count = shnum_;
        uint64_t strndx = shstrndx_;
        if (count == 0) {
            if (!has(static_cast<size_t>(shoff_), need)) return;
            count = rword(static_cast<size_t>(shoff_) + (is64_ ? 32 : 20));
        }
        if (count > 100000) return;
        for (uint64_t i = 0; i < count; ++i) {
            size_t p = static_cast<size_t>(shoff_ + i * shentsize_);
            if (!has(p, need)) break;
            ElfSection s;
            s.name = std::to_string(i);
            s.type = r32(p + 4);
            if (is64_) {
                s.flags = r64(p + 8);
                s.addr = r64(p + 16);
                s.offset = r64(p + 24);
                s.size = r64(p + 32);
                s.link = r32(p + 40);
                s.entsize = r64(p + 56);
            } else {
                s.flags = r32(p + 8);
                s.addr = r32(p + 12);
                s.offset = r32(p + 16);
                s.size = r32(p + 20);
                s.link = r32(p + 24);
                s.entsize = r32(p + 36);
            }
            sections_.push_back(s);
        }
        if (strndx == SHN_XINDEX && !sections_.empty()) strndx = sections_[0].link;
        if (strndx >= sections_.size()) return;
        const ElfSection &strtab = sections_[strndx];
        if (!has(static_cast<size_t>(strtab.offset), static_cast<size_t>(strtab.size))) return;
        const char *base = reinterpret_cast<const char *>(bytes_->data() + strtab.offset);
        for (ElfSection &s : sections_) {
            uint64_t idx = 0;
            // Section names were stored as decimal placeholders above; recover
            // the original sh_name by re-reading the header field.
            size_t hp = static_cast<size_t>(shoff_ + (&s - sections_.data()) * shentsize_);
            idx = r32(hp);
            if (idx < strtab.size) {
                const char *start = base + idx;
                size_t max = static_cast<size_t>(strtab.size - idx);
                size_t len = strnlen(start, max);
                s.name.assign(start, len);
            }
        }
    }

    void parse_symbols() {
        for (const ElfSection &sec : sections_) {
            if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM) continue;
            if (sec.link >= sections_.size()) continue;
            const ElfSection &strtab = sections_[sec.link];
            if (!has(static_cast<size_t>(strtab.offset), static_cast<size_t>(strtab.size))) continue;
            size_t entsize = static_cast<size_t>(sec.entsize ? sec.entsize : (is64_ ? 24 : 16));
            size_t need = is64_ ? 24 : 16;
            if (entsize < need) continue;
            const char *names = reinterpret_cast<const char *>(bytes_->data() + strtab.offset);
            for (uint64_t off = 0; off + need <= sec.size; off += entsize) {
                size_t p = static_cast<size_t>(sec.offset + off);
                if (!has(p, need)) break;
                uint32_t name_idx = r32(p);
                ElfSymbol sym;
                if (is64_) {
                    sym.value = r64(p + 8);
                    sym.size = r64(p + 16);
                    sym.section_index = r16(p + 6);
                } else {
                    sym.value = r32(p + 4);
                    sym.size = r32(p + 8);
                    sym.section_index = r16(p + 14);
                }
                if (name_idx < strtab.size) {
                    size_t max = static_cast<size_t>(strtab.size - name_idx);
                    size_t len = strnlen(names + name_idx, max);
                    sym.name.assign(names + name_idx, len);
                }
                symbols_.push_back(sym);
            }
        }
    }

    std::shared_ptr<std::vector<uint8_t>> bytes_;
    bool valid_ = false;
    bool is64_ = true;
    bool be_ = false;
    uint16_t machine_ = 0;
    uint64_t phoff_ = 0, shoff_ = 0;
    uint16_t phentsize_ = 0, phnum_ = 0, shentsize_ = 0, shnum_ = 0, shstrndx_ = 0;
    std::vector<ElfSection> sections_;
    std::vector<ElfSegment> segments_;
    std::vector<ElfSymbol> symbols_;
};

}  // namespace

std::unique_ptr<IElfReader> open_elf(const std::vector<uint8_t> &bytes) {
#if defined(PARALLAX_HAVE_LIEF)
    if (auto lief = open_elf_lief(bytes)) return lief;
#endif
    auto owned = std::make_shared<std::vector<uint8_t>>(bytes);
    std::unique_ptr<IElfReader> reader(new BuiltinElf(owned));
    if (!reader->valid()) return nullptr;
    return reader;
}

}  // namespace parallax
