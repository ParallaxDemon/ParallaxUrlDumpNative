#include "parallax/address.hpp"
#include "parallax/common.hpp"
#include "parallax/dex.hpp"
#include "parallax/elf.hpp"
#include "parallax/report.hpp"
#include "parallax/url.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool ok, const char *name) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}

std::vector<uint8_t> bytes_of(const std::string &s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

class FakeElf : public parallax::IElfReader {
public:
    bool valid() const override { return true; }
    const std::vector<parallax::ElfSection> &sections() const override { return sections_; }
    const std::vector<parallax::ElfSegment> &segments() const override { return segments_; }
    const std::vector<parallax::ElfSymbol> &symbols() const override { return symbols_; }
    uint16_t machine() const override { return 183; }
    bool is64() const override { return true; }
    bool offset_to_va(uint64_t off, uint64_t &va) const override {
        if (off >= 0x1000 && off < 0x1100) { va = 0x20000 + (off - 0x1000); return true; }
        return false;
    }
    bool va_to_offset(uint64_t a, uint64_t &off) const override {
        if (a >= 0x20000 && a < 0x20100) { off = 0x1000 + (a - 0x20000); return true; }
        return false;
    }
    std::vector<uint8_t> section_data(const parallax::ElfSection &) const override { return {}; }
    std::string backend() const override { return "fake"; }

    FakeElf() {
        parallax::ElfSegment s;
        s.type = 1; s.offset = 0x1000; s.vaddr = 0x20000;
        s.filesz = 0x100; s.memsz = 0x100;
        segments_.push_back(s);
    }

private:
    std::vector<parallax::ElfSection> sections_;
    std::vector<parallax::ElfSegment> segments_;
    std::vector<parallax::ElfSymbol> symbols_;
};

}  // namespace

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    // URL scan with exact offsets.
    {
        std::string buf(10, 'X');
        std::string url = "https://ascii.example.com/a";
        size_t offset = buf.size();
        buf += url;
        auto found = parallax::UrlScanner().scan(bytes_of(buf).data(), buf.size(), 0,
            parallax::SourceKind::RawFile, "test");
        bool ok = !found.empty() && found[0].url == url && found[0].entry_offset == offset &&
                  found[0].encoding == "ASCII" && found[0].confidence > 0.6;
        check(ok, "ASCII URL with byte-exact offset");
    }

    // UTF-16LE + escaped URL.
    {
        std::string u = "https://wide.example.net/p";
        std::vector<uint8_t> buf(4, 0x41);
        size_t wide_offset = buf.size();
        for (char c : u) { buf.push_back(static_cast<uint8_t>(c)); buf.push_back(0); }
        size_t esc_offset = buf.size();
        std::string esc = "https:\\/\\/esc.example.org\\/x";
        buf.insert(buf.end(), esc.begin(), esc.end());
        auto found = parallax::UrlScanner().scan(buf.data(), buf.size(), 0,
            parallax::SourceKind::RawFile, "test");
        bool wide = false, escaped = false;
        for (const auto &f : found) {
            if (f.encoding == "UTF16LE" && f.entry_offset == wide_offset && f.url == u) wide = true;
            if (f.encoding == "ESCAPED" && f.entry_offset == esc_offset &&
                f.url == "https://esc.example.org/x") escaped = true;
        }
        check(wide, "UTF-16LE URL with byte-exact offset");
        check(escaped, "escaped URL normalized with byte-exact offset");
    }

    // Big-endian patterns start with zero bytes; anchoring must still work.
    {
        std::string u = "https://be.example/p";
        std::vector<uint8_t> buf(2, 0x41);
        size_t be16_offset = buf.size();
        for (char c : u) { buf.push_back(0); buf.push_back(static_cast<uint8_t>(c)); }
        size_t be32_offset = buf.size();
        for (char c : u) {
            buf.push_back(0); buf.push_back(0); buf.push_back(0);
            buf.push_back(static_cast<uint8_t>(c));
        }
        auto found = parallax::UrlScanner().scan(buf.data(), buf.size(), 0,
            parallax::SourceKind::RawFile, "test");
        bool be16 = false, be32 = false;
        for (const auto &f : found) {
            if (f.encoding == "UTF16BE" && f.entry_offset == be16_offset && f.url == u) be16 = true;
            if (f.encoding == "UTF32BE" && f.entry_offset == be32_offset && f.url == u) be32 = true;
        }
        check(be16, "UTF-16BE URL with byte-exact offset");
        check(be32, "UTF-32BE URL with byte-exact offset");
    }

    check(parallax::normalize_url("https:\\/\\/a.example\\/b&amp;c=1.") ==
              "https://a.example/b&c=1",
          "URL normalization (slashes, entities, trailing dot)");

    // Synthetic DEX with one string.
    {
        std::vector<uint8_t> dex(256, 0);
        const char magic[8] = {'d','e','x','\n','0','3','5','\0'};
        std::memcpy(dex.data(), magic, 8);
        auto put32 = [&](size_t off, uint32_t v) {
            dex[off] = v & 0xff; dex[off+1] = (v >> 8) & 0xff;
            dex[off+2] = (v >> 16) & 0xff; dex[off+3] = (v >> 24) & 0xff;
        };
        put32(32, 256); put32(36, 112); put32(40, 0x12345678);
        put32(56, 1); put32(60, 112); put32(104, 144); put32(108, 112);
        put32(112, 120);
        std::string s = "https://dex.example/path";
        dex[120] = static_cast<uint8_t>(s.size());
        std::memcpy(dex.data() + 121, s.data(), s.size());
        dex[121 + s.size()] = 0;
        parallax::DexReader reader(dex);
        check(reader.valid() && reader.strings().size() == 1 &&
              reader.strings()[0].value == s && reader.strings()[0].data_offset == 120,
              "DEX string_ids / MUTF-8 parser");
    }

    // Address terminology stays separate.
    {
        FakeElf elf;
        parallax::AddressCalculator calc(elf);
        uint64_t va = 0, rva = 0, runtime = 0, direct_runtime = 0;
        const uint64_t bias = 0x7f0000000000ULL;
        bool ok = calc.file_offset_to_va(0x1010, va) && va == 0x20010 &&
                  calc.va_to_rva(va, rva) && rva == 0x10 &&
                  calc.rva_to_runtime(rva, bias, runtime) &&
                  runtime == bias + 0x20000 + 0x10 &&
                  calc.module_offset_to_runtime(va, bias, direct_runtime) &&
                  direct_runtime == bias + va;
        check(ok && calc.image_base() == 0x20000,
              "file offset -> VA -> RVA -> runtime address (image base preserved)");
    }

    // Report serialization.
    {
        parallax::Finding f;
        f.url = "https://report.example/a?b=1";
        f.file_offset = 0x1234;
        f.confidence = 0.91;
        std::vector<parallax::Finding> findings{f};
        std::string json = parallax::to_json(findings);
        std::string csv = parallax::to_csv(findings);
        std::string html = parallax::to_html(findings);
        check(json.find(f.url) != std::string::npos && json.find("\"file_offset\":4660") != std::string::npos,
              "JSON report fields");
        check(csv.find("file_offset") != std::string::npos && csv.find(f.url) != std::string::npos,
              "CSV report fields");
        check(html.find("<table>") != std::string::npos && html.find(f.url) != std::string::npos,
              "HTML report fields");
    }

    std::printf("%s\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
