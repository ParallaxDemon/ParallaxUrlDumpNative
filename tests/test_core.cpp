#include "parallax/address.hpp"
#include "parallax/common.hpp"
#include "parallax/dex.hpp"
#include "parallax/elf.hpp"
#include "parallax/obfuscation.hpp"
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
    std::vector<uint8_t> section_data(const parallax::ElfSection &s) const override {
        return s.name == ".text" ? code_ : std::vector<uint8_t>();
    }
    std::string backend() const override { return "fake"; }

    void add_section(const parallax::ElfSection &s) { sections_.push_back(s); }
    void set_code(std::vector<uint8_t> code) { code_ = code; }

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
    std::vector<uint8_t> code_;
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

    // AArch64 code-immediate reconstruction: prefix from a data blob, suffix
    // from mov/movk immediates. Gated on the Capstone backend being present.
    {
        bool ok = false;
        if (parallax::code_built_backend() != "unavailable") {
            static const uint8_t code[] = {
                0x08,0x01,0x00,0x90, 0x00,0x01,0xc0,0x3d,
                0x81,0x01,0x00,0x90, 0x21,0x00,0x00,0x91,
                0x20,0x00,0x80,0x3d, 0xaa,0x6b,0x89,0x52,
                0x8a,0x0b,0xab,0x72, 0x2a,0x10,0x00,0xb9,
                0x6b,0x89,0x8b,0x52, 0x2b,0x28,0x00,0x79,
                0xcc,0x05,0x80,0x52, 0x2c,0x58,0x00,0x39,
                0xc0,0x03,0x5f,0xd6
            };
            FakeElf elf;
            elf.set_code(std::vector<uint8_t>(code, code + sizeof(code)));
            parallax::ElfSection text;
            text.name = ".text"; text.type = 1; text.flags = 6;
            text.addr = 0; text.offset = 0; text.size = sizeof(code);
            elf.add_section(text);

            std::vector<uint8_t> image(0x1010, 0);
            const std::string prefix = "https://x.co/abc";
            for (size_t i = 0; i < prefix.size(); ++i) {
                image[0x1000 + i] = static_cast<uint8_t>(prefix[i] ^ 0x2E);
            }
            auto found = parallax::scan_code_built_strings(
                elf, image, parallax::UrlScanOptions(), "synthetic.so", 0);
            for (const auto &f : found) {
                if (f.url == "https://x.co/abcserver" && f.xor_key == 0x2E &&
                    f.encoding == "XOR8:2E+CODE" && f.entry_offset == 0x1000) {
                    ok = true;
                    break;
                }
            }
        } else {
            ok = true;  // documented no-op when Capstone is unavailable
        }
        check(ok, "AArch64 code-immediate URL reconstruction (Capstone-gated)");
    }

    check(parallax::normalize_url("https:\\/\\/a.example\\/b&amp;c=1.") ==
              "https://a.example/b&c=1",
          "URL normalization (slashes, entities, trailing dot)");

    // Single-byte XOR obfuscation: exact offset, recovered key, decode note.
    {
        const std::string plain = "https://xor.example.net/v1/key";
        const uint8_t key = 0x2E;
        std::vector<uint8_t> buf(7, 0x41);
        size_t xor_offset = buf.size();
        for (char c : plain) buf.push_back(static_cast<uint8_t>(c) ^ key);

        auto found = parallax::UrlScanner().scan(buf.data(), buf.size(), 0,
            parallax::SourceKind::RawFile, "test");
        bool ok = false;
        for (const auto &f : found) {
            if (f.url == plain && f.entry_offset == xor_offset &&
                f.encoding == "XOR8:2E" && f.xor_key == key && !f.note.empty()) {
                ok = true;
                break;
            }
        }
        check(ok, "single-byte XOR URL with byte-exact offset, key and note");

        parallax::UrlScanOptions no_xor;
        no_xor.scan_xor = false;
        auto plain_only = parallax::UrlScanner(no_xor).scan(buf.data(), buf.size(), 0,
            parallax::SourceKind::RawFile, "test");
        bool disabled = true;
        for (const auto &f : plain_only) if (f.xor_key != 0) disabled = false;
        check(disabled, "scan_xor=false disables XOR decoding");
    }

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
        f.xor_key = 0x2E;
        f.note = "rebuilt from code immediates at 0xd8758";
        std::vector<parallax::Finding> findings{f};
        std::string json = parallax::to_json(findings);
        std::string csv = parallax::to_csv(findings);
        parallax::ReportOptions report;
        report.code_backend = "capstone-arm64-immediate-reconstruction";
        std::string html = parallax::to_html(findings, report);
        std::string json_with_backend = parallax::to_json(findings, report);
        check(json.find(f.url) != std::string::npos && json.find("\"file_offset\":4660") != std::string::npos,
              "JSON report fields");
        check(csv.find("file_offset") != std::string::npos && csv.find(f.url) != std::string::npos,
              "CSV report fields");
        check(html.find("<table>") != std::string::npos && html.find(f.url) != std::string::npos,
              "HTML report fields");
        check(json.find("xor_key") != std::string::npos &&
                  json.find(f.note) != std::string::npos &&
                  json_with_backend.find("capstone-arm64-immediate-reconstruction") != std::string::npos,
              "JSON XOR evidence and code backend");
        check(csv.find("xor_key,note") != std::string::npos && csv.find(f.note) != std::string::npos,
              "CSV XOR evidence columns");
        check(html.find("detail") != std::string::npos &&
                  html.find(f.note) != std::string::npos &&
                  html.find("capstone-arm64-immediate-reconstruction") != std::string::npos,
              "HTML XOR evidence and code backend");
    }

    std::printf("%s\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
