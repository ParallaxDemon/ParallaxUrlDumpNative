#include "parallax/obfuscation.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <unordered_map>
#include <unordered_set>

#if defined(PARALLAX_HAVE_CAPSTONE)
#include <capstone/capstone.h>
#endif

namespace parallax {

#if defined(PARALLAX_HAVE_CAPSTONE)
namespace {

std::string trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split_ops(const std::string &s) {
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    for (char c : s) {
        if (c == '[') ++depth;
        if (c == ']') --depth;
        if (c == ',' && depth == 0) {
            out.push_back(trim(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!trim(cur).empty() || out.empty()) out.push_back(trim(cur));
    return out;
}

uint64_t parse_num(const std::string &t) {
    std::string s = trim(t);
    if (!s.empty() && s[0] == '#') s.erase(s.begin());
    bool neg = false;
    if (!s.empty() && s[0] == '-') { neg = true; s.erase(s.begin()); }
    uint64_t v = std::strtoull(s.c_str(), nullptr, 0);
    return neg ? static_cast<uint64_t>(-static_cast<int64_t>(v)) : v;
}

bool is_reg(const std::string &s) {
    if (s.size() < 2 || s.size() > 4) return false;
    if (s[0] != 'x' && s[0] != 'w' && s[0] != 'q' && s[0] != 'v') return false;
    for (size_t i = 1; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    }
    return true;
}

bool parse_mem(const std::string &text, std::string &base, uint64_t &off) {
    std::string s = trim(text);
    if (s.size() < 2 || s.front() != '[' || s.back() != ']') return false;
    std::vector<std::string> parts = split_ops(s.substr(1, s.size() - 2));
    if (parts.empty() || !is_reg(parts[0])) return false;
    base = parts[0];
    off = 0;
    for (size_t i = 1; i < parts.size(); ++i) {
        std::string p = trim(parts[i]);
        if (p.rfind("#", 0) == 0) off += parse_num(p);
    }
    return true;
}

bool read_va(const IElfReader &elf, const std::vector<uint8_t> &bytes,
             uint64_t va, uint8_t *out, size_t n) {
    uint64_t off = 0;
    if (!elf.va_to_offset(va, off)) return false;
    if (off > bytes.size() || n > bytes.size() - off) return false;
    std::memcpy(out, bytes.data() + off, n);
    return true;
}

struct Buffer {
    std::map<uint64_t, uint8_t> bytes;          // offset -> byte
    std::map<uint64_t, uint64_t> src_by_offset; // offset -> file-backed source VA
    std::map<uint64_t, uint64_t> code_by_offset; // offset -> store instruction VA
};

// src_va/code_va are recorded per byte: a later store may overwrite an earlier
// one, and attribution must follow the bytes that actually form the string.
void write_buffer(std::unordered_map<uint64_t, Buffer> &buffers, uint64_t dst, uint64_t off,
                  const uint8_t *data, size_t n, uint64_t code_va, uint64_t src_va) {
    if (off > 65536 || n == 0) return;
    Buffer &b = buffers[dst];
    for (size_t i = 0; i < n && off + i <= 65536; ++i) {
        b.bytes[off + i] = data[i];
        b.src_by_offset[off + i] = src_va;
        b.code_by_offset[off + i] = code_va;
    }
}

bool has_scheme(const std::string &s) {
    static const char *const schemes[] = {"https://", "http://", "wss://", "ws://"};
    for (const char *scheme : schemes) {
        if (s.compare(0, std::strlen(scheme), scheme) == 0) return true;
    }
    return false;
}

std::string xor_name(unsigned key) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "XOR8:%02X+CODE", key);
    return buf;
}

}  // namespace
#endif

std::vector<Finding> scan_code_built_strings(const IElfReader &elf,
                                             const std::vector<uint8_t> &elf_bytes,
                                             const UrlScanOptions &opts,
                                             const std::string &source_path,
                                             uint64_t file_base,
                                             const CodeBuiltOptions &options) {
    std::vector<Finding> out;
#if defined(PARALLAX_HAVE_CAPSTONE)
    if (elf.machine() != 183) return out;  // EM_AARCH64

    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) return out;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    std::unordered_set<std::string> emitted;

    for (const ElfSection &sec : elf.sections()) {
        if ((sec.flags & 4u) == 0 || sec.size == 0) continue;  // executable only
        std::vector<uint8_t> code = elf.section_data(sec);
        if (code.size() > 16u * 1024u * 1024u) code.resize(16u * 1024u * 1024u);
        if (code.empty()) continue;

        cs_insn *insn = nullptr;
        size_t count = cs_disasm(handle, code.data(), code.size(), sec.addr,
                                 options.max_instructions, &insn);

        std::unordered_map<std::string, uint64_t> addr;   // register -> absolute address
        std::unordered_map<std::string, uint64_t> val;    // register -> integer constant
        std::unordered_map<std::string, std::vector<uint8_t>> vec;
        std::unordered_map<std::string, uint64_t> vec_src;
        std::unordered_map<uint64_t, Buffer> buffers;

        for (size_t i = 0; i < count; ++i) {
            const cs_insn &in = insn[i];
            std::string mn = in.mnemonic;
            std::string ops = in.op_str;
            std::vector<std::string> p = split_ops(ops);
            uint64_t at = in.address;

            if (mn == "ret") {
                addr.clear(); val.clear(); vec.clear(); vec_src.clear();
                continue;
            }
            if (mn == "adrp" && p.size() >= 2) {
                addr[p[0]] = parse_num(p[1]);
                val.erase(p[0]);
                continue;
            }
            if (mn == "add" && p.size() >= 3 && is_reg(p[1]) && p[2].rfind("#", 0) == 0) {
                auto it = addr.find(p[1]);
                if (it != addr.end()) addr[p[0]] = it->second + parse_num(p[2]);
                continue;
            }
            if ((mn == "mov" || mn == "movz") && p.size() >= 2) {
                if (p[1].rfind("#", 0) == 0) {
                    val[p[0]] = parse_num(p[1]);
                    addr.erase(p[0]);
                } else if (is_reg(p[1])) {
                    auto vit = val.find(p[1]);
                    if (vit != val.end()) val[p[0]] = vit->second;
                    auto ait = addr.find(p[1]);
                    if (ait != addr.end()) addr[p[0]] = ait->second;
                }
                continue;
            }
            if (mn == "movk" && p.size() >= 2 && p[1].rfind("#", 0) == 0) {
                uint64_t imm = parse_num(p[1]);
                uint64_t shift = 0;
                for (size_t k = 2; k < p.size(); ++k) {
                    std::string t = trim(p[k]);  // e.g. "#16" or "lsl #16"
                    size_t hash = t.find('#');
                    if (hash != std::string::npos) shift = parse_num(t.substr(hash));
                }
                uint64_t mask = 0xffffULL << shift;
                val[p[0]] = (val[p[0]] & ~mask) | ((imm & 0xffffULL) << shift);
                continue;
            }
            if (mn == "ldr" && p.size() >= 2) {
                std::string base; uint64_t off = 0;
                if (parse_mem(p[1], base, off)) {
                    auto it = addr.find(base);
                    if (it != addr.end()) {
                        uint64_t va = it->second + off;
                        if (!p[0].empty() && p[0][0] == 'q') {
                            uint8_t tmp[16];
                            if (read_va(elf, elf_bytes, va, tmp, sizeof(tmp))) {
                                vec[p[0]].assign(tmp, tmp + sizeof(tmp));
                                vec_src[p[0]] = va;
                            }
                        } else {
                            uint8_t tmp[8] = {0};
                            if (read_va(elf, elf_bytes, va, tmp, sizeof(tmp))) {
                                uint64_t v = 0;
                                for (int b = 0; b < 8; ++b) v |= static_cast<uint64_t>(tmp[b]) << (8 * b);
                                val[p[0]] = v;
                                addr.erase(p[0]);
                            }
                        }
                    }
                }
                continue;
            }
            if ((mn == "str" || mn == "strh" || mn == "strb") && p.size() >= 2) {
                std::string base; uint64_t off = 0;
                if (parse_mem(p[1], base, off)) {
                    auto it = addr.find(base);
                    if (it != addr.end()) {
                        uint8_t tmp[16] = {0};
                        size_t n = mn == "strb" ? 1 : mn == "strh" ? 2 :
                                   (!p[0].empty() && p[0][0] == 'w') ? 4 : 8;
                        uint64_t src = 0;
                        if (!p[0].empty() && p[0][0] == 'q') {
                            auto vit = vec.find(p[0]);
                            if (vit == vec.end() || vit->second.size() < 16) continue;
                            std::memcpy(tmp, vit->second.data(), 16);
                            n = 16;
                            auto sit = vec_src.find(p[0]);
                            if (sit != vec_src.end()) src = sit->second;
                        } else {
                            auto vit = val.find(p[0]);
                            if (vit == val.end()) continue;
                            for (size_t b = 0; b < n; ++b) {
                                tmp[b] = static_cast<uint8_t>(vit->second >> (8 * b));
                            }
                        }
                        write_buffer(buffers, it->second, off, tmp, n, at, src);
                    }
                }
                continue;
            }
            if ((mn == "stp" || mn == "ldp") && p.size() >= 3) {
                std::string base; uint64_t off = 0;
                if (parse_mem(p[2], base, off)) {
                    auto it = addr.find(base);
                    if (it != addr.end()) {
                        uint64_t va = it->second + off;
                        size_t unit = (!p[0].empty() && p[0][0] == 'q') ? 16 : 8;
                        for (int r = 0; r < 2; ++r) {
                            const std::string &reg = p[r];
                            if (reg.empty()) continue;
                            if (mn == "stp") {
                                uint8_t tmp[16] = {0};
                                uint64_t src = 0;
                                if (reg[0] == 'q') {
                                    auto vit = vec.find(reg);
                                    if (vit == vec.end() || vit->second.size() < 16) continue;
                                    std::memcpy(tmp, vit->second.data(), 16);
                                    auto sit = vec_src.find(reg);
                                    if (sit != vec_src.end()) src = sit->second;
                                } else {
                                    auto vit = val.find(reg);
                                    if (vit == val.end()) continue;
                                    for (size_t b = 0; b < 8; ++b) {
                                        tmp[b] = static_cast<uint8_t>(vit->second >> (8 * b));
                                    }
                                }
                                write_buffer(buffers, va, unit * static_cast<uint64_t>(r),
                                             tmp, unit, at, src);
                            } else if (reg[0] == 'q') {
                                uint8_t tmp[16];
                                if (read_va(elf, elf_bytes, va + unit * r, tmp, sizeof(tmp))) {
                                    vec[reg].assign(tmp, tmp + sizeof(tmp));
                                    vec_src[reg] = va + unit * r;
                                }
                            } else {
                                uint8_t tmp[8] = {0};
                                if (read_va(elf, elf_bytes, va + unit * r, tmp, sizeof(tmp))) {
                                    uint64_t v = 0;
                                    for (int b = 0; b < 8; ++b) v |= static_cast<uint64_t>(tmp[b]) << (8 * b);
                                    val[reg] = v;
                                }
                            }
                        }
                    }
                }
                continue;
            }
        }

        for (const auto &kv : buffers) {
            const Buffer &b = kv.second;
            if (b.bytes.empty() || b.src_by_offset.empty()) continue;
            auto src_it = b.src_by_offset.find(0);
            uint64_t src_va = src_it == b.src_by_offset.end() ? 0 : src_it->second;
            if (src_va == 0) src_va = b.src_by_offset.begin()->second;
            uint64_t code_va = b.code_by_offset.empty() ? 0 : b.code_by_offset.rbegin()->second;
            uint64_t max_off = b.bytes.rbegin()->first;
            if (max_off > options.max_buffer_bytes) continue;
            std::vector<uint8_t> blob(max_off + 1, 0);
            bool complete = true;
            for (uint64_t o = 0; o <= max_off; ++o) {
                auto it = b.bytes.find(o);
                if (it == b.bytes.end()) { complete = false; break; }
                blob[o] = it->second;
            }
            if (!complete) continue;

            for (unsigned key = 1; key < 256; ++key) {
                std::string decoded;
                for (uint8_t raw : blob) {
                    uint8_t c = static_cast<uint8_t>(raw ^ key);
                    if (c == 0) break;
                    if (c < 0x20 || c >= 0x7f) { decoded.clear(); break; }
                    decoded.push_back(static_cast<char>(c));
                }
                if (!has_scheme(decoded)) continue;
                std::string url = normalize_url(decoded);
                if (!is_probable_url(url, opts)) continue;
                size_t sep = url.find("://");
                std::string rest = sep == std::string::npos ? "" : url.substr(sep + 3);
                std::string host = rest.substr(0, rest.find_first_of("/?#"));
                if (host.find('.') == std::string::npos) continue;

                std::string dedup = std::to_string(src_va) + "|" + url;
                if (!emitted.insert(dedup).second) continue;

                Finding f;
                f.url = url;
                f.source = SourceKind::ElfSection;
                f.source_path = source_path;
                for (const ElfSection &s : elf.sections()) {
                    if (src_va >= s.addr && src_va < s.addr + s.size) {
                        f.source_path = source_path + "!" + s.name;
                        break;
                    }
                }
                uint64_t off = 0;
                if (elf.va_to_offset(src_va, off)) {
                    f.entry_offset = off;
                    f.file_offset = file_base + off;
                } else {
                    f.entry_offset = src_va;
                    f.file_offset = file_base + src_va;
                }
                f.encoding = xor_name(key);
                f.xor_key = static_cast<uint8_t>(key);
                f.confidence = 0.97;
                f.va = src_va;
                f.note = "full URL rebuilt from code immediates at " + hex(code_va) +
                         "; XOR key 0x" + xor_name(key).substr(5, 2) + "; blob VA " + hex(src_va);
                if (code_va != 0) {
                    for (const ElfSection &cs : elf.sections()) {
                        if (code_va >= cs.addr && code_va < cs.addr + cs.size) {
                            f.xrefs.push_back(cs.name + "+" + hex(code_va - cs.addr) +
                                              ":immediate-build");
                            break;
                        }
                    }
                }
                out.push_back(f);
            }
        }

        if (insn != nullptr) cs_free(insn, count);
    }
    cs_close(&handle);
#endif
    return out;
}

}  // namespace parallax
