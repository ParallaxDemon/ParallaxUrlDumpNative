#include "parallax/xref.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <vector>

#if defined(PARALLAX_HAVE_CAPSTONE)
#include <capstone/capstone.h>
#endif

namespace parallax {
namespace {

bool is_executable(const ElfSection &s) { return (s.flags & 4u) != 0 && s.size > 0; }

void append_unique(std::vector<std::string> &list, const std::string &value) {
    if (std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
}

}  // namespace

XrefEngine::XrefEngine(const IElfReader &elf, XrefOptions options)
    : elf_(elf), options_(options) {}

std::string XrefEngine::backend() const {
#if defined(PARALLAX_HAVE_CAPSTONE)
    return options_.use_capstone ? "capstone+raw-pointer" : "raw-pointer";
#else
    return "raw-pointer";
#endif
}

void XrefEngine::annotate(std::vector<Finding> &findings) const {
    std::map<uint64_t, std::vector<size_t>> by_va;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (findings[i].va != 0) by_va[findings[i].va].push_back(i);
    }
    if (by_va.empty()) return;

    for (const ElfSection &sec : elf_.sections()) {
        if (!is_executable(sec) || sec.addr == 0) continue;
        size_t want = static_cast<size_t>(std::min<uint64_t>(sec.size, options_.max_code_bytes_per_section));
        std::vector<uint8_t> code = elf_.section_data(sec);
        if (code.size() > want) code.resize(want);

        // 1) Raw pointer references (works without any disassembler).
        // Build needle tables once, then walk the code a single time per width.
        std::unordered_map<uint32_t, std::vector<size_t>> pointers32;
        std::unordered_map<uint64_t, std::vector<size_t>> pointers64;
        for (const auto &kv : by_va) {
            pointers32[static_cast<uint32_t>(kv.first)] = kv.second;
            pointers64[kv.first] = kv.second;
        }
        for (size_t p = 0; p + 4 <= code.size(); ++p) {
            uint32_t key = static_cast<uint32_t>(code[p]) |
                           (static_cast<uint32_t>(code[p + 1]) << 8) |
                           (static_cast<uint32_t>(code[p + 2]) << 16) |
                           (static_cast<uint32_t>(code[p + 3]) << 24);
            auto it = pointers32.find(key);
            if (it == pointers32.end()) continue;
            std::string ref = sec.name + "+" + hex(p) + ":ptr32";
            for (size_t idx : it->second) append_unique(findings[idx].xrefs, ref);
        }
        for (size_t p = 0; p + 8 <= code.size(); ++p) {
            uint64_t key = 0;
            for (int b = 0; b < 8; ++b) key |= static_cast<uint64_t>(code[p + b]) << (8 * b);
            auto it = pointers64.find(key);
            if (it == pointers64.end()) continue;
            std::string ref = sec.name + "+" + hex(p) + ":ptr64";
            for (size_t idx : it->second) append_unique(findings[idx].xrefs, ref);
        }

#if defined(PARALLAX_HAVE_CAPSTONE)
        if (!options_.use_capstone || code.empty()) continue;
        cs_insn *insn = nullptr;
        csh handle = 0;
        cs_mode mode = CS_MODE_LITTLE_ENDIAN;
        cs_arch arch = CS_ARCH_ARM64;
        switch (elf_.machine()) {
            case 40: arch = CS_ARCH_ARM; mode = static_cast<cs_mode>(CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM); break;  // EM_ARM
            case 183: arch = CS_ARCH_ARM64; mode = CS_MODE_LITTLE_ENDIAN; break;               // EM_AARCH64
            case 3: arch = CS_ARCH_X86; mode = CS_MODE_32; break;     // EM_386
            case 62: arch = CS_ARCH_X86; mode = CS_MODE_64; break;    // EM_X86_64
            default: arch = CS_ARCH_ARM64; break;
        }
        if (cs_open(arch, mode, &handle) != CS_ERR_OK) continue;
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        size_t count = cs_disasm(handle, code.data(), code.size(), sec.addr,
                                 options_.max_instructions_per_section, &insn);
        for (size_t i = 0; i < count; ++i) {
            const cs_insn &in = insn[i];
            std::vector<uint64_t> immediates;
            if (in.detail != nullptr) {
                // CS_ARCH_* are enum values, not preprocessor macros; select
                // the operand union member at runtime so Capstone xrefs really
                // contribute evidence instead of being compiled out.
                if (arch == CS_ARCH_X86) {
                    for (size_t o = 0; o < in.detail->x86.op_count; ++o) {
                        const cs_x86_op &x = in.detail->x86.operands[o];
                        if (x.type == X86_OP_IMM) immediates.push_back(x.imm);
                    }
                } else if (arch == CS_ARCH_ARM64) {
                    for (size_t o = 0; o < in.detail->arm64.op_count; ++o) {
                        const cs_arm64_op &a = in.detail->arm64.operands[o];
                        if (a.type == ARM64_OP_IMM) immediates.push_back(a.imm);
                    }
                } else if (arch == CS_ARCH_ARM) {
                    for (size_t o = 0; o < in.detail->arm.op_count; ++o) {
                        const cs_arm_op &a = in.detail->arm.operands[o];
                        if (a.type == ARM_OP_IMM) immediates.push_back(a.imm);
                    }
                }
            }
            for (uint64_t imm : immediates) {
                auto exact = by_va.find(imm);
                auto page = by_va.lower_bound(imm);
                std::vector<size_t> targets;
                if (exact != by_va.end()) targets = exact->second;
                else if (page != by_va.end() && (*page).first >= imm &&
                         (*page).first - imm < 0x1000) {
                    targets = page->second;
                }
                if (targets.empty()) continue;
                std::string ref = sec.name + "+" + hex(in.address - sec.addr) +
                                  ":" + in.mnemonic;
                for (size_t idx : targets) {
                    append_unique(findings[idx].xrefs, ref);
                    findings[idx].confidence = std::min(1.0, findings[idx].confidence + 0.05);
                }
            }
        }
        if (insn != nullptr) cs_free(insn, count);
        cs_close(&handle);
#endif
    }
}

}  // namespace parallax
