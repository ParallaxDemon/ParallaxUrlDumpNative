#include "parallax/analyzer.hpp"
#include "parallax/elf.hpp"
#include "parallax/report.hpp"
#include "parallax/xref.hpp"
#include "parallax/zip.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void usage(const char *prog) {
    std::printf(
        "Parallax URL Dumper - native static + runtime URL intelligence\n"
        "Usage: %s <apk|elf|dex|file> [options]\n\n"
        "Options:\n"
        "  -o, --out DIR        report directory (default: parallax-report)\n"
        "      --stem NAME      report file basename (default: target name)\n"
        "      --no-xrefs       skip code-reference analysis\n"
        "      --no-xor         skip single-byte XOR URL scanning\n"
        "      --no-code-built  skip AArch64 code-immediate string reconstruction\n"
        "      --extract        safely extract APK entries into <out>/extracted\n"
        "      --runtime FILE   merge a liburldump urls_*.txt/.csv/.jsonl (repeatable)\n"
        "      --min-len N      minimum URL length (default 8)\n"
        "      --max-len N      maximum URL length (default 512)\n"
        "      --no-utf16       skip UTF-16 strings\n"
        "      --no-utf32       skip UTF-32 strings\n"
        "      --no-escaped     skip escaped (https:\\/\\/) strings\n"
        "  -v, --verbose        print every finding\n"
        "  -h, --help           show this help\n", prog);
}

std::string basename_of(const std::string &path) {
    size_t p = path.find_last_of('/');
    std::string n = p == std::string::npos ? path : path.substr(p + 1);
    size_t dot = n.find_last_of('.');
    return dot == std::string::npos ? n : n.substr(0, dot);
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2 || std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return argc < 2 ? 1 : 0;
    }

    parallax::AnalyzeOptions options;
    std::string target = argv[1];
    std::string out_dir = "parallax-report";
    std::string stem = basename_of(target);
    bool verbose = false;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : std::string(); };
        if (a == "-o" || a == "--out") out_dir = next();
        else if (a == "--stem") stem = next();
        else if (a == "--no-xrefs") options.xrefs = false;
        else if (a == "--no-xor") options.url.scan_xor = false;
        else if (a == "--no-code-built") options.code_built = false;
        else if (a == "--extract") { options.extract_entries = true; options.extract_dir = out_dir + "/extracted"; }
        else if (a == "--runtime") options.runtime_files.push_back(next());
        else if (a == "--min-len") options.url.min_len = static_cast<size_t>(std::strtoul(next().c_str(), nullptr, 0));
        else if (a == "--max-len") options.url.max_len = static_cast<size_t>(std::strtoul(next().c_str(), nullptr, 0));
        else if (a == "--no-utf16") options.url.scan_utf16 = false;
        else if (a == "--no-utf32") options.url.scan_utf32 = false;
        else if (a == "--no-escaped") options.url.scan_escaped = false;
        else if (a == "-v" || a == "--verbose") verbose = true;
        else {
            std::fprintf(stderr, "Unknown option: %s\n", a.c_str());
            usage(argv[0]);
            return 2;
        }
    }
    if (options.extract_entries) options.extract_dir = out_dir + "/extracted";

    std::vector<parallax::Finding> findings = parallax::analyze_path(target, options);

    parallax::ReportOptions report;
    report.target = target;
    report.zip_backend = parallax::zip_backend();
    report.backend = parallax::elf_backend();
    report.xref_backend = parallax::xref_backend(options.xrefs);
    report.code_backend = options.code_built ? parallax::code_built_backend() : "disabled";
    bool ok = parallax::write_reports(findings, out_dir, stem, report);
    if (!ok) std::fprintf(stderr, "warning: could not write all report files to %s\n", out_dir.c_str());

    std::printf("target   : %s\n", target.c_str());
    std::printf("findings : %zu\n", findings.size());
    std::printf("reports  : %s/%s.{json,csv,html}\n", out_dir.c_str(), stem.c_str());
    size_t shown = verbose ? findings.size() : std::min<size_t>(findings.size(), 15);
    for (size_t i = 0; i < shown; ++i) {
        const parallax::Finding &f = findings[i];
        std::printf("  [%s] %s\n      file=%s entry=%s va=%s rva=%s mod=%s runtime=%s enc=%s conf=%.2f\n",
                    parallax::to_string(f.source), f.url.c_str(),
                    parallax::hex(f.file_offset).c_str(),
                    parallax::hex(f.entry_offset).c_str(),
                    parallax::hex(f.va).c_str(), parallax::hex(f.rva).c_str(),
                    parallax::hex(f.module_offset).c_str(),
                    parallax::hex(f.runtime_addr).c_str(), f.encoding.c_str(), f.confidence);
        if (f.xor_key) std::printf("      xor_key=%s\n", parallax::hex(f.xor_key).c_str());
        if (!f.note.empty()) std::printf("      note: %s\n", f.note.c_str());
        for (const std::string &x : f.xrefs) std::printf("      xref: %s\n", x.c_str());
    }
    return ok ? 0 : 3;
}
