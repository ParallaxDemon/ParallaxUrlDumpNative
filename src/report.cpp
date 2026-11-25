#include "parallax/report.hpp"

#if defined(PARALLAX_HAVE_NLOHMANN_JSON)
#include <nlohmann/json.hpp>
#endif

#include <algorithm>
#include <cstdio>
#include <sys/stat.h>
#include <cerrno>

namespace parallax {
namespace {

std::string escape_json(const std::string &s) {
    std::string out;
    static const char *HEX = "0123456789abcdef";
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(HEX[c >> 4]);
                    out.push_back(HEX[c & 0xf]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string escape_html(const std::string &s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

std::string csv_cell(const std::string &s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out += "\"";
    return out;
}

bool ensure_dir(const std::string &path) {
    std::string cur;
    size_t pos = 0;
    while (pos < path.size()) {
        size_t next = path.find('/', pos);
        if (next == std::string::npos) next = path.size();
        cur = path.substr(0, next);
        if (!cur.empty() && mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
        pos = next + 1;
    }
    return true;
}

}  // namespace

std::string to_json(const std::vector<Finding> &findings, const ReportOptions &options) {
#if defined(PARALLAX_HAVE_NLOHMANN_JSON)
    nlohmann::json root;
    root["tool"] = options.title;
    root["target"] = options.target;
    root["zip_backend"] = options.zip_backend;
    root["elf_backend"] = options.backend;
    root["xref_backend"] = options.xref_backend;
    root["count"] = findings.size();
    root["findings"] = nlohmann::json::array();
    for (const Finding &f : findings) {
        nlohmann::json j;
        j["url"] = f.url;
        j["source"] = to_string(f.source);
        j["source_path"] = f.source_path;
        j["entry_offset"] = f.entry_offset;
        j["file_offset"] = f.file_offset;
        j["encoding"] = f.encoding;
        j["confidence"] = f.confidence;
        j["va"] = f.va;
        j["rva"] = f.rva;
        j["module_offset"] = f.module_offset;
        j["runtime_addr"] = f.runtime_addr;
        j["module"] = f.module;
        j["xrefs"] = f.xrefs;
        root["findings"].push_back(j);
    }
    return root.dump(2) + "\n";
#else
    std::string out = "{\n  \"tool\": \"" + escape_json(options.title) + "\",\n" +
                      "  \"target\": \"" + escape_json(options.target) + "\",\n" +
                      "  \"zip_backend\": \"" + escape_json(options.zip_backend) + "\",\n" +
                      "  \"elf_backend\": \"" + escape_json(options.backend) + "\",\n" +
                      "  \"xref_backend\": \"" + escape_json(options.xref_backend) + "\",\n" +
                      "  \"count\": " + std::to_string(findings.size()) + ",\n" +
                      "  \"findings\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const Finding &f = findings[i];
        char conf[32];
        std::snprintf(conf, sizeof(conf), "%.3f", f.confidence);
        out += "    {\"url\":\"" + escape_json(f.url) + "\",\"source\":\"" +
               to_string(f.source) + "\",\"source_path\":\"" + escape_json(f.source_path) +
               "\",\"entry_offset\":" + std::to_string(f.entry_offset) +
               ",\"file_offset\":" + std::to_string(f.file_offset) +
               ",\"encoding\":\"" + f.encoding + "\",\"confidence\":" + conf +
               ",\"va\":" + std::to_string(f.va) +
               ",\"rva\":" + std::to_string(f.rva) +
               ",\"module_offset\":" + std::to_string(f.module_offset) +
               ",\"runtime_addr\":" + std::to_string(f.runtime_addr) +
               ",\"module\":\"" + escape_json(f.module) + "\",\"xrefs\":[";
        for (size_t x = 0; x < f.xrefs.size(); ++x) {
            if (x) out += ",";
            out += "\"" + escape_json(f.xrefs[x]) + "\"";
        }
        out += "]}";
        if (i + 1 < findings.size()) out += ",";
        out += "\n";
    }
    out += "  ]\n}\n";
    return out;
#endif
}

std::string to_csv(const std::vector<Finding> &findings) {
    std::string out =
        "url,source,source_path,entry_offset,file_offset,encoding,confidence,"
        "va,rva,module_offset,runtime_addr,module,xrefs\n";
    for (const Finding &f : findings) {
        char conf[32];
        std::snprintf(conf, sizeof(conf), "%.3f", f.confidence);
        std::string xrefs;
        for (const std::string &x : f.xrefs) { if (!xrefs.empty()) xrefs += ";"; xrefs += x; }
        out += csv_cell(f.url) + "," + to_string(f.source) + "," +
               csv_cell(f.source_path) + "," + std::to_string(f.entry_offset) + "," +
               std::to_string(f.file_offset) + "," + csv_cell(f.encoding) + "," + conf +
               "," + std::to_string(f.va) + "," + std::to_string(f.rva) + "," +
               std::to_string(f.module_offset) + "," + std::to_string(f.runtime_addr) + "," +
               csv_cell(f.module) + "," +
               csv_cell(xrefs) + "\n";
    }
    return out;
}

std::string to_html(const std::vector<Finding> &findings, const ReportOptions &options) {
    std::string out =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>" +
        escape_html(options.title) + "</title><style>"
        "body{font:14px system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}"
        "h1{font-size:1.4rem} table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top}"
        "th{background:#161b22;position:sticky;top:0} tr:nth-child(even){background:#11161c}"
        "a{color:#58a6ff} .meta{color:#8b949e;margin-bottom:1rem}"
        "</style></head><body><h1>" + escape_html(options.title) +
        "</h1><div class=\"meta\">target: " + escape_html(options.target) +
        " &middot; findings: " + std::to_string(findings.size()) +
        " &middot; zip: " + escape_html(options.zip_backend) +
        " &middot; elf: " + escape_html(options.backend) +
        " &middot; xrefs: " + escape_html(options.xref_backend) +
        "</div><table><thead><tr><th>URL</th><th>source</th><th>offset</th><th>VA/RVA</th>"
        "<th>module+offset</th><th>runtime</th><th>enc</th><th>conf</th><th>xrefs</th>"
        "</tr></thead><tbody>";
    for (const Finding &f : findings) {
        char conf[32];
        std::snprintf(conf, sizeof(conf), "%.2f", f.confidence);
        out += "<tr><td>" + escape_html(f.url) + "</td><td>" +
               escape_html(std::string(to_string(f.source)) + ":" + f.source_path) +
               "</td><td>" + hex(f.file_offset) + "</td><td>" + hex(f.va) + " / " +
               hex(f.rva) + "</td><td>" + hex(f.module_offset) + "</td><td>" +
               hex(f.runtime_addr) + "</td><td>" + f.encoding + "</td><td>" + conf +
               "</td><td>";
        for (const std::string &x : f.xrefs) out += escape_html(x) + "<br>";
        out += "</td></tr>";
    }
    out += "</tbody></table></body></html>\n";
    return out;
}

bool write_reports(const std::vector<Finding> &findings, const std::string &output_dir,
                   const std::string &stem, const ReportOptions &options) {
    if (!ensure_dir(output_dir)) return false;
    bool ok = true;
    ok &= write_whole_file(output_dir + "/" + stem + ".json", to_json(findings, options));
    ok &= write_whole_file(output_dir + "/" + stem + ".csv", to_csv(findings));
    ok &= write_whole_file(output_dir + "/" + stem + ".html", to_html(findings, options));
    return ok;
}

}  // namespace parallax
