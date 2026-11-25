#include "parallax/runtime.hpp"

#include "parallax/url.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace parallax {
namespace {

uint64_t hex_field(const std::string &line, const std::string &key) {
    size_t p = line.find(key);
    if (p == std::string::npos) return 0;
    p += key.size();
    if (p >= line.size() || line[p] != '=') return 0;
    const char *start = line.c_str() + p + 1;
    char *end = nullptr;
    unsigned long long v = strtoull(start, &end, 0);
    return static_cast<uint64_t>(v);
}

std::string str_field(const std::string &line, const std::string &key) {
    size_t p = line.find(key);
    if (p == std::string::npos) return "";
    p += key.size();
    if (p >= line.size() || line[p] != '=') return "";
    size_t b = p + 1;
    size_t e = line.find(' ', b);
    if (e == std::string::npos) e = line.size();
    return line.substr(b, e - b);
}

Finding from_text_line(const std::string &line, const std::string &path) {
    Finding f;
    size_t pipe = line.find(" | addr=");
    if (pipe == std::string::npos) return f;
    std::string head = line.substr(0, pipe);
    size_t lb = head.find(']');
    f.url = lb == std::string::npos ? head : head.substr(lb + 1);
    while (!f.url.empty() && f.url[0] == ' ') f.url.erase(0, 1);
    f.source = SourceKind::RuntimeDump;
    f.source_path = path;
    f.runtime_addr = hex_field(line, "addr");
    f.entry_offset = hex_field(line, "r_off");
    f.file_offset = hex_field(line, "f_off");
    f.module = str_field(line, "module");
    f.module_base = hex_field(line, "base");
    f.module_offset = hex_field(line, "m_off");
    f.va = f.module_offset;  // m_off is addr - load_bias, i.e. the ELF VA
    f.encoding = str_field(line, "enc");
    f.confidence = url_confidence(f.url, f.encoding);
    std::string hits = str_field(line, "hits");
    f.hits = static_cast<uint64_t>(strtoull(hits.c_str(), nullptr, 10));
    return f;
}

size_t find_unescaped(const std::string &s, size_t from, char c) {
    for (size_t i = from; i < s.size(); ++i) {
        if (s[i] == '\\') { ++i; continue; }
        if (s[i] == c) return i;
    }
    return std::string::npos;
}

std::string unescape_json(std::string s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default: out.push_back(s[i]); break;
            }
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

std::string json_value(const std::string &line, const std::string &key) {
    std::string needle = "\"" + key + "\"";
    size_t p = line.find(needle);
    if (p == std::string::npos) return "";
    p = line.find(':', p + needle.size());
    if (p == std::string::npos) return "";
    ++p;
    while (p < line.size() && line[p] == ' ') ++p;
    if (p < line.size() && line[p] == '"') {
        size_t e = find_unescaped(line, p + 1, '"');
        if (e == std::string::npos) return "";
        return unescape_json(line.substr(p + 1, e - p - 1));
    }
    size_t e = p;
    while (e < line.size() && (isdigit(static_cast<unsigned char>(line[e])) || line[e] == '-')) ++e;
    return line.substr(p, e - p);
}

uint64_t json_hex(const std::string &line, const std::string &key) {
    std::string v = json_value(line, key);
    if (v.empty() || (v[0] != '0' || (v.size() > 1 && v[1] != 'x'))) {
        return static_cast<uint64_t>(strtoull(v.c_str(), nullptr, 10));
    }
    return static_cast<uint64_t>(strtoull(v.c_str(), nullptr, 0));
}

Finding from_json_line(const std::string &line, const std::string &path) {
    Finding f;
    f.url = json_value(line, "url");
    if (f.url.empty()) return f;
    f.source = SourceKind::RuntimeDump;
    f.source_path = path;
    f.encoding = json_value(line, "encoding");
    f.module = json_value(line, "module");
    f.runtime_addr = json_hex(line, "addr");
    f.entry_offset = json_hex(line, "r_off");
    f.file_offset = json_hex(line, "f_off");
    f.module_base = json_hex(line, "module_base");
    f.module_offset = json_hex(line, "m_off");
    f.va = f.module_offset;
    f.confidence = url_confidence(f.url, f.encoding);
    return f;
}

std::vector<std::string> split_csv_line(const std::string &line) {
    std::vector<std::string> cells;
    std::string cell;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (quoted) {
            if (c == '"' && i + 1 < line.size() && line[i + 1] == '"') { cell += '"'; ++i; }
            else if (c == '"') quoted = false;
            else cell += c;
        } else if (c == '"') {
            quoted = true;
        } else if (c == ',') {
            cells.push_back(cell); cell.clear();
        } else {
            cell += c;
        }
    }
    cells.push_back(cell);
    return cells;
}

Finding from_csv_line(const std::string &line, const std::string &path) {
    Finding f;
    std::vector<std::string> c = split_csv_line(line);
    if (c.size() < 12 || c[0] == "timestamp") return f;
    f.url = c[1];
    if (f.url.empty()) return f;
    f.source = SourceKind::RuntimeDump;
    f.source_path = path;
    f.runtime_addr = strtoull(c[2].c_str(), nullptr, 0);
    f.entry_offset = strtoull(c[6].c_str(), nullptr, 0);
    f.file_offset = strtoull(c[7].c_str(), nullptr, 0);
    f.module = c[8];
    f.module_base = strtoull(c[9].c_str(), nullptr, 0);
    f.module_offset = strtoull(c[10].c_str(), nullptr, 0);
    f.va = f.module_offset;
    f.encoding = c[11];
    f.confidence = url_confidence(f.url, f.encoding);
    return f;
}

}  // namespace

std::vector<Finding> parse_runtime_dump(const std::string &path) {
    std::vector<Finding> out;
    std::vector<uint8_t> bytes = read_whole_file(path, 128u * 1024u * 1024u);
    if (bytes.empty()) return out;
    std::string data(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    bool csv = path.size() >= 4 && path.compare(path.size() - 4, 4, ".csv") == 0;
    bool jsonl = path.size() >= 6 && path.compare(path.size() - 6, 6, ".jsonl") == 0;

    size_t start = 0;
    while (start <= data.size()) {
        size_t end = data.find('\n', start);
        if (end == std::string::npos) end = data.size();
        std::string line = data.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        Finding f;
        if (jsonl && line.find("\"url\"") != std::string::npos) f = from_json_line(line, path);
        else if (csv) f = from_csv_line(line, path);
        else if (line.find(" | addr=") != std::string::npos) f = from_text_line(line, path);
        if (!f.url.empty()) out.push_back(f);
        if (end == data.size()) break;
        start = end + 1;
    }
    return out;
}

}  // namespace parallax
