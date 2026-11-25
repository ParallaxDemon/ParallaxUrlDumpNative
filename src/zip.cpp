#include "parallax/zip.hpp"

#include "detail/endian.hpp"

#include <zlib.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>

namespace parallax {
namespace {

constexpr uint32_t kEocdSig = 0x06054b50;
constexpr uint32_t kCentralSig = 0x02014b50;
constexpr uint32_t kLocalSig = 0x04034b50;
constexpr uint32_t kZip64EocdSig = 0x06064b50;
constexpr uint32_t kZip64LocatorSig = 0x07064b50;
constexpr size_t kMaxZipBytes = 512u * 1024u * 1024u;

class BuiltinZipArchive : public IZipArchive {
public:
    explicit BuiltinZipArchive(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {
        parse();
    }

    const std::vector<ZipEntry> &entries() const override { return entries_; }
    std::string backend() const override { return "builtin-zip64-zlib"; }

    bool read(const ZipEntry &entry, std::vector<uint8_t> &out) const override {
        out.clear();
        if (entry.uncompressed_size > kMaxZipBytes) return false;
        if (entry.local_offset > bytes_.size() || entry.compressed_size > bytes_.size()) return false;
        const uint8_t *local = bytes_.data() + entry.local_offset;
        if (bytes_.size() - entry.local_offset < 30) return false;
        if (detail::rd32(local) != kLocalSig) return false;
        size_t name_len = detail::rd16(local + 26);
        size_t extra_len = detail::rd16(local + 28);
        size_t data_off = entry.local_offset + 30 + name_len + extra_len;
        if (data_off > bytes_.size()) return false;
        size_t avail = bytes_.size() - data_off;
        size_t csize = static_cast<size_t>(entry.compressed_size);
        if (csize > avail) return false;
        const uint8_t *src = bytes_.data() + data_off;

        if (entry.method == 0) {
            out.assign(src, src + csize);
            return out.size() == entry.uncompressed_size;
        }
        if (entry.method != 8) return false;

        out.resize(static_cast<size_t>(entry.uncompressed_size));
        z_stream strm;
        std::memset(&strm, 0, sizeof(strm));
        strm.next_in = const_cast<Bytef *>(src);
        strm.avail_in = static_cast<uInt>(csize);
        strm.next_out = out.data();
        strm.avail_out = static_cast<uInt>(out.size());
        if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) return false;
        int rc = inflate(&strm, Z_FINISH);
        bool ok = (rc == Z_STREAM_END || (rc == Z_OK && strm.avail_out == 0));
        size_t produced = out.size() - strm.avail_out;
        inflateEnd(&strm);
        out.resize(produced);
        return ok && produced == entry.uncompressed_size;
    }

private:
    void parse() {
        if (bytes_.size() < 22) return;
        size_t search_start = bytes_.size() - std::min<size_t>(bytes_.size(), 66000);
        size_t eocd = std::string::npos;
        for (size_t pos = bytes_.size() - 22; pos >= search_start; --pos) {
            if (detail::rd32(bytes_.data() + pos) == kEocdSig) { eocd = pos; break; }
            if (pos == search_start) break;
        }
        if (eocd == std::string::npos) return;

        uint64_t total = detail::rd16(bytes_.data() + eocd + 10);
        uint64_t cd_size = detail::rd32(bytes_.data() + eocd + 12);
        uint64_t cd_off = detail::rd32(bytes_.data() + eocd + 16);

        if (eocd >= 20 && detail::rd32(bytes_.data() + eocd - 20) == kZip64LocatorSig) {
            uint64_t z64_off = detail::rd64(bytes_.data() + eocd - 12);
            if (z64_off + 56 <= bytes_.size() &&
                detail::rd32(bytes_.data() + z64_off) == kZip64EocdSig) {
                const uint8_t *z = bytes_.data() + z64_off;
                total = detail::rd64(z + 32);
                cd_size = detail::rd64(z + 40);
                cd_off = detail::rd64(z + 48);
            }
        }

        if (cd_off > bytes_.size() || cd_size > bytes_.size() - cd_off) return;
        size_t pos = static_cast<size_t>(cd_off);
        size_t end = static_cast<size_t>(cd_off + cd_size);
        while (pos + 46 <= end && detail::rd32(bytes_.data() + pos) == kCentralSig) {
            const uint8_t *p = bytes_.data() + pos;
            ZipEntry e;
            e.method = detail::rd16(p + 10);
            e.crc32 = detail::rd32(p + 16);
            e.compressed_size = detail::rd32(p + 20);
            e.uncompressed_size = detail::rd32(p + 24);
            size_t name_len = detail::rd16(p + 28);
            size_t extra_len = detail::rd16(p + 30);
            size_t comment_len = detail::rd16(p + 32);
            e.local_offset = detail::rd32(p + 42);
            size_t total_len = 46 + name_len + extra_len + comment_len;
            if (pos + total_len > end || name_len > bytes_.size() - pos - 46) break;
            e.name.assign(reinterpret_cast<const char *>(p + 46), name_len);
            e.is_directory = !e.name.empty() && e.name.back() == '/';

            const uint8_t *extra = p + 46 + name_len;
            size_t extra_end = static_cast<size_t>(extra - bytes_.data()) + extra_len;
            while (extra + 4 <= bytes_.data() + extra_end) {
                uint16_t id = detail::rd16(extra);
                uint16_t sz = detail::rd16(extra + 2);
                const uint8_t *v = extra + 4;
                if (id == 0x0001) {
                    size_t idx = 0;
                    if (e.uncompressed_size == 0xffffffffu && idx + 8 <= sz) {
                        e.uncompressed_size = detail::rd64(v + idx); idx += 8;
                    }
                    if (e.compressed_size == 0xffffffffu && idx + 8 <= sz) {
                        e.compressed_size = detail::rd64(v + idx); idx += 8;
                    }
                    if (e.local_offset == 0xffffffffu && idx + 8 <= sz) {
                        e.local_offset = detail::rd64(v + idx);
                    }
                    break;
                }
                extra += 4 + sz;
            }
            entries_.push_back(e);
            pos += total_len;
            if (entries_.size() >= total && total > 0) break;
        }
    }

    std::vector<uint8_t> bytes_;
    std::vector<ZipEntry> entries_;
};

bool ensure_directory(const std::string &path) {
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

bool safe_relative_path(const std::string &name, std::string &out) {
    if (name.empty() || name[0] == '/' || name.find('\\') != std::string::npos) return false;
    std::string clean;
    size_t start = 0;
    while (start <= name.size()) {
        size_t end = name.find('/', start);
        if (end == std::string::npos) end = name.size();
        std::string part = name.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") {
            if (end == name.size()) break;
            start = end + 1;
            continue;
        }
        if (!clean.empty()) clean += "/";
        clean += part;
        if (end == name.size()) break;
        start = end + 1;
    }
    if (clean.empty()) return false;
    out = clean;
    return true;
}

}  // namespace

std::unique_ptr<IZipArchive> open_zip(const std::string &path) {
    std::vector<uint8_t> bytes = read_whole_file(path, kMaxZipBytes);
    if (bytes.empty()) return nullptr;
#if defined(PARALLAX_HAVE_MINIZIP_NG)
    if (auto z = open_zip_minizip(path)) return z;
#endif
    return std::unique_ptr<IZipArchive>(new BuiltinZipArchive(std::move(bytes)));
}

bool extract_entry_safely(const IZipArchive &zip, const ZipEntry &entry,
                          const std::string &output_dir, size_t max_bytes) {
    if (entry.is_directory || entry.uncompressed_size > max_bytes) return false;
    std::string rel;
    if (!safe_relative_path(entry.name, rel)) return false;
    std::vector<uint8_t> data;
    if (!zip.read(entry, data) || data.size() > max_bytes) return false;
    std::string full = output_dir + "/" + rel;
    size_t slash = full.find_last_of('/');
    if (slash != std::string::npos && !ensure_directory(full.substr(0, slash))) return false;
    return write_whole_file(full, std::string(data.begin(), data.end()));
}

}  // namespace parallax
