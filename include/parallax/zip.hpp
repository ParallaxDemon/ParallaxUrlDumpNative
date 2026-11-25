#pragma once

#include "parallax/common.hpp"

#include <memory>
#include <vector>

namespace parallax {

struct ZipEntry {
    std::string name;
    uint64_t compressed_size = 0;
    uint64_t uncompressed_size = 0;
    uint64_t local_offset = 0;
    uint32_t crc32 = 0;
    uint16_t method = 0;  // 0 = stored, 8 = deflate
    bool is_directory = false;
};

class IZipArchive {
public:
    virtual ~IZipArchive() = default;
    virtual const std::vector<ZipEntry> &entries() const = 0;
    virtual bool read(const ZipEntry &entry, std::vector<uint8_t> &out) const = 0;
    virtual std::string backend() const = 0;
};

// Returns the minizip-ng backed archive when compiled with it, otherwise the
// built-in ZIP/ZIP64 reader (zlib inflate). Never extracts by itself.
inline const char *zip_backend() {
#if defined(PARALLAX_HAVE_MINIZIP_NG)
    return "minizip-ng";
#else
    return "builtin-zip64-zlib";
#endif
}

std::unique_ptr<IZipArchive> open_zip(const std::string &path);

#if defined(PARALLAX_HAVE_MINIZIP_NG)
std::unique_ptr<IZipArchive> open_zip_minizip(const std::string &path);
#endif

// Extracts selected entries with path traversal protection and size limits.
bool extract_entry_safely(const IZipArchive &zip, const ZipEntry &entry,
                          const std::string &output_dir, size_t max_bytes = 128u * 1024u * 1024u);

}  // namespace parallax
