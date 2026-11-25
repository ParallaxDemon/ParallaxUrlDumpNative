// Optional minizip-ng backend. Enabled with -DPARALLAX_WITH_MINIZIP_NG=ON when
// a minizip-ng installation provides the classic <minizip/unzip.h> compatibility API.
#include "parallax/zip.hpp"

#if defined(PARALLAX_HAVE_MINIZIP_NG)
#include <minizip/unzip.h>

#include <memory>
#include <string>
#include <vector>

namespace parallax {
namespace {

class MinizipArchive : public IZipArchive {
public:
    explicit MinizipArchive(unzFile handle) : handle_(handle) { enumerate(); }
    ~MinizipArchive() override {
        if (handle_ != nullptr) unzClose(handle_);
    }

    const std::vector<ZipEntry> &entries() const override { return entries_; }
    std::string backend() const override { return "minizip-ng"; }

    bool read(const ZipEntry &entry, std::vector<uint8_t> &out) const override {
        out.clear();
        if (handle_ == nullptr || entry.uncompressed_size > 512u * 1024u * 1024u) return false;
        if (unzGoToFile(handle_, entry.name.c_str()) != UNZ_OK) return false;
        if (unzOpenCurrentFile(handle_) != UNZ_OK) return false;
        out.resize(static_cast<size_t>(entry.uncompressed_size));
        int got = unzReadCurrentFile(handle_, out.data(), static_cast<unsigned>(out.size()));
        unzCloseCurrentFile(handle_);
        if (got < 0) { out.clear(); return false; }
        out.resize(static_cast<size_t>(got));
        return true;
    }

private:
    void enumerate() {
        if (handle_ == nullptr) return;
        if (unzGoToFirstFile(handle_) != UNZ_OK) return;
        do {
            unz_file_info64 info;
            char name[4096] = {0};
            if (unzGetCurrentFileInfo64(handle_, &info, name, sizeof(name),
                                        nullptr, 0, nullptr, 0) != UNZ_OK) continue;
            ZipEntry e;
            e.name = name;
            e.compressed_size = info.compressed_size;
            e.uncompressed_size = info.uncompressed_size;
            e.crc32 = info.crc;
            e.method = info.compression_method;
            e.is_directory = !e.name.empty() && e.name.back() == '/';
            entries_.push_back(e);
        } while (unzGoToNextFile(handle_) == UNZ_OK);
    }

    unzFile handle_;
    std::vector<ZipEntry> entries_;
};

}  // namespace

std::unique_ptr<IZipArchive> open_zip_minizip(const std::string &path) {
    unzFile handle = unzOpen(path.c_str());
    if (handle == nullptr) return nullptr;
    return std::unique_ptr<IZipArchive>(new MinizipArchive(handle));
}

}  // namespace parallax

#endif  // PARALLAX_HAVE_MINIZIP_NG
