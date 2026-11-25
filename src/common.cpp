#include "parallax/common.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <limits>

namespace parallax {

const char *to_string(SourceKind kind) {
    switch (kind) {
        case SourceKind::ApkEntry: return "apk_entry";
        case SourceKind::DexString: return "dex_string";
        case SourceKind::ElfSection: return "elf_section";
        case SourceKind::NativeModule: return "native_module";
        case SourceKind::RuntimeDump: return "runtime_dump";
        case SourceKind::RawFile: return "raw_file";
        default: return "unknown";
    }
}

std::string hex(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return buf;
}

std::string finding_key(const Finding &f) {
    return std::to_string(static_cast<int>(f.source)) + "|" + f.source_path + "|" +
           std::to_string(f.entry_offset) + "|" + f.url + "|" + f.encoding;
}

std::vector<uint8_t> read_whole_file(const std::string &path, size_t limit) {
    std::vector<uint8_t> data;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return data;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        size_t want = static_cast<size_t>(st.st_size);
        if (want > limit) want = limit;
        data.resize(want);
        size_t done = 0;
        while (done < want) {
            ssize_t n = read(fd, data.data() + done, want - done);
            if (n > 0) done += static_cast<size_t>(n);
            else if (n < 0 && errno == EINTR) continue;
            else break;
        }
        data.resize(done);
    } else {
        uint8_t chunk[65536];
        for (;;) {
            ssize_t n = read(fd, chunk, sizeof(chunk));
            if (n > 0 && data.size() + static_cast<size_t>(n) <= limit) {
                data.insert(data.end(), chunk, chunk + n);
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
    }
    close(fd);
    return data;
}

bool write_whole_file(const std::string &path, const std::string &data) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n > 0) off += static_cast<size_t>(n);
        else if (n < 0 && errno == EINTR) continue;
        else { close(fd); return false; }
    }
    close(fd);
    return true;
}

}  // namespace parallax
