#include "parallax/dex.hpp"

#include "detail/endian.hpp"

#include <algorithm>

namespace parallax {

DexReader::DexReader(const std::vector<uint8_t> &bytes) : bytes_(bytes) {
    if (bytes_.size() < 112) return;
    if (!(bytes_[0] == 'd' && bytes_[1] == 'e' && bytes_[2] == 'x' && bytes_[3] == '\n')) return;
    version_.assign(reinterpret_cast<const char *>(bytes_.data() + 4), 3);
    if (detail::rd32(bytes_.data() + 40) != 0x12345678) return;  // endian tag
    file_size_ = detail::rd32(bytes_.data() + 32);
    string_count_ = detail::rd32(bytes_.data() + 56);
    string_ids_off_ = detail::rd32(bytes_.data() + 60);
    type_count_ = detail::rd32(bytes_.data() + 64);
    type_ids_off_ = detail::rd32(bytes_.data() + 68);
    valid_ = true;

    if (string_count_ > 4000000) string_count_ = 4000000;
    for (uint64_t i = 0; i < string_count_; ++i) {
        uint64_t entry = string_ids_off_ + i * 4;
        if (entry + 4 > bytes_.size()) break;
        uint64_t data_off = detail::rd32(bytes_.data() + entry);
        if (data_off + 1 > bytes_.size()) continue;
        uint64_t utf16_len = 0, used = 0;
        if (!read_uleb(data_off, utf16_len, used)) continue;
        uint64_t consumed = 0;
        std::string value = read_mutf8(data_off + used, bytes_.size() - data_off - used, consumed);
        DexString s;
        s.value = value;
        s.data_offset = data_off;
        s.id_offset = entry;
        s.utf16_length = utf16_len;
        strings_.push_back(s);
    }

    if (type_count_ > 4000000) type_count_ = 4000000;
    for (uint64_t i = 0; i < type_count_; ++i) {
        uint64_t entry = type_ids_off_ + i * 4;
        if (entry + 4 > bytes_.size()) break;
        uint32_t idx = detail::rd32(bytes_.data() + entry);
        if (idx < strings_.size()) types_.push_back(strings_[idx].value);
    }
}

bool DexReader::read_uleb(uint64_t offset, uint64_t &value, uint64_t &consumed) const {
    value = 0;
    consumed = 0;
    for (unsigned shift = 0; shift < 35; shift += 7) {
        if (offset + consumed >= bytes_.size()) return false;
        uint8_t b = bytes_[static_cast<size_t>(offset + consumed++)];
        value |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) return true;
    }
    return false;
}

std::string DexReader::read_mutf8(uint64_t offset, uint64_t max, uint64_t &consumed) const {
    std::string out;
    consumed = 0;
    if (offset >= bytes_.size()) return out;
    uint64_t limit = std::min<uint64_t>(max, bytes_.size() - offset);
    while (consumed < limit) {
        uint8_t c = bytes_[static_cast<size_t>(offset + consumed)];
        if (c == 0) { ++consumed; break; }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++consumed;
        } else if ((c & 0xe0) == 0xc0 && consumed + 1 < limit) {
            uint8_t c2 = bytes_[static_cast<size_t>(offset + consumed + 1)];
            if ((c2 & 0xc0) != 0x80) break;
            // Modified UTF-8 NUL is C0 80.
            unsigned cp = ((c & 0x1f) << 6) | (c2 & 0x3f);
            out.push_back(static_cast<char>(cp == 0 ? 0 : cp & 0xff));
            consumed += 2;
        } else if ((c & 0xf0) == 0xe0 && consumed + 2 < limit) {
            uint8_t c2 = bytes_[static_cast<size_t>(offset + consumed + 1)];
            uint8_t c3 = bytes_[static_cast<size_t>(offset + consumed + 2)];
            if ((c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80) break;
            unsigned cp = ((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
            if (cp >= 0xd800 && cp <= 0xdfff) {
                out.push_back('?');  // surrogate pair, simplified
            } else if (cp < 0x80) {
                out.push_back(static_cast<char>(cp));
            } else if (cp < 0x800) {
                out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else {
                out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            }
            consumed += 3;
        } else {
            break;
        }
    }
    return out;
}

}  // namespace parallax
