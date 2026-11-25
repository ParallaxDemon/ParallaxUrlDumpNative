#pragma once

#include "parallax/common.hpp"

#include <vector>

namespace parallax {

struct DexString {
    std::string value;
    uint64_t data_offset = 0;   // offset of string_data_item in the DEX file
    uint64_t id_offset = 0;     // offset of the string_id_item entry
    uint64_t utf16_length = 0;
};

// Minimal, bounds-checked DEX reader: string_ids, string_data and type
// descriptors. It never executes or loads DEX code.
class DexReader {
public:
    explicit DexReader(const std::vector<uint8_t> &bytes);

    bool valid() const { return valid_; }
    const std::vector<DexString> &strings() const { return strings_; }
    const std::vector<std::string> &types() const { return types_; }
    std::string version() const { return version_; }
    uint32_t file_size() const { return file_size_; }

private:
    bool read_uleb(uint64_t offset, uint64_t &value, uint64_t &consumed) const;
    std::string read_mutf8(uint64_t offset, uint64_t max, uint64_t &consumed) const;

    std::vector<uint8_t> bytes_;
    bool valid_ = false;
    std::string version_;
    uint32_t file_size_ = 0;
    uint64_t string_count_ = 0;
    uint64_t string_ids_off_ = 0;
    uint64_t type_count_ = 0;
    uint64_t type_ids_off_ = 0;
    std::vector<DexString> strings_;
    std::vector<std::string> types_;
};

}  // namespace parallax
