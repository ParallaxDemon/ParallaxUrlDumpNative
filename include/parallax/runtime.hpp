#pragma once

#include "parallax/common.hpp"

namespace parallax {

// Reads output produced by the native liburldump.so (ULTRA text/CSV/JSONL).
// Runtime findings are merged into the same report as static findings.
std::vector<Finding> parse_runtime_dump(const std::string &path);

}  // namespace parallax
