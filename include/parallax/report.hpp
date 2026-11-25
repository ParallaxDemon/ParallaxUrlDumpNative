#pragma once

#include "parallax/common.hpp"

namespace parallax {

struct ReportOptions {
    std::string title = "Parallax URL Dumper";
    std::string target;
    std::string zip_backend;
    std::string backend;  // ELF backend, kept for compatibility
    std::string xref_backend;
};

std::string to_json(const std::vector<Finding> &findings, const ReportOptions &options = {});
std::string to_csv(const std::vector<Finding> &findings);
std::string to_html(const std::vector<Finding> &findings, const ReportOptions &options = {});

bool write_reports(const std::vector<Finding> &findings, const std::string &output_dir,
                   const std::string &stem, const ReportOptions &options = {});

}  // namespace parallax
