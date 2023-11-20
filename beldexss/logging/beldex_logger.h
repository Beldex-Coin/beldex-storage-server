#pragma once

#include <filesystem>

#include <oxen/log.hpp>

namespace beldex::logging {

void init(const std::filesystem::path& data_dir, oxen::log::Level log_level);

}  // namespace beldex::logging
