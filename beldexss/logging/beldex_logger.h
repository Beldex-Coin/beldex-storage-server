#pragma once

#include <filesystem>

#include <oxen/log.hpp>

namespace beldexss {
namespace log = oxen::log;
}

namespace beldexss::logging {
void init(const std::filesystem::path& data_dir, oxen::log::Level log_level);

}  // namespace beldexss::logging
