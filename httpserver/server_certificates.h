#pragma once

#include <filesystem>

namespace beldex {

void generate_dh_pem(const std::filesystem::path& dh_path);
void generate_cert(const std::filesystem::path& cert_path, const std::filesystem::path& key_path);

}
