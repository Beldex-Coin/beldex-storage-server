#pragma once

#include <filesystem>
#include <string>
#include <variant>
#include <vector>

namespace beldexss::cli {

struct command_line_options {
    std::string ip = "0.0.0.0";
    uint16_t https_port = 29090;
    uint16_t omq_port = 29089;
    std::string beldexd_omq_rpc;  // Defaults to ipc://$HOME/.beldex/[testnet/]beldexd.sock
    bool force_start = false;
    bool testnet = false;
    std::string log_level = "info";
    std::filesystem::path data_dir;
    std::string beldexd_key;          // test only (but needed for backwards compatibility)
    std::string beldexd_x25519_key;   // test only
    std::string beldexd_ed25519_key;  // test only
    // x25519 key that will be given access to get_stats omq endpoint
    std::vector<std::string> stats_access_keys;
};

using parse_result = std::variant<command_line_options, int>;

parse_result parse_cli_args(std::vector<const char*> args);
parse_result parse_cli_args(int argc, char* argv[]);

}  // namespace beldexss::cli
