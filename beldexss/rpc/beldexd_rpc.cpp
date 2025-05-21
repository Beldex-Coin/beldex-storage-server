#include "beldexd_rpc.h"
#include <beldexss/logging/beldex_logger.h>
#include <beldexss/server/omq_logger.h>

#include <chrono>
#include <exception>
#include <future>
#include <string_view>

#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

namespace beldexss::rpc {

using namespace oxen;
static auto logcat = log::Cat("rpc");

using namespace std::literals;

beldexd_seckeys get_mn_privkeys(
        std::string_view beldexd_rpc_address, std::function<bool()> keep_trying) {
    oxenmq::OxenMQ omq{omq_logger, oxenmq::LogLevel::info};
    omq.start();
    constexpr auto retry_interval = 5s;
    auto last_try = std::chrono::steady_clock::now() - retry_interval;
    log::info(logcat, "Retrieving MN keys from beldexd");

    while (true) {
        // Rate limit ourselves so that we don't spam connection/request attempts
        auto next_try = last_try + retry_interval;
        auto now = std::chrono::steady_clock::now();
        if (now < next_try)
            std::this_thread::sleep_until(next_try);
        last_try = now;

        if (keep_trying && !keep_trying())
            return {};
        std::promise<beldexd_seckeys> prom;
        auto fut = prom.get_future();
        auto conn = omq.connect_remote(
                oxenmq::address{beldexd_rpc_address},
                [&omq, &prom](auto conn) {
                    log::info(logcat, "Connected to beldexd; retrieving MN keys");
                    omq.request(
                            conn,
                            "admin.get_master_node_privkey",
                            [&prom](bool success, std::vector<std::string> data) {
                                try {
                                    if (!success || data.size() < 2) {
                                        throw std::runtime_error{
                                                "beldexd MN keys request failed: " +
                                                (data.empty() ? "no data received" : data[0])};
                                    }
                                    auto r = nlohmann::json::parse(data[1]);
                                    auto pk =
                                            r.value<std::string_view>("master_node_privkey", ""sv);
                                    if (pk.empty())
                                        throw std::runtime_error{
                                                "main master node private key is empty (perhaps "
                                                "beldexd is not running in master-node mode?)"};
                                    prom.set_value(beldexd_seckeys{
                                            crypto::legacy_seckey::from_hex(pk),
                                            crypto::ed25519_seckey::from_hex(
                                                    r.at("master_node_ed25519_privkey")
                                                            .get<std::string_view>()),
                                            crypto::x25519_seckey::from_hex(
                                                    r.at("master_node_x25519_privkey")
                                                            .get<std::string_view>())});
                                } catch (...) {
                                    prom.set_exception(std::current_exception());
                                }
                            });
                },
                [&prom](auto&&, std::string_view fail_reason) {
                    try {
                        throw std::runtime_error{
                                "Failed to connect to beldexd: " + std::string{fail_reason}};
                    } catch (...) {
                        prom.set_exception(std::current_exception());
                    }
                });

        try {
            return fut.get();
        } catch (const std::exception& e) {
            log::critical(
                    logcat, "Error retrieving private keys from beldexd: {}; retrying", e.what());
        }
        if (keep_trying && !keep_trying())
            return {};
    }
}

}  // namespace beldexss::rpc
