#include "beldex_logger.h"
#include "beldexd_rpc.h"
#include "omq_server.h"

#include <chrono>
#include <exception>
#include <future>
#include <string_view>

#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

namespace beldex {

beldexd_seckeys get_mn_privkeys(std::string_view beldexd_rpc_address,
        std::function<bool()> keep_trying) {
    oxenmq::OxenMQ omq{omq_logger, oxenmq::LogLevel::info};
    omq.start();
    constexpr auto retry_interval = 5s;
    auto last_try = std::chrono::steady_clock::now() - retry_interval;
    BELDEX_LOG(info, "Retrieving MN keys from beldexd");

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
        auto conn = omq.connect_remote(oxenmq::address{beldexd_rpc_address},
            [&omq, &prom](auto conn) {
                BELDEX_LOG(info, "Connected to beldexd; retrieving MN keys");
                omq.request(conn, "admin.get_master_node_privkey",
                    [&prom](bool success, std::vector<std::string> data) {
                        try {
                            if (!success || data.size() < 2) {
                                throw std::runtime_error{"beldexd MN keys request failed: " +
                                    (data.empty() ? "no data received" : data[0])};
                            }
                            auto r = nlohmann::json::parse(data[1]);

                            auto pk = r.at("master_node_privkey").get<std::string>();
                            if (pk.empty())
                                throw std::runtime_error{"main master node private key is empty ("
                                    "perhaps beldexd is not running in master-node mode?)"};
                            prom.set_value(beldexd_seckeys{
                                legacy_seckey::from_hex(pk),
                                ed25519_seckey::from_hex(r.at("master_node_ed25519_privkey").get<std::string>()),
                                x25519_seckey::from_hex(r.at("master_node_x25519_privkey").get<std::string>())});
                        } catch (...) {
                            prom.set_exception(std::current_exception());
                        }
                    });
            },
            [&prom](auto&&, std::string_view fail_reason) {
                try {
                    throw std::runtime_error{
                        "Failed to connect to beldexd: " + std::string{fail_reason}};
                } catch (...) { prom.set_exception(std::current_exception()); }
            });

        try {
            return fut.get();
        } catch (const std::exception& e) {
            BELDEX_LOG(critical, "Error retrieving private keys from beldexd: {}; retrying", e.what());
        }
        if (keep_trying && !keep_trying())
            return {};
    }
}

}
