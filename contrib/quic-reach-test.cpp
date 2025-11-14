#include <chrono>
#include <exception>
#include <iostream>
#include <random>
#include <string>

#include <oxen/quic.hpp>
#include <nlohmann/json.hpp>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

using namespace std::literals;

using namespace oxen::quic;
using namespace oxenc::literals;

bool verbose = false;

int usage(std::string_view argv0, std::string_view err = "") {
    if (!err.empty())
        std::cerr << "\e[31;1mError: " << err << "\e[0m\n\n";

    std::cerr << "Usage: " << argv0 << " [--verbose|-v] MNODE_PK [MNODE_PK ...]"
              << R"(

Performs a storage server quic connectivity test for the given master node(s).  Each MNODE_PK
should be the primary pubkey of the master node; its address will be looked up and a test
request will be made to its advertised IP/port.

By default this outputs one line per tested node, of `PUBKEY: (status)`, where (status) is one of:

- `pass` -- test request succeeded
- `FAIL` -- test request failed to connect
- `NOT FOUND` -- given pubkey does not match any current registered master node
- `NO IP` -- given pubkey matches a master node, but we didn't find a recent proof with IP/port
             contact info

The `--verbose` flag can be given for more details.

)";
    return 1;
}

std::array SEEDS = {
        RemoteAddress{
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"_hex,
                "144.76.164.202",
                uint16_t{20200}},
        RemoteAddress{
                "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce"_hex,
                "88.99.102.229",
                uint16_t{20201}},
        RemoteAddress{
                "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f"_hex,
                "195.16.73.17",
                uint16_t{20202}},
        RemoteAddress{
                "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b"_hex,
                "104.194.11.120",
                uint16_t{20203}},
        RemoteAddress{
                "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0"_hex,
                "104.194.8.115",
                uint16_t{20204}},
};

std::mt19937_64 rng{std::random_device{}()};

std::shared_ptr<GNUTLSCreds> client_creds() {
    if (sodium_init())
        throw std::runtime_error{"Failed to initialize libsodium"};

    std::array<unsigned char, 32> pk;
    std::string sk;
    sk.resize(64);
    crypto_sign_ed25519_keypair(pk.data(), reinterpret_cast<unsigned char*>(sk.data()));
    return GNUTLSCreds::make_from_ed_seckey(std::move(sk));
}

const std::shared_ptr<GNUTLSCreds> creds = client_creds();

constexpr auto ALPN = "beldexstorage"sv;
const ustring uALPN{reinterpret_cast<const unsigned char*>(ALPN.data()), ALPN.size()};

std::unordered_map<std::string, std::optional<RemoteAddress>> fetch_mn_addresses(
        const std::shared_ptr<Endpoint>& ep) {
    std::shuffle(SEEDS.begin(), SEEDS.end(), rng);

    nlohmann::json req{
            {"endpoint", "get_master_nodes"},
            {"params",
             {{"fields",
               {{"master_node_pubkey", true},
                {"pubkey_ed25519", true},
                {"public_ip", true},
                {"storage_lmq_port", true}}}}}};

    std::unordered_map<std::string, std::optional<RemoteAddress>> result;
    for (const auto& seed : SEEDS) {
        if (verbose)
            std::cerr << "\e[3mFetching master node list from seed "
                      << oxenc::to_hex(seed.view_remote_key().substr(0, 5)) << "...\e[0m\n";
        auto c = ep->connect(seed, creds);
        auto s = c->open_stream<BTRequestStream>();
        std::promise<nlohmann::json> mns_prom;
        s->command("beldexd_request", req.dump(), [&seed, &mns_prom](message resp) {
            try {
                if (resp.is_error())
                    throw std::runtime_error{"Failed to fetch master node list from seed node"};

                mns_prom.set_value(nlohmann::json::parse(resp.body()));
            } catch (...) {
                mns_prom.set_exception(std::current_exception());
            }
        });

        nlohmann::json mns;
        try {
            mns = mns_prom.get_future().get();
            if (!(mns.is_array() && mns.size() == 2 && mns[0].get<int>() == 200))
                throw std::runtime_error{"An error occured: " + mns.dump()};

            for (const auto& state : mns[1]["result"]["master_node_states"]) {
                auto& addr = result[state["master_node_pubkey"].get<std::string>()];
                auto ip = state["public_ip"].get<std::string>();
                if (ip.empty() || ip == "0.0.0.0")
                    continue;

                addr.emplace(
                        oxenc::from_hex(state["pubkey_ed25519"].get<std::string_view>()),
                        std::move(ip),
                        state["storage_lmq_port"].get<uint16_t>());
            }

            return result;

        } catch (const std::exception& e) {
            std::cerr << "\e[3mFailed to obtain master node list: " << e.what() << "\e[0m\n";
            result.clear();
        }
    }

    throw std::runtime_error{"Failed to fetch master node state from any seed node!"};
}

enum class Result { pass, fail, not_found, no_ip };
void print_result(
        const std::string& pubkey,
        Result result,
        const RemoteAddress* addr = nullptr,
        std::chrono::nanoseconds reqtime = 0ns,
        std::string extra = ""s) {
    std::cout << pubkey << ": "
              << (result == Result::pass        ? "pass"
                  : result == Result::fail      ? "FAIL"
                  : result == Result::not_found ? "NOT FOUND"
                  : result == Result::no_ip     ? "NO IP"
                                                : "???")
              << "\n";

    if (!verbose)
        return;

    if (result == Result::pass || result == Result::fail) {
        assert(addr);
        if (auto ed_pk = oxenc::to_hex(addr->view_remote_key()); ed_pk != pubkey) {
            std::cout << " - pre-Beldex-8 server with Ed25519 pubkey " << ed_pk << "\n";
        }
        std::cout << " - request took " << fmt::format("{:.1f}ms", reqtime.count() * 1e-6) << "\n";
    }
    if (!extra.empty())
        std::cout << " - " << extra << "\n";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::vector<std::string> pubkeys_hex;

    for (int i = 1; i < argc; i++) {
        std::string arg{argv[i]};

        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
            continue;
        }

        if (!oxenc::is_hex(arg) || arg.size() != 64)
            return usage(
                    argv[0],
                    "Invalid pubkey (" + std::string{arg} + "): expected 64-character hex pubkey");

        pubkeys_hex.push_back(std::move(arg));
    }

    if (pubkeys_hex.empty())
        return usage(argv[0]);

    Network net;
    auto ep = net.endpoint(Address{"0.0.0.0", 0}, opt::outbound_alpns{{uALPN}});

    auto remotes = fetch_mn_addresses(ep);

    if (verbose)
        std::cout << "\n";

    std::unordered_set<std::string> pubkeys_seen;
    for (const auto& mnpub : pubkeys_hex) {
        if (!pubkeys_seen.insert(mnpub).second) {
            if (verbose)
                std::cerr << "\e[3mIgnoring repeated MN " << mnpub << "\e[0m\n";
            continue;
        }

        auto it = remotes.find(mnpub);
        if (it == remotes.end()) {
            print_result(mnpub, Result::not_found);
            continue;
        }
        if (!it->second) {
            print_result(mnpub, Result::no_ip);
            continue;
        }

        auto& raddr = *it->second;

        auto started = std::chrono::steady_clock::now();

        std::string label =
                fmt::format("{}…{} @ {}", mnpub.substr(0, 8), mnpub.substr(61), raddr.to_string());
        if (verbose)
            std::cerr << "\e[3mTesting " << label << "\e[0m\n\n";

        auto c = ep->connect(raddr, creds);
        auto s = c->open_stream<BTRequestStream>();
        std::promise<nlohmann::json> info_prom;
        s->command("info", "", [&info_prom](message resp) {
            try {
                if (resp.timed_out)
                    throw std::runtime_error{"connection timed out"};
                if (resp.is_error())
                    throw std::runtime_error{"request failed"};

                info_prom.set_value(nlohmann::json::parse(resp.body()));
            } catch (...) {
                info_prom.set_exception(std::current_exception());
            }
        });

        std::string ver;
        try {
            auto info = info_prom.get_future().get()[1];
            ver = fmt::format(
                    "v{}, hf {}",
                    fmt::format("{}", fmt::join(info["version"].get<std::vector<int>>(), ".")),
                    fmt::format("{}", fmt::join(info["hf"].get<std::vector<int>>(), ".")));
        } catch (const std::exception& e) {
            print_result(
                    mnpub,
                    Result::fail,
                    &raddr,
                    std::chrono::steady_clock::now() - started,
                    fmt::format("request failed: {}", e.what()));
            continue;
        }

        print_result(mnpub, Result::pass, &raddr, std::chrono::steady_clock::now() - started, ver);
    }
}
