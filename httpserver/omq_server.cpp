#include "omq_server.h"

#include "dev_sink.h"
#include "http.h"
#include "beldex_common.h"
#include "beldex_logger.h"
#include "beldexd_key.h"
#include "channel_encryption.hpp"
#include "rate_limiter.h"
#include "request_handler.h"
#include "master_node.h"
#include "string_utils.hpp"

#include <chrono>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <oxenc/base64.h>

#include <optional>
#include <stdexcept>
#include <variant>

namespace beldex {

std::string OxenmqServer::peer_lookup(std::string_view pubkey_bin) const {

    BELDEX_LOG(trace, "[LMQ] Peer Lookup");

    if (pubkey_bin.size() != sizeof(x25519_pubkey))
        return "";
    x25519_pubkey pubkey;
    std::memcpy(pubkey.data(), pubkey_bin.data(), sizeof(x25519_pubkey));

    if (auto mn = master_node_->find_node(pubkey))
        return fmt::format("tcp://{}:{}", mn->ip, mn->omq_port);

    BELDEX_LOG(debug, "[LMQ] peer node not found via x25519 pubkey {}!", pubkey);
    return "";
}

void OxenmqServer::handle_mn_data(oxenmq::Message& message) {

    BELDEX_LOG(debug, "[LMQ] handle_mn_data");
    BELDEX_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    BELDEX_LOG(debug, "[LMQ]   from: {}", oxenc::to_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    master_node_->process_push_batch(ss.str());

    BELDEX_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending MN
    message.send_reply();
};

void OxenmqServer::handle_ping(oxenmq::Message& message) {
    BELDEX_LOG(debug, "Remote pinged me");
    master_node_->update_last_ping(ReachType::OMQ);
    message.send_reply("pong");
}

void OxenmqServer::handle_storage_test(oxenmq::Message& message) {
    if (message.conn.pubkey().size() != 32) {
        // This shouldn't happen as this endpoint should have remote-MN-only permissions, so be
        // noisy
        BELDEX_LOG(err, "bug: invalid mn.storage_test omq request from {} with no pubkey",
                message.remote);
        return message.send_reply("invalid parameters");
    } else if (message.data.size() < 2) {
        BELDEX_LOG(warn, "invalid mn.storage_test omq request from {}: not enough data parts; expected 2, received {}",
                message.remote, message.data.size());
        return message.send_reply("invalid parameters");
    }
    legacy_pubkey tester_pk;
    if (auto node = master_node_->find_node(x25519_pubkey::from_bytes(message.conn.pubkey()))) {
        tester_pk = node->pubkey_legacy;
        BELDEX_LOG(debug, "incoming mn.storage_test request from {}@{}", tester_pk, message.remote);
    } else {
        BELDEX_LOG(warn, "invalid mn.storage_test omq request from {}: sender is not an active MN");
        return message.send_reply("invalid pubkey");
    }

    uint64_t height;
    if (!util::parse_int(message.data[0], height) || !height) {
        BELDEX_LOG(warn, "invalid mn.storage_test omq request from {}@{}: '{}' is not a valid height",
                tester_pk, message.remote, height);
        return message.send_reply("invalid height");
    }
    std::string msg_hash;
    if (message.data[1].size() == 64)
        msg_hash = oxenc::to_hex(message.data[1]);
    else if (message.data[1].size() == 32) {
        msg_hash = oxenc::to_base64(message.data[1]);
        assert(msg_hash.back() == '=');
        msg_hash.pop_back();
    } else {
        BELDEX_LOG(warn, "invalid mn.storage_test omq request from {}@{}: message hash is {} bytes, expected 64 or 32",
                tester_pk, message.remote, message.data[1].size());
        return message.send_reply("invalid msg hash");
    }

    request_handler_->process_storage_test_req(height, tester_pk, msg_hash,
            [reply=message.send_later()](MessageTestStatus status, std::string answer, std::chrono::steady_clock::duration elapsed) {
                switch (status) {
                    case MessageTestStatus::SUCCESS:
                        BELDEX_LOG(debug, "Storage test success after {}", util::friendly_duration(elapsed));
                        reply.reply("OK", answer);
                        return;
                    case MessageTestStatus::WRONG_REQ:
                        reply.reply("wrong request");
                        return;
                    case MessageTestStatus::RETRY:
                        [[fallthrough]]; // If we're getting called then a retry ran out of time
                    case MessageTestStatus::ERROR:
                        // Promote this to `error` once we enforce storage testing
                        BELDEX_LOG(debug, "Failed storage test, tried for {}", util::friendly_duration(elapsed));
                        reply.reply("other");
                }
            });
}

void OxenmqServer::handle_onion_request(
        std::string_view payload,
        OnionRequestMetadata&& data,
        oxenmq::Message::DeferredSend send) {

    data.cb = [send](beldex::Response res) {
        if (BELDEX_LOG_ENABLED(trace))
            BELDEX_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

        if (auto* js = std::get_if<nlohmann::json>(&res.body))
            send.reply(std::to_string(res.status.first), js->dump());
        else
            send.reply(std::to_string(res.status.first), view_body(res));
    };

    if (data.hop_no > MAX_ONION_HOPS)
        return data.cb({http::BAD_REQUEST, "onion request max path length exceeded"sv});

    request_handler_->process_onion_req(payload, std::move(data));
}

void OxenmqServer::handle_onion_request(oxenmq::Message& message) {
    std::pair<std::string_view, OnionRequestMetadata> data;
    try {
        if (message.data.size() != 1)
            throw std::runtime_error{"expected 1 part, got " + std::to_string(message.data.size())};

        data = decode_onion_data(message.data[0]);
    } catch (const std::exception& e) {
        auto msg = "Invalid internal onion request: "s + e.what();
        BELDEX_LOG(err, msg);
        message.send_reply(std::to_string(http::BAD_REQUEST.first), msg);
        return;
    }

    handle_onion_request(data.first, std::move(data.second), message.send_later());
}

void OxenmqServer::handle_get_logs(oxenmq::Message& message) {

    BELDEX_LOG(debug, "Received get_logs request via LMQ");

    auto dev_sink = dynamic_cast<beldex::dev_sink_mt*>(
        spdlog::get("beldex_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        BELDEX_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        auto err_msg = "Developer error: sink #3 is not a dev sink.";
        message.send_reply(err_msg);
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    message.send_reply(val.dump(4));
}

void OxenmqServer::handle_get_stats(oxenmq::Message& message) {

    BELDEX_LOG(debug, "Received get_stats request via LMQ");

    auto payload = master_node_->get_stats();

    message.send_reply(payload);
}

namespace {

template <typename RPC>
void register_client_rpc_endpoint(OxenmqServer::rpc_map& regs) {
    auto call = [](RequestHandler& h, std::string_view params, bool recursive, std::function<void(Response)> cb) {
        RPC req;
        if (params.empty())
            params = "{}"sv;
        if (params.front() == 'd') {
            req.load_from(oxenc::bt_dict_consumer{params});
            req.b64 = false;
        } else {
            auto body = nlohmann::json::parse(params, nullptr, false);
            if (body.is_discarded()) {
                BELDEX_LOG(debug, "Bad OMQ client request: not valid json or bt_dict");
                return cb(Response{http::BAD_REQUEST, "invalid body: expected json or bt_dict"sv});
            }
            req.load_from(body);
        }
        if constexpr (std::is_base_of_v<rpc::recursive, RPC>)
            req.recurse = recursive;
        h.process_client_req(std::move(req), std::move(cb));
    };
    for (auto& name : RPC::names()) {
        [[maybe_unused]] auto [it, ins] = regs.emplace(name, call);
        assert(ins);
    }
}

template <typename... RPC>
OxenmqServer::rpc_map register_client_rpc_endpoints(rpc::type_list<RPC...>) {
    OxenmqServer::rpc_map regs;
    (register_client_rpc_endpoint<RPC>(regs), ...);
    return regs;
}

} // anon. namespace

oxenc::bt_value json_to_bt(nlohmann::json j) {
    if (j.is_object()) {
        oxenc::bt_dict res;
        for (auto& [k, v] : j.items())
            res[k] = json_to_bt(v);
        return res;
    }
    if (j.is_array()) {
        oxenc::bt_list res;
        for (auto& v : j)
            res.push_back(json_to_bt(v));
        return res;
    }
    if (j.is_string())
        return j.get<std::string>();
    if (j.is_boolean())
        return j.get<bool>() ? 1 : 0;
    if (j.is_number_unsigned())
        return j.get<uint64_t>();
    if (j.is_number_integer())
        return j.get<int64_t>();
    BELDEX_LOG(warn, "client request returned json with an unhandled value type, unable to convert to bt");
    throw std::runtime_error{"internal error"};
}

nlohmann::json bt_to_json(oxenc::bt_dict_consumer d) {
    nlohmann::json j;
    while (!d.is_finished()) {
        std::string key{d.key()};
        if (d.is_string())
            j[key] = d.consume_string();
        else if (d.is_dict())
            j[key] = bt_to_json(d.consume_dict_consumer());
        else if (d.is_list())
            j[key] = bt_to_json(d.consume_list_consumer());
        else if (d.is_negative_integer())
            j[key] = d.consume_integer<int64_t>();
        else if (d.is_integer())
            j[key] = d.consume_integer<uint64_t>();
        else
            assert(!"invalid bt type!");
    }
    return j;
}

nlohmann::json bt_to_json(oxenc::bt_list_consumer l) {
    nlohmann::json j = nlohmann::json::array();
    while (!l.is_finished()) {
        if (l.is_string())
            j.push_back(l.consume_string());
        else if (l.is_dict())
            j.push_back(bt_to_json(l.consume_dict_consumer()));
        else if (l.is_list())
            j.push_back(bt_to_json(l.consume_list_consumer()));
        else if (l.is_negative_integer())
            j.push_back(l.consume_integer<int64_t>());
        else if (l.is_integer())
            j.push_back(l.consume_integer<uint64_t>());
        else
            assert(!"invalid bt type!");
    }
    return j;
}

const OxenmqServer::rpc_map OxenmqServer::client_rpc_endpoints =
    register_client_rpc_endpoints(rpc::client_rpc_types{});

void OxenmqServer::handle_client_request(std::string_view method, oxenmq::Message& message, bool forwarded) {
    BELDEX_LOG(debug, "Handling OMQ RPC request for {}", method);
    auto it = client_rpc_endpoints.find(method);
    assert(it != client_rpc_endpoints.end()); // This endpoint shouldn't have been registered if it isn't in here

    const size_t full_size = forwarded ? 2 : 1;
    const size_t empty_body = full_size - 1;
    if (message.data.size() != empty_body && message.data.size() != full_size) {
        BELDEX_LOG(warn, "Invalid {}OMQ RPC request for {}: incorrect number of message parts ({})",
                forwarded ? "forwarded " : "", method, message.data.size());
        message.send_reply(
                std::to_string(http::BAD_REQUEST.first),
                fmt::format("Invalid request: expected {} message parts, received {}",
                    full_size, message.data.size()));
        return;
    }

    if (!forwarded && rate_limiter_->should_rate_limit_client(message.remote)) {
        BELDEX_LOG(debug, "Rate limiting client request from {}", message.remote);
        return message.send_reply(std::to_string(http::TOO_MANY_REQUESTS.first), "Too many requests, try again later");
    }

    try {
        std::string_view params = message.data.size() == full_size ? message.data.back() : ""sv;
        it->second(*request_handler_, params, !forwarded,
            [send=message.send_later(), bt_encoded = !params.empty() && params.front() == 'd']
            (beldex::Response res) {
                std::string dump;
                std::string_view body;
                if (auto* j = std::get_if<nlohmann::json>(&res.body)) {
                    if (bt_encoded)
                        dump = bt_serialize(json_to_bt(std::move(*j)));
                    else
                        dump = j->dump();
                    body = dump;
                } else
                    body = view_body(res);

                if (res.status == http::OK) {
                    BELDEX_LOG(debug, "OMQ RPC request successful, returning {}-byte {} response",
                            body.size(), dump.empty() ? "text" : bt_encoded ? "bt" : "json");
                    // Success: return just the body
                    send.reply(body);
                } else {
                    // On error return [errcode, body]
                    BELDEX_LOG(debug, "OMQ RPC request failed, replying with [{}, {}]", res.status.first, body);
                    send.reply(std::to_string(res.status.first), body);
                }
            });
    } catch (const rpc::parse_error& e) {
        // These exceptions carry a failure message to send back to the client
        BELDEX_LOG(debug, "Invalid request: {}", e.what());
        message.send_reply(std::to_string(http::BAD_REQUEST.first), "invalid request: "s + e.what());
    } catch (const std::exception& e) {
        // Other exceptions might contain something sensitive or irrelevant so warn about it and
        // send back a generic message.
        BELDEX_LOG(warn, "Client request raised an exception: {}", e.what());
        message.send_reply(std::to_string(http::INTERNAL_SERVER_ERROR.first), "request failed");
    }
}

void omq_logger(oxenmq::LogLevel level, const char* file, int line,
        std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case oxenmq::LogLevel::LMQ_LVL:                                            \
        BELDEX_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;

    switch (level) {
        LMQ_LOG_MAP(fatal, critical);
        LMQ_LOG_MAP(error, err);
        LMQ_LOG_MAP(warn, warn);
        LMQ_LOG_MAP(info, info);
        LMQ_LOG_MAP(trace, trace);
        LMQ_LOG_MAP(debug, debug);
    }
#undef LMQ_LOG_MAP
}

OxenmqServer::OxenmqServer(
        const mn_record& me,
        const x25519_seckey& privkey,
        const std::vector<x25519_pubkey>& stats_access_keys) :
    omq_{
        std::string{me.pubkey_x25519.view()},
        std::string{privkey.view()},
        true, // is master node
        [this](auto pk) { return peer_lookup(pk); }, // MN-by-key lookup func
        omq_logger,
        oxenmq::LogLevel::info}
{
    for (const auto& key : stats_access_keys)
        stats_access_keys_.emplace(key.view());

    // clang-format off

    // Endpoints invoked by other MNs
    omq_.add_category("mn", oxenmq::Access{oxenmq::AuthLevel::none, true, false}, 2 /*reserved threads*/, 1000 /*max queue*/)
        .add_request_command("data", [this](auto& m) { handle_mn_data(m); })
        .add_request_command("ping", [this](auto& m) { handle_ping(m); })
        .add_request_command("storage_test", [this](auto& m) { handle_storage_test(m); }) // NB: requires a 60s request timeout
        .add_request_command("onion_request", [this](auto& m) { handle_onion_request(m); })
        .add_request_command("storage_cc", [this](auto& m) {
            if (m.data.size() >= 2) return handle_client_request(m.data[0], m, true);
            BELDEX_LOG(warn, "Invalid forwarded client request: incorrect number of message parts ({})",  m.data.size());
        })
        ;

    // storage.WHATEVER (e.g. storage.store, storage.retrieve, etc.) endpoints are invokable by
    // anyone (i.e. clients) and have the same WHATEVER endpoints as the "method" values for the
    // HTTPS /storage_rpc/v1 endpoint.
    auto st_cat = omq_.add_category("storage", oxenmq::AuthLevel::none, 1 /*reserved threads*/, 200 /*max queue*/);
    for (const auto& [name, _cb] : RequestHandler::client_rpc_endpoints)
        st_cat.add_request_command(std::string{name}, [this, name=name](auto& m) { handle_client_request(name, m); });

    // Endpoints invokable by a local admin
    omq_.add_category("service", oxenmq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { handle_get_logs(m); })
        ;

    // We send a sub.block to beldexd to tell it to push new block notifications to us via this
    // endpoint:
    omq_.add_category("notify", oxenmq::AuthLevel::admin)
        .add_request_command("block", [this](auto& m) {
            BELDEX_LOG(debug, "Recieved new block notification from beldexd, updating swarms");
            if (master_node_) master_node_->update_swarms();
        });

    // clang-format on
    omq_.set_general_threads(1);

    omq_.MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver, and swarm msg serialization)

    // Be explicit about wanting per-MN unique connection IDs:
    omq_.EPHEMERAL_ROUTING_ID = false;
}

void OxenmqServer::connect_beldexd(const oxenmq::address& beldexd_rpc) {
    // Establish our persistent connection to beldexd.
    auto start = std::chrono::steady_clock::now();
    while (true) {
        std::promise<bool> prom;
        BELDEX_LOG(info, "Establishing connection to beldexd...");
        omq_.connect_remote(beldexd_rpc,
            [this, &prom](auto cid) { beldexd_conn_ = cid; prom.set_value(true); },
            [&prom, &beldexd_rpc](auto&&, std::string_view reason) {
                BELDEX_LOG(warn, "failed to connect to local beldexd @ {}: {}; retrying", beldexd_rpc, reason);
                prom.set_value(false);
            },
            // Turn this off since we are using oxenmq's own key and don't want to replace some existing
            // connection to it that might also be using that pubkey:
            oxenmq::connect_option::ephemeral_routing_id{},
            oxenmq::AuthLevel::admin);

        if (prom.get_future().get()) {
            BELDEX_LOG(info, "Connected to beldexd in {}",
                    util::short_duration(std::chrono::steady_clock::now() - start));
            break;
        }
        std::this_thread::sleep_for(500ms);
    }
}

void OxenmqServer::init(MasterNode* mn, RequestHandler* rh, RateLimiter* rl, oxenmq::address beldexd_rpc) {
    // Initialization happens in 3 steps:
    // - connect to beldexd
    // - get initial block update from beldexd
    // - start OMQ and HTTPS listeners
    assert(!master_node_);
    master_node_ = mn;
    request_handler_ = rh;
    rate_limiter_ = rl;
    omq_.start();
    // Block until we are connected to beldexd:
    connect_beldexd(beldexd_rpc);

    // Block until we get a block update from beldexd:
    master_node_->on_beldexd_connected();

    // start omq listener
    const auto& me = master_node_->own_address();
    BELDEX_LOG(info, "Starting listening for OxenMQ connections on port {}", me.omq_port);
    auto omq_prom = std::make_shared<std::promise<void>>();
    auto omq_future = omq_prom->get_future();
    omq_.listen_curve(
        fmt::format("tcp://0.0.0.0:{}", me.omq_port),
        [this](std::string_view /*addr*/, std::string_view pk, bool /*mn*/) {
            return stats_access_keys_.count(std::string{pk})
                ? oxenmq::AuthLevel::admin : oxenmq::AuthLevel::none;
        },
        [prom=std::move(omq_prom)](bool listen_success) {
            if (listen_success)
                prom->set_value();
            else {
                try { throw std::runtime_error{""}; }
                catch (...) { prom->set_exception(std::current_exception()); }
            }
        });
    try {
        omq_future.get();
    } catch (const std::runtime_error&) {
        auto msg = fmt::format("OxenMQ server failed to bind to port {}", me.omq_port);
        BELDEX_LOG(critical, msg);
        throw std::runtime_error{msg};
    }

    // The https server startup happens in main(), after we return
}

std::string OxenmqServer::encode_onion_data(std::string_view payload, const OnionRequestMetadata& data) {
    return oxenc::bt_serialize<oxenc::bt_dict>({
            {"data", payload},
            {"enc_type", to_string(data.enc_type)},
            {"ephemeral_key", data.ephem_key.view()},
            {"hop_no", data.hop_no},
    });
}

std::pair<std::string_view, OnionRequestMetadata> OxenmqServer::decode_onion_data(std::string_view data) {
    // NB: stream parsing here is alphabetical (that's also why these keys *aren't* constexprs: that
    // would potentially be error-prone if someone changed them without noticing the sort order
    // requirements).
    std::pair<std::string_view, OnionRequestMetadata> result;
    auto& [payload, meta] = result;
    oxenc::bt_dict_consumer d{data};
    if (!d.skip_until("data"))
        throw std::runtime_error{"required data payload not found"};
    payload = d.consume_string_view();

    if (d.skip_until("enc_type"))
        meta.enc_type = parse_enc_type(d.consume_string_view());
    else
        meta.enc_type = EncryptType::aes_gcm;

    if (!d.skip_until("ephemeral_key"))
        throw std::runtime_error{"ephemeral key not found"};
    meta.ephem_key = x25519_pubkey::from_bytes(d.consume_string_view());

    if (d.skip_until("hop_no"))
        meta.hop_no = d.consume_integer<int>();
    if (meta.hop_no < 1)
        meta.hop_no = 1;

    return result;
}

} // namespace beldex
