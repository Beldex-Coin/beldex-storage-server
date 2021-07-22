#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <oxenmq/oxenmq.h>
#include <nlohmann/json_fwd.hpp>

#include "oxenmq/bt_serialize.h"
#include "mn_record.h"

namespace beldex {

class MasterNode;
class RequestHandler;
class RateLimiter;
struct Response;
struct OnionRequestMetadata;

void omq_logger(oxenmq::LogLevel level, const char* file, int line,
        std::string message);

oxenmq::bt_value json_to_bt(nlohmann::json j);

nlohmann::json bt_to_json(oxenmq::bt_dict_consumer d);
nlohmann::json bt_to_json(oxenmq::bt_list_consumer l);

class OxenmqServer {

    oxenmq::OxenMQ omq_;
    oxenmq::ConnectionID beldexd_conn_;

    // Has information about current MNs
    MasterNode* master_node_ = nullptr;

    RequestHandler* request_handler_ = nullptr;

    RateLimiter* rate_limiter_ = nullptr;

    // Get node's address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer MN
    void handle_mn_data(oxenmq::Message& message);

    // Called starting at HF18 for SS-to-SS onion requests
    void handle_onion_request(oxenmq::Message& message);

    // Handles a decoded onion request
    void handle_onion_request(
            std::string_view payload,
            OnionRequestMetadata&& data,
            oxenmq::Message::DeferredSend send);

    // mn.ping - sent by MNs to ping each other.
    void handle_ping(oxenmq::Message& message);

    // mn.storage_test
    void handle_storage_test(oxenmq::Message& message);

    /// storage.(whatever) -- client request handling.  These reply with [BODY] on success or [CODE,
    /// BODY] on failure (where BODY typically is some sort of error message).
    ///
    /// The return value is either:
    /// [VALUE] for a successful response
    /// [ERRCODE, VALUE] for a failure.
    ///
    /// Successful responses will generally return VALUE as json, if the request was json (or
    /// empty), or a bt-encoded dict if the request was bt-encoded.  Note that base64-encoded values
    /// for json responses are raw byte values (*not* base64-encoded) when returning a bt-encoded
    /// value.
    ///
    /// Failure responses are an HTTP error number and a plain text failure string.
    ///
    /// `forwarded` is set if this request was forwarded from another swarm member rather than being
    /// direct from the client; the request is handled identically except that these forwarded
    /// requests are not-reforwarded again, and the method name is prepended on the argument list.
    void handle_client_request(std::string_view method, oxenmq::Message& message, bool forwarded = false);

    void handle_get_logs(oxenmq::Message& message);

    void handle_get_stats(oxenmq::Message& message);

    // Access pubkeys for the 'service' command category (for access stats & logs), in binary.
    std::unordered_set<std::string> stats_access_keys_;

    // Connects (and blocks until connected) to beldexd.  When this returns an beldexd connection will
    // be available (and beldexd_conn_ will be set to the connection id to reach it).
    void connect_beldexd(const oxenmq::address& beldexd_rpc);

  public:
    OxenmqServer(
            const mn_record& me,
            const x25519_seckey& privkey,
            const std::vector<x25519_pubkey>& stats_access_keys_hex);

    // Initialize oxenmq; return a future that completes once we have connected to and initialized
    // from beldexd.
    void init(MasterNode* mn, RequestHandler* rh, RateLimiter* rl, oxenmq::address beldexd_rpc);

    /// Dereferencing via * or -> accesses the contained OxenMQ instance.
    oxenmq::OxenMQ& operator*() { return omq_; }
    oxenmq::OxenMQ* operator->() { return &omq_; }

    // Returns the OMQ ConnectionID for the connection to beldexd.
    const oxenmq::ConnectionID& beldexd_conn() const { return beldexd_conn_; }

    // Invokes a request to the local beldexd; given arguments (which must contain at least the
    // request name and a callback) are forwarded as `omq.request(connid, ...)`.
    template <typename... Args>
    void beldexd_request(Args&&... args) {
        assert(beldexd_conn_);
        omq_.request(beldexd_conn(), std::forward<Args>(args)...);
    }

    // Sends a one-way message to the local beldexd; arguments are forwarded as `omq.send(connid,
    // ...)` (and must contain at least a command name).
    template <typename... Args>
    void beldexd_send(Args&&... args) {
        assert(beldexd_conn_);
        omq_.send(beldexd_conn(), std::forward<Args>(args)...);
    }

    // Encodes the onion request data that we send for internal MN-to-MN onion requests starting at
    // HF18.
    static std::string encode_onion_data(std::string_view payload, const OnionRequestMetadata& data);
    // Decodes onion request data; throws if invalid formatted or missing required fields.
    static std::pair<std::string_view, OnionRequestMetadata> decode_onion_data(std::string_view data);

    using rpc_map = std::unordered_map<
        std::string_view,
        std::function<void(RequestHandler&, std::string_view params, bool recurse, std::function<void(Response)>)>
    >;
    static const rpc_map client_rpc_endpoints;
};

} // namespace beldex
