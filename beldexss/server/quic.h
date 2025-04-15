#pragma once

#include "utils.h"
#include "mqbase.h"

#include <beldexss/crypto/keys.h>
#include <beldexss/logging/beldex_logger.h>
#include <beldexss/rpc/rate_limiter.h>
#include <beldexss/mnode/master_node.h>

#include <oxen/quic.hpp>

namespace beldexss::rpc {
class RequestHandler;
}  // namespace beldexss::rpc

namespace beldexss::server {

namespace quic = oxen::quic;

using quic_callback = std::function<void(quic::message)>;
using Address = quic::Address;

struct PendingRequest {
    std::optional<std::string> name = std::nullopt;
    std::string body;
    quic_callback func = nullptr;

    // Constructor
    PendingRequest(std::string name, std::string body, quic_callback func) :
            name{std::move(name)}, body{std::move(body)}, func{std::move(func)} {}
    PendingRequest(std::string_view name, std::string_view body, quic_callback func) :
            name{name}, body{body}, func{std::move(func)} {}
};

using RequestQueue = std::deque<PendingRequest>;

class QUIC : public MQBase {
    public:
    QUIC(mnode::MasterNode& mnode,
         rpc::RequestHandler& rh,
         rpc::RateLimiter& rl,
         const Address& bind,
         const crypto::ed25519_seckey& sk);
  
  void startup_endpoint();

  void notify(std::vector<connection_id>&, std::string_view notification) override;

  void reachability_test(std::shared_ptr<mnode::mn_test> test) override;

  private:
    const Address local;
    std::unique_ptr<quic::Network> network;
    std::shared_ptr<quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<quic::Endpoint> ep;

    rpc::RequestHandler& request_handler;
    std::function<void(quic::message m)> command_handler;

    std::shared_ptr<quic::Endpoint> create_endpoint();

    void handle_request(quic::message m);

    void handle_onion_request(quic::message m);

    void handle_monitor_message(quic::message m);

    void handle_ping(quic::message m);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace beldexss::server
