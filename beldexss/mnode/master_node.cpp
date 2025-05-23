#include "master_node.h"

#include "serialization.h"
#include "sn_test.h"
#include <fmt/ranges.h>
#include <oxenmq/connections.h>
#include <oxen/quic/format.hpp>
#include <beldexss/version.h>
#include <beldexss/common/mainnet.h>
#include <beldexss/rpc/request_handler.h>
#include <beldexss/server/base.h>
#include <beldexss/server/omq.h>
#include <beldexss/logging/beldex_logger.h>
#include <iterator>
#include <numeric>
#include <beldexss/utils/string_utils.hpp>
#include <beldexss/utils/random.hpp>

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>

#include <algorithm>
#include <tuple>
#include <utility>

using json = nlohmann::json;

namespace beldexss::mnode {

using namespace oxen;
static auto logcat = log::Cat("mnode");

// Threshold of missing data records at which we start warning and consult bootstrap nodes
// (mainly so that we don't bother producing warning spam or going to the bootstrap just for a
// few new nodes that will often have missing info for a few minutes).
using MISSING_PUBKEY_THRESHOLD = std::ratio<3, 100>;

/// TODO: there should be config.h to store constants like these
constexpr auto BELDEXD_PING_INTERVAL = 30s;

constexpr auto NEW_SWARM_MEMBER_INTERVAL = 10s;

MasterNode::MasterNode(
        const crypto::legacy_keypair& keys,
        const contact& contact,
        server::OMQ& omq_server,
        const std::filesystem::path& db_location,
        const bool force_start) :
        force_start_{force_start},
        db_{std::make_unique<Database>(db_location)},
        our_keys_{keys},
        our_contact_{contact},
        network_{*omq_server},
        omq_server_{omq_server},
        all_stats_{*omq_server} {
    mq_servers_.push_back(&omq_server);

    log::info(logcat, "Requesting initial swarm state");

    omq_server->add_timer(
            [this] {
                std::lock_guard l{mn_mutex_};
                db_->clean_expired();
            },
            Database::CLEANUP_PERIOD);

    omq_server->add_timer([this] { check_new_members(); }, NEW_SWARM_MEMBER_INTERVAL);

    // We really want to make sure nodes don't get stuck in "syncing" mode,
    // so if we are still "syncing" after a long time, activate MN regardless
    auto delay_timer = std::make_shared<oxenmq::TimerID>();
    auto& dtimer = *delay_timer;  // Get reference before we move away the shared_ptr
    omq_server_->add_timer(
            dtimer,
            [this, timer = std::move(delay_timer)] {
                omq_server_->cancel_timer(*timer);
                std::lock_guard lock{mn_mutex_};
                if (!syncing_)
                    return;
                log::warning(logcat, "Block syncing is taking too long, activating SS regardless");
                syncing_ = false;
            },
            1h);
}

void MasterNode::on_beldexd_connected() {
    // This should be the first time we ever trigger a block update from Oxen, i.e. the initial
    // call to `update_swarms` should not early out which would cause a deadlock on the promise.
    assert(!updating_swarms_.load());
    auto started = std::chrono::steady_clock::now();

    bool success;
    do {
        std::promise<bool> update_swarms_promise;
        std::future<bool> update_swarms_result = update_swarms_promise.get_future();
        update_swarms(&update_swarms_promise);

        while (update_swarms_result.wait_for(5s) != std::future_status::ready)
            log::warning(logcat, "Still waiting for initial block update from beldexd...");
        success = update_swarms_result.get();
    } while (!success);

    log::info(
            logcat,
            "Got initial block update from beldexd in {} (height {}/{} HF {}.{})",
            util::short_duration(std::chrono::steady_clock::now() - started),
            block_height_,
            block_hash_,
            hardfork_.first,
            hardfork_.second);

    beldexd_ping();
    omq_server_->add_timer([this] { beldexd_ping(); }, BELDEXD_PING_INTERVAL);
    omq_server_->add_timer([this] { ping_peers(); }, reachability_testing::TESTING_TIMER_INTERVAL);
}

template <typename T>
static T get_or(const json& j, std::string_view key, std::common_type_t<T> default_val) {
    if (auto it = j.find(key); it != j.end())
        return it->get<T>();
    return default_val;
}

static std::optional<block_update> parse_swarm_update(
        std::string_view response_body, const crypto::legacy_pubkey& our_pk) {
    if (response_body.empty()) {
        log::critical(logcat, "Bad beldexd rpc response: no response body");
        throw std::runtime_error("Failed to parse swarm update");
    }

    std::optional<block_update> maybe_bu;

    log::trace(logcat, "swarm response: <{}>", response_body);

    try {
        json result = json::parse(response_body, nullptr, true);
        if (result.value<bool>("unchanged", false))
            return maybe_bu;  // nullopt

        auto& bu = maybe_bu.emplace();

        bu.height = result.at("height").get<uint64_t>();
        bu.block_hash = result.at("block_hash").get<std::string>();
        bu.hardfork = result.at("hardfork").get<int>();
        bu.mnode_revision = result.value<int>("mnode_revision", 0);

        const json master_node_states = result.at("master_node_states");

        int missing_contacts = 0, total = 0;

        for (const auto& mn_json : master_node_states) {
            total++;
            const auto& pk_hex = mn_json.at("master_node_pubkey").get_ref<const std::string&>();
            const auto pk_x25519_hex = mn_json.value<std::string_view>("pubkey_x25519", ""sv);
            const auto pk_ed25519_hex = mn_json.value<std::string_view>("pubkey_ed25519", ""sv);

            auto pk = crypto::legacy_pubkey::from_hex(pk_hex);
            auto& c = bu.contacts[pk];
            c = contact{
                    ipv4{mn_json.value<std::string>("public_ip", "0.0.0.0")},
                    mn_json.value<uint16_t>("storage_port", 0),
                    mn_json.value<uint16_t>("storage_lmq_port", 0),
                    mn_json.value<std::array<uint16_t, 3>>("storage_server_version", {0, 0, 0}),
                    pk_ed25519_hex.empty() ? crypto::ed25519_pubkey{}
                                           : crypto::ed25519_pubkey::from_hex(pk_ed25519_hex),
                    pk_x25519_hex.empty() ? crypto::x25519_pubkey{}
                                          : crypto::x25519_pubkey::from_hex(pk_x25519_hex)};

            if (!c) {
                // beldexd hasn't yet received an uptime proof from this node
                missing_contacts++;
                log::debug(logcat, "contact info is missing from master node info {}", pk_hex);
            }
            const swarm_id_t swarm_id = mn_json.at("swarm_id").get<swarm_id_t>();
            
            if (swarm_id != INVALID_SWARM_ID)
                bu.swarms[swarm_id].insert(pk);
            else if (pk == our_pk)
                bu.decommed = true;

        }

        if (missing_contacts >
            MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den) {
            log::warning(
                    logcat,
                    "Missing contact info for {}/{} master nodes; "
                    "beldexd may be out of sync with the network",
                    missing_contacts,
                    total);
        }
    } catch (const std::exception& e) {
        log::critical(logcat, "Bad beldexd rpc response: invalid json ({})", e.what());
        throw std::runtime_error("Failed to parse swarm update");
    }

    return maybe_bu;
}

void MasterNode::register_mq_server(server::MQBase* server) {
    mq_servers_.push_back(server);
}

void MasterNode::bootstrap_fallback() {
    std::lock_guard guard(mn_mutex_);

    log::trace(logcat, "Bootstrapping peer data");

    // TODO: once all bootstraps are on 11.x releases, we can change the fields value to be an array
    // of field names rather than this dict of {"field": true, "field2": true, ...} pairs.
    std::string params = json{
            {"fields",
             {
                     {"master_node_pubkey", true},
                     {"swarm_id", true},
                     {"storage_port", true},
                     {"public_ip", true},
                     {"height", true},
                     {"block_hash", true},
                     {"hardfork", true},
                     {"mnode_revision", true},
                     {"pubkey_x25519", true},
                     {"pubkey_ed25519", true},
                     {"storage_lmq_port", true},
                     {"storage_server_version", true},
             }}}.dump();


    std::vector<oxenmq::address> seed_nodes;
    if (beldexss::is_mainnet) {
        seed_nodes.emplace_back(
                "curve://public.beldex.io:29091/"
                "eee01f183b2079a529f4ba8933c0f0fcb8053337e003870ef6467a97f2259d73");
        seed_nodes.emplace_back(
                "curve://seed1.beldex.io:29091/"
                "37659353131815666979acea91cefa909e3413811a5453c434879b3d7e5b7031");
        seed_nodes.emplace_back(
                "curve://seed2.rpcnode.stream:29091/"
                "e06f6b3396b00430ff1ecfaeaa6f68030b5bcd8c3fd2fe813a0a5baa1cb9d008");
        seed_nodes.emplace_back(
                "curve://seed3.beldex.io:29091/"
                "bcf02e1364237e549f45accc8cab95895198c0bc0e78a86f52df74d1c2dd8204");
    } else {
        seed_nodes.emplace_back(
                "curve://54.80.140.73:19091/"
                "6713a9a96ea47b25223de373edc0203cf8b4d625e96bf2656b042db8e398064");
    }

    auto req_counter = std::make_shared<std::atomic<int>>(0);

    for (const auto& addr : seed_nodes) {
        auto connid = omq_server_->connect_remote(
                addr,
                [addr](oxenmq::ConnectionID) {
                    log::debug(logcat, "Connected to bootstrap node {}", addr.full_address());
                },
                [addr](oxenmq::ConnectionID, auto reason) {
                    log::debug(
                            logcat,
                            "Failed to connect to bootstrap node {}: {}",
                            addr.full_address(),
                            reason);
                },
                oxenmq::connect_option::ephemeral_routing_id{true},
                oxenmq::connect_option::timeout{BOOTSTRAP_TIMEOUT});
        omq_server_->request(
                connid,
                "rpc.get_master_nodes",
                [this, connid, addr, req_counter, node_count = (int)seed_nodes.size()](
                        bool success, std::vector<std::string> data) {
                    if (!success)
                        log::error(
                                logcat,
                                "Failed to contact bootstrap node {}: request timed out",
                                addr.full_address());
                    else if (data.empty())
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "no "
                                "data",
                                addr.full_address());
                    else if (data[0] != "200")
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "failure status {}",
                                addr.full_address(),
                                data[0]);
                    else {
                        log::info(
                                logcat,
                                "Parsing response from bootstrap node {}",
                                addr.full_address());
                        try {
                            std::lock_guard lock{mn_mutex_};
                            if (auto update = parse_swarm_update(data[1], our_keys_.pub))
                                on_bootstrap_update(std::move(*update));
                            log::info(logcat, "Bootstrapped from {}", addr.full_address());
                        } catch (const std::exception& e) {
                            log::error(
                                    logcat,
                                    "Exception caught while bootstrapping from {}: {}",
                                    addr.full_address(),
                                    e.what());
                        }
                    }

                    omq_server_->disconnect(connid);

                    if (++(*req_counter) == node_count) {
                        log::info(logcat, "Bootstrapping done");
                        if (target_height_ > 0)
                            update_swarms();
                        else {
                            // If target height is still 0 after having contacted
                            // (successfully or not) all seed nodes, just assume we have
                            // finished syncing. (Otherwise we will never get a chance
                            // to update syncing status.)
                            log::warning(
                                    logcat,
                                    "Could not contact any bootstrap nodes to get target "
                                    "height. Assuming our local height is correct.");
                            syncing_ = false;
                        }
                    }
                },
                params,
                oxenmq::send_option::request_timeout{BOOTSTRAP_TIMEOUT});
    }
}

void MasterNode::shutdown() {
    shutting_down_ = true;
}

bool MasterNode::mnode_ready(std::string* reason) {
    if (shutting_down()) {
        if (reason)
            *reason = "shutting down";
        return false;
    }

    std::lock_guard guard(mn_mutex_);

    std::vector<std::string> problems;

    if (!hf_at_least(STORAGE_SERVER_HARDFORK))
        problems.push_back(fmt::format(
                "not yet on hardfork {}.{}",
                STORAGE_SERVER_HARDFORK.first,
                STORAGE_SERVER_HARDFORK.second));
    if (syncing_)
        problems.push_back("not done syncing");

    if (reason && !problems.empty())
        *reason = "{}"_format(fmt::join(problems, "; "));

    return problems.empty() || force_start_;
}

bool MasterNode::is_swarm_peer(const crypto::x25519_pubkey& xpk) {
    return swarm_.is_member(xpk);
}

void MasterNode::send_onion_to_mn(
    const contact& ct,
    std::string_view payload,
        rpc::OnionRequestMetadata&& data,
        std::function<void(bool success, std::vector<std::string> data)> cb) const {
    // Since HF18 we bencode everything (which is a bit more compact than sending the eph_key in
    // hex, plus flexible enough to allow other metadata such as the hop number and the
    // encryption type).
    data.hop_no++;
    omq_server_->request(
            ct.pubkey_x25519.view(),
            "mn.onion_request",
            std::move(cb),
            oxenmq::send_option::request_timeout{30s},
            omq_server_.encode_onion_data(payload, data));
}

void MasterNode::record_proxy_request() {
    all_stats_.bump_proxy_requests();
}

void MasterNode::record_onion_request() {
    all_stats_.bump_onion_requests();
}

void MasterNode::record_retrieve_request() {
    all_stats_.bump_retrieve_requests();
}

void MasterNode::check_new_members() {
    for (const auto& pk : swarm_.extract_pending_members()) {
        auto c = network_.contacts.find(pk);
        if (!c || !*c) {
            // We don't have contact info, so don't do anything right now and this will get
            // triggered again later.
            log::debug(
                    logcat,
                    "Leaving {} as pending: node {}",
                    pk,
                    c ? "has missing contact info" : "is unknown");
            continue;
        }

        if (c->version < NEW_SWARM_MEMBER_HANDSHAKE_VERSION) {
            log::debug(
                    logcat,
                    "Skipping handshake with new swarm member {}: v{}+ required, remote is v{}",
                    pk,
                    fmt::join(NEW_SWARM_MEMBER_HANDSHAKE_VERSION, "."),
                    fmt::join(c->version, "."));
            swarm_.set_member_ready(pk);
            continue;
        }

        log::debug(logcat, "Initiating contact with new swarm member {}", pk);
        omq_server_->request(
                c->pubkey_x25519.view(),
                "mn.data_ready",
                [this, pk](bool success, std::vector<std::string> data) {
                    if (data.empty()) {
                        success = false;
                        data.push_back("Empty reply"s);
                    } else if (data[0] != "OK"sv) {
                        success = false;
                    }
                    if (!success) {
                        log::info(
                                logcat,
                                "Failed to connect to remote SS {} to initiate new "
                                "data transfer ({}); will retry soon",
                                pk,
                                fmt::join(data, ", "));
                        return;
                    }
                    log::debug(
                            logcat,
                            "Successful contact made with swarm member {}, queuing a message push",
                            pk);
                    swarm_.set_member_ready(pk);
                });
    }

    if (auto send_now = swarm_.extract_ready_members(); !send_now.empty()) {
        auto msgs = db_->retrieve_all();
        log::debug(
                logcat,
                "Initiating swarm message dump ({} message) to new swarm member(s): {}",
                msgs.size(),
                fmt::join(send_now, ", "));
        relay_messages(std::move(msgs), send_now);
    }
}

static void write_metadata(
        oxenc::bt_dict_producer& d, std::string_view pubkey, const message& msg) {
    d.append("@", pubkey);
    d.append("h", msg.hash);
    d.append("n", to_int(msg.msg_namespace));
    d.append("t", to_epoch_ms(msg.timestamp));
    d.append("z", to_epoch_ms(msg.expiry));
}

void MasterNode::send_notifies(message msg) {
    auto pubkey = msg.pubkey.prefixed_raw();
    std::vector<server::connection_id> relay_to, relay_to_with_data;

    for (auto* s : mq_servers_)
        s->get_notifiers(msg, relay_to, relay_to_with_data);

    if (relay_to.empty() && relay_to_with_data.empty())
        return;

    // We output a dict with keys (in order):
    // - @ pubkey
    // - h msg hash
    // - n msg namespace
    // - t msg timestamp
    // - z msg expiry
    // - ~ msg data (optional)
    constexpr size_t metadata_size = 2       // d...e
                                   + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                   + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                   + 3 + 8   // 1:n and i-32768e
                                   + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                   + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                   + 10;     // safety margin

    oxenc::bt_dict_producer d;
    d.reserve(
            relay_to_with_data.empty() ? metadata_size
                                       : metadata_size  // all the metadata above
                                                 + 3    // 1:~
                                                 + 8    // 76800: plus a couple bytes to grow
                                                 + msg.data.size());

    write_metadata(d, pubkey, msg);

    if (!relay_to.empty())
        for (auto* s : mq_servers_)
            s->notify(relay_to, d.view());

    if (!relay_to_with_data.empty()) {
        d.append("~", msg.data);
        for (auto* s : mq_servers_)
            s->notify(relay_to_with_data, d.view());
    }
}
bool MasterNode::process_store(
        message msg, bool* new_msg, std::chrono::system_clock::time_point* expiry) {
    std::lock_guard guard{mn_mutex_};
    /// only accept a message if we are in a swarm
    if (!swarm_.is_valid()) {
        // This should never be printed now that we have "mnode_ready"
        log::error(logcat, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database (if not already present)
    const auto result = db_->store(msg, expiry);
    if (new_msg)
        *new_msg = result == StoreResult::New;

    if (result == StoreResult::New)
        send_notifies(std::move(msg));

    return result != StoreResult::Full;
}

void MasterNode::save_bulk(const std::vector<message>& msgs) {
    try {
        db_->bulk_store(msgs);
    } catch (const std::exception& e) {
        log::error(logcat, "failed to save batch to the database: {}", e.what());
        return;
    }

    log::trace(logcat, "saved messages count: {}", msgs.size());
}

void MasterNode::on_bootstrap_update(block_update&& bu) {
    swarm_.update_swarms(std::move(bu.swarms), bu.contacts);
    target_height_ = std::max(target_height_, bu.height);
}

void MasterNode::on_mnodes_update(block_update&& bu) {
    hf_revision net_ver{bu.hardfork, bu.mnode_revision};
    if (hardfork_ != net_ver) {
        log::info(logcat, "New hardfork: {}.{}", net_ver.first, net_ver.second);
        hardfork_ = net_ver;
    }

    if (syncing_ && target_height_ != 0) {
        syncing_ = bu.height < target_height_;
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        log::debug(logcat, "Still syncing: {}/{}", bu.height, target_height_);
        // Note that because we are still syncing, we won't update our swarm id
        return;
    }

    if (bu.block_hash != block_hash_) {
        log::debug(logcat, "new block, height: {}, hash: {}", bu.height, bu.block_hash);
        block_height_ = bu.height;
        block_hash_ = bu.block_hash;
    } else {
        log::trace(logcat, "already seen this block");
        return;
    }

    bool ready;
    if (std::string reason; !(ready = mnode_ready(&reason)))
        log::warning(logcat, "Storage server is still not ready: {}", reason);
    else if (!active_) {
        // NOTE: because we never reset `active_` after we get decommissioned, this code won't run
        // when the node comes back again
        log::info(logcat, "Storage server is now active!");
        active_ = true;
    }

    auto events = swarm_.update_swarms(std::move(bu.swarms), bu.contacts);

    if (const MnodeStatus status = events.our_swarm_id != INVALID_SWARM_ID ? MnodeStatus::ACTIVE
                                 : bu.decommed ? MnodeStatus::DECOMMISSIONED
                                               : MnodeStatus::UNSTAKED;
        status != status_) {

        log::info(logcat, "Node status updated: {}", status);
        status_ = status;
    }
    if (!ready)
        return;

    if (!events.new_swarms.empty())
        bootstrap_swarms(events.new_swarms);
        
    if (events.dissolved)
       /// Go through all our PK and push them accordingly
        bootstrap_swarms();
}

void MasterNode::update_swarms(std::promise<bool>* on_finish) {
    if (updating_swarms_.exchange(true)) {
        log::debug(logcat, "Swarm update already in progress, not sending another update request");
        return;
    }

    std::lock_guard lock{mn_mutex_};

    log::debug(logcat, "Swarm update triggered");

    json params{
            {"fields",
             {
                     "block_hash",
                     "hardfork",
                     "height",
                     "pubkey_ed25519",
                     "pubkey_x25519",
                     "public_ip",
                     "master_node_pubkey",
                     "mnode_revision",
                     "storage_lmq_port",
                     "storage_port",
                     "storage_server_version",
                     "swarm_id",
             }},

            {"active_only", false}};
    if (got_first_response_ && !block_hash_.empty())
        params["poll_block_hash"] = block_hash_;

    omq_server_.beldexd_request(
            "rpc.get_master_nodes",
            [this, on_finish](bool success, std::vector<std::string> data) {
                updating_swarms_ = false;
                if (!success || data.size() < 2 || data[0] != "200") {
                    log::critical(
                        logcat,
                        "Failed to retrieve mnode list from beldexd: {}",
                        fmt::join(data, " "));
            if (on_finish)
                        on_finish->set_value(false);
                    return;
                }

                try {
                    process_mnodes_update(data[1]);
                } catch (const std::exception& e) {
                    log::error(logcat, "Exception caught on swarm update: {}", e.what());
                    if (on_finish)
                        on_finish->set_value(false);    
                    return;
                }
                if (on_finish)
                    on_finish->set_value(true);
            },
            params.dump());
}

void MasterNode::process_mnodes_update(std::string_view data) {
    auto maybe_bu = parse_swarm_update(data, our_keys_.pub);
    std::lock_guard lock{mn_mutex_};
    if (maybe_bu) {
        log::debug(logcat, "Blockchain updated, rebuilding swarm list");
        on_mnodes_update(std::move(*maybe_bu));
    }

    if (got_first_response_.exchange(true))
        return;

    log::info(logcat, "Got initial swarm information from local Beldexd");
    // This is our very first response and so we *may* want to try falling back to the bootstrap
    // node *if* our response looks sparse: this will typically happen for a fresh master node
    // because IP/port distribution through the network can take up to an hour.  We don't really
    // want to hit the bootstrap nodes when we don't have to, though, so only do it if our responses
    // is missing more than 3% of proof data (IPs/ports/ed25519/x25519 pubkeys) or we got back fewer
    // than 100 MNs (10 on testnet).
    //
    // (In the future it would be nice to eliminate this by putting all the required data on chain,
    // and get rid of needing to consult bootstrap nodes: but currently we still need this to deal
    // with the lag).

    auto [total, contactable] = network_.contacts.counts();
    auto missing = total - contactable;

    if (total >= (beldexss::is_mainnet ? 100 : 10) &&
        missing <= MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den) {
        log::info(
                logcat,
                "Initialized from beldexd with {}/{} contactable master nodes",
                contactable,
                total);
        syncing_ = false;
    } else {
        log::info(
                logcat,
                "Detected some missing MN data ({}/{} contactable); "
                "falling back to bootstrap nodes for help",
                contactable,
                total);
        bootstrap_fallback();
    }
}

void MasterNode::update_last_ping(ReachType type) {
    reach_records_.incoming_ping(type);
}

void MasterNode::ping_peers() {
    std::lock_guard lock{mn_mutex_};

    // TODO: Don't do anything until we are fully funded

    if (status_ == MnodeStatus::UNSTAKED || status_ == MnodeStatus::UNKNOWN) {
        log::trace(logcat, "Skipping peer testing (unstaked)");
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // Check if we've been tested (reached) recently ourselves
    reach_records_.check_incoming_tests(now);

    if (status_ == MnodeStatus::DECOMMISSIONED) {
        log::trace(logcat, "Skipping peer testing (decommissioned)");
        return;
    }

    /// We always test nodes due to be tested plus one general, non-failing node.

    auto to_test = reach_records_.get_failing(now);
    for (int i = 0; i < reachability_testing::RANDOM_TESTS_PER_TICK; i++) {
        auto rando = reach_records_.next_random(swarm_, now);
        if (!rando)
            break;
        to_test.emplace_back(std::move(*rando), 0);
    }
    if (to_test.empty())
        log::trace(logcat, "no nodes to test this tick");
    else
        log::debug(logcat, "{} nodes to test", to_test.size());
    for (const auto& [mn, prev_fails] : to_test)
        test_reachability(mn, prev_fails);
}

void MasterNode::test_reachability(const crypto::legacy_pubkey& mn, int previous_failures) {
    log::debug(
            logcat,
            "Testing {} MN {} for reachability",
            previous_failures > 0 ? "previously failing" : "random",
            mn);
    auto http = http_.lock();
    if (!http) {
        log::debug(logcat, "Skipping reachability test during shutdown");
        return;
    }

    auto c = network_.contacts.find(mn);
    if (!c || !*c) {
        // beldexd won't accept uncontactable info in an uptime proof, which means if we get here the
        // node hasn't sent an uptime proof; we could treat it as a failure, but that seems
        // unnecessary since beldexd will already fail the master node for not sending uptime proofs.
        log::debug(logcat, "Not testing {}: node is uncontactable", mn);
        reach_records_.remove_node_from_failing(mn);
        return;
    }

    auto test = std::make_shared<mn_test>(
            mn,
            1 + mq_servers_.size(),
            [this, previous_failures](const crypto::legacy_pubkey& mn, bool passed) {
                report_reachability(mn, passed, previous_failures);
            });

    for (auto* mq : mq_servers_)
        mq->reachability_test(test);

    auto url = fmt::format("https://{}:{}/ping_test/v1", c->ip, c->https_port);
    std::optional<std::string> host;
    host = "{}.mnode"_format(oxenc::to_base32z(mn.view()));

    log::debug(logcat, "Sending HTTPS ping to {} @ {}", mn, url);
    http->post(
            [test](cpr::Response r) {
                const auto& pk = test->pubkey;
                bool success = false;
                if (r.error.code != cpr::ErrorCode::OK) {
                    log::debug(logcat, "FAILED HTTPS ping test of {}: {}", pk, r.error.message);
                } else if (r.status_code != 200) {
                    log::debug(
                            logcat,
                            "FAILED HTTPS ping test of {}: received non-200 status {} {}",
                            pk,
                            r.status_code,
                            r.status_line);
                } else {
                    if (auto it = r.header.find(http::MNODE_PUBKEY_HEADER); it == r.header.end())
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: {} response header missing",
                                pk,
                                http::MNODE_PUBKEY_HEADER);
                    else if (auto remote_pk = crypto::parse_legacy_pubkey(it->second);
                             remote_pk != pk)
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: reply has wrong pubkey {}",
                                pk,
                                remote_pk);
                    else
                        success = true;
                }
                if (success)
                    log::debug(logcat, "Successful HTTPS ping test of {}", pk);

                test->add_result(success);
            },
            std::move(url),
            ""s /*body*/,
            MN_PING_TIMEOUT,
            std::move(host),
            true /*disable https validation*/);
}

void MasterNode::beldexd_ping() {
    std::lock_guard guard(mn_mutex_);

    json beldexd_params{
        {"pubkey_ed25519", our_contact_.pubkey_ed25519.hex()},
        {"https_port", our_contact_.https_port},
        {"omq_port", our_contact_.omq_quic_port}};

    omq_server_.beldexd_request(
            "admin.storage_server_ping",
            [this](bool success, std::vector<std::string> data) {
                if (!success)
                    log::critical(
                            logcat, "Could not ping beldexd: Request failed ({})", data.front());
                else if (data.size() < 2 || data[1].empty())
                    log::critical(logcat, "Could not ping beldexd: Empty body on reply");
                else
                    try {
                        if (const auto status =
                                    json::parse(data[1]).at("status").get<std::string>();
                            status == "OK") {
                            auto good_pings = ++beldexd_pings_;
                            if (good_pings == 1)  // First ping after startup or after ping failure
                                log::info(logcat, "Successfully pinged beldexd");
                            else if (good_pings % (1h / BELDEXD_PING_INTERVAL) == 0)  // Once an hour
                                log::info(logcat, "{} successful beldexd pings", good_pings);
                            else
                                log::debug(
                                        logcat,
                                        "Successfully pinged Beldexd ({} consecutive times)",
                                        good_pings);
                        } else {
                            log::critical(logcat, "Could not ping beldexd: {}", status);
                            beldexd_pings_ = 0;
                        }
                    } catch (...) {
                        log::critical(logcat, "Could not ping beldexd: bad json in response");
                    }
            },
            beldexd_params.dump());

    // Also re-subscribe (or subscribe, in case beldexd restarted) to block and mnode address
    // subscriptions.  This makes beldexd start firing notify.block/notify.mnode_addr messages at as
    // whenever new blocks or contact-changing proofs arrive, but we have to renew the subscriptions
    // within 30min to keep them alive, so do it here (it doesn't hurt anything for it to be much
    // faster than 30min).
    omq_server_.beldexd_request("sub.block", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to beldexd block notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to beldexd new block notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed beldexd new block notification subscription");
    });

    omq_server_.beldexd_request("sub.mnode_addr", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to beldexd address notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to beldexd address change notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed beldexd address change notification subscription");
    });
}

void MasterNode::report_reachability(
        const crypto::legacy_pubkey& mn_pk, bool reachable, int previous_failures) {
    auto cb = [mn_pk, reachable](bool success, std::vector<std::string> data) {
        if (!success) {
            log::warning(
                    logcat,
                    "Could not report node status: {}",
                    data.empty() ? "unknown reason" : data[0]);
            return;
        }

        if (data.size() < 2 || data[1].empty()) {
            log::warning(logcat, "Empty body on Beldexd report node status");
            return;
        }

        try {
            const auto status = json::parse(data[1]).at("status").get<std::string>();

            if (status == "OK") {
                log::debug(
                        logcat,
                        "Successfully reported {} node: {}",
                        reachable ? "reachable" : "UNREACHABLE",
                        mn_pk);
            } else {
                log::warning(logcat, "Could not report node: {}", status);
            }
        } catch (...) {
            log::error(logcat, "Could not report node status: bad json in response");
        }
    };

    json params{{"type", "storage"}, {"pubkey", mn_pk.hex()}, {"passed", reachable}};

    omq_server_.beldexd_request("admin.report_peer_status", std::move(cb), params.dump());

    if (!reachable || previous_failures > 0) {
        std::lock_guard guard(mn_mutex_);
        if (!reachable)
            reach_records_.add_failing_node(mn_pk, previous_failures);
        else
            reach_records_.remove_node_from_failing(mn_pk);
    }
}

void MasterNode::bootstrap_swarms(const std::set<swarm_id_t>& swarms) const {
    std::lock_guard guard(mn_mutex_);

    if (swarms.empty())
        log::info(logcat, "Bootstrapping all swarms");
    else if (logcat->level() <= log::Level::info)
        log::info(logcat, "Bootstrapping swarms: [{}]", fmt::join(swarms, ", "));

    std::unordered_map<user_pubkey, swarm_id_t> pk_swarm_cache;
    std::unordered_map<swarm_id_t, std::vector<message>> to_relay;

    std::vector<message> all_msgs = db_->retrieve_all();
    log::debug(logcat, "We have {} messages", all_msgs.size());
    for (auto& entry : all_msgs) {
        if (!entry.pubkey) {
            log::error(logcat, "Invalid pubkey in a message while bootstrapping other nodes");
            continue;
        }

        auto [it, ins] = pk_swarm_cache.try_emplace(entry.pubkey);
        if (ins)
            it->second = network_.get_swarm_id_for(entry.pubkey).value_or(INVALID_SWARM_ID);
        auto swarm_id = it->second;

        if (swarms.empty() || swarms.count(swarm_id))
            to_relay[swarm_id].push_back(std::move(entry));
    }

    log::trace(logcat, "Bootstrapping {} swarms", to_relay.size());

    for (const auto& [swarm_id, items] : to_relay)
        if (auto swarm = network_.get_swarm(swarm_id))
            relay_messages(items, *swarm);
}

void MasterNode::relay_messages(
        const std::vector<message>& messages, const std::set<crypto::legacy_pubkey>& mnodes) const {
    std::vector<std::string> batches =
            serialize_messages(messages.begin(), messages.end(), SERIALIZATION_VERSION_BT);

    if (logcat->level() <= log::Level::debug) {
        log::debug(logcat, "Relaying messages:");
        for (auto msg : batches)
            log::trace(logcat, "    {}", msg);
        log::debug(logcat, "To Mnodes:");
        for (auto mn : mnodes)
            log::debug(logcat, "    {}", mn);

        log::debug(logcat, "Serialised batches: {}", batches.size());
    }

    for (const auto& mn : mnodes) {
        auto ct = network_.contacts.find(mn);
        if (ct && *ct) {
            for (auto& batch : batches) {
                log::debug(
                        logcat, "Relaying data to: {} (x25519 pubkey {})", mn, ct->pubkey_x25519);

                omq_server_->request(
                        ct->pubkey_x25519.view(),
                        "mn.data",
                        [](bool success, auto&& /*data*/) {
                            if (!success)
                                log::error(logcat, "Failed to relay batch data: timeout");
                        },
                        batch);
            }
        } else {
            log::warning(
                    logcat,
                    "Unable to relay messages to {}: node is not currently contactable",
                    mn);
        }
    }
}

void to_json(nlohmann::json& j, const test_result& val) {
    j["timestamp"] = std::chrono::duration<double>(val.timestamp.time_since_epoch()).count();
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats& stats) {
    json peers;
    for (const auto& [pk, stats] : stats.peer_report()) {
        auto& p = peers[pk.hex()];

        p["requests_failed"] = stats.requests_failed;
        p["pushes_failed"] = stats.requests_failed;
    }

    auto [window, recent] = stats.get_recent_requests();
    return json{
            {"total_store_requests", stats.get_total_store_requests()},
            {"total_retrieve_requests", stats.get_total_retrieve_requests()},
            {"total_onion_requests", stats.get_total_onion_requests()},
            {"total_proxy_requests", stats.get_total_proxy_requests()},

            {"recent_timespan", std::chrono::duration<double>(window).count()},
            {"recent_store_requests", recent.client_store_requests},
            {"recent_retrieve_requests", recent.client_retrieve_requests},
            {"recent_onion_requests", recent.onion_requests},
            {"recent_proxy_requests", recent.proxy_requests},

            {"peers", std::move(peers)}};
}

std::string MasterNode::get_stats_for_session_client() const {
    return json{{"version", STORAGE_SERVER_VERSION_STRING}}.dump();
}

std::string MasterNode::get_stats() const {
    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    std::vector<int> counts = db_->get_message_counts();
    int64_t total = std::accumulate(counts.begin(), counts.end(), int64_t{0});

    counts.erase(
            std::remove_if(counts.begin(), counts.end(), [](int c) { return c < 2; }),
            counts.end());

    // If less than 5 our iterators below could end up at the same position, so just require at
    // least 5 rather than worrying about that case:
    if (counts.size() >= 5) {
        // We're going to calculate a few numbers here from the list of stored account sizes:
        // - minimum
        // - 5th percentile
        // - 25th percentile
        // - median (i.e. 50th percentile)
        // - 75th percentile
        // - 95th percentile
        // - maximum
        // - total
        // - mean
        //
        // To get a percentile we partially sort the data via nth_element; we don't muck around with
        // averaging the middle two elements or anything like that (because that's of limited actual
        // real world use) and instead just use the upper value by rounding up.  These look a little
        // weird as `size-1+n` values but that's because we to divide the top index, not the size.
        auto pct_5th = std::next(counts.begin(), (counts.size() - 1 + 19) / 20 - 1);
        auto pct_25th = std::next(counts.begin(), (counts.size() - 1 + 3) / 4 - 1);
        auto pct_50th = std::next(counts.begin(), (counts.size() - 1) / 2 - 1);
        auto pct_75th = std::next(counts.begin(), (3 * counts.size() - 1 + 3) / 4 - 1);
        auto pct_95th = std::next(counts.begin(), (19 * counts.size() - 1 + 19) / 20);
        std::nth_element(counts.begin(), pct_5th, counts.end());
        std::nth_element(std::next(pct_5th), pct_25th, counts.end());
        std::nth_element(std::next(pct_25th), pct_50th, counts.end());
        std::nth_element(std::next(pct_50th), pct_75th, counts.end());
        std::nth_element(std::next(pct_75th), pct_95th, counts.end());

        val["account_msg_count_min"] = *std::min_element(counts.begin(), pct_5th);
        val["account_msg_count_max"] = *std::max_element(pct_95th, counts.end());
        val["account_msg_count_5th"] = *pct_5th;
        val["account_msg_count_25th"] = *pct_25th;
        val["account_msg_count_median"] = *pct_50th;
        val["account_msg_count_75th"] = *pct_75th;
        val["account_msg_count_95th"] = *pct_95th;
    }

    val["accounts"] = counts.size();
    val["total_stored"] = total;
    if (counts.size() > 0)
        val["account_msg_mean"] = total / (double)counts.size();

    auto& ns_stats = (val["namespace_messages"] = nlohmann::json::object());
    for (auto& [ns, count] : db_->get_namespace_counts())
        ns_stats[fmt::format("{}", ns)] = count;

    val["db_used"] = db_->get_used_bytes();
    val["db_total"] = db_->get_total_bytes();
    val["db_max"] = Database::SIZE_LIMIT;

    return val.dump();
}

std::string MasterNode::get_status_line() const {
    // This produces a short, single-line status string, used when running as a
    // systemd Type=notify service to update the service Status line.  The
    // status message has to be fairly short: has to fit on one line, and if
    // it's too long systemd just truncates it when displaying it.

    std::lock_guard guard(mn_mutex_);

    std::string swarm_disp;
    if (auto our_swid = swarm_.our_swarm_id(); our_swid == INVALID_SWARM_ID)
        swarm_disp = "NONE";
    else {
        std::string swarm_hex = "{:016x}"_format(swarm_.our_swarm_id());
        std::string_view sw{swarm_hex};
        swarm_disp = "{}…{}(n={})"_format(sw.substr(0, 4), sw.substr(sw.size() - 3), swarm_.size());
    }
    auto [window, stats] = all_stats_.get_recent_requests();

    // v2.3.4; sw=abcd…789(n=7); 1234 msgs (47.3 MB) for 567 users; reqs(S/R/O/P):
    // 123/456/789/1011 (last 62.3min)
    return "v{}{}{}; {} msgs ({}) for {} accts; reqs(S/R/O/P): {}/{}/{}/{} (last {})"_format(
            STORAGE_SERVER_VERSION_STRING,
            beldexss::is_mainnet ? "" : " (TESTNET)",
            syncing_ ? "; SYNCING" : "",
            db_->get_message_count(),
            util::get_human_readable_bytes(db_->get_used_bytes()),
            db_->get_owner_count(),
            stats.client_store_requests,
            stats.client_retrieve_requests,
            stats.onion_requests,
            stats.proxy_requests,
            util::short_duration(window));
}

void MasterNode::process_push_batch(std::string_view blob, std::string_view sender) {
    if (blob.empty())
        return;

    std::vector<message> items;
    try {
        items = deserialize_messages(blob);
    } catch (const std::exception& e) {
        log::warning(
                logcat,
                "Failed to deserialize incoming message batch from {}: {}",
                sender,
                e.what());
    }

    log::trace(logcat, "Saving all: begin");

    log::debug(logcat, "Got {} messages from peers, size: {}", items.size(), blob.size());

    save_bulk(items);

    log::trace(logcat, "Saving all: end");
}

}  // namespace beldexss::mnode
