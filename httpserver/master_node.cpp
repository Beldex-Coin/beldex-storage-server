#include "master_node.h"

#include "Database.hpp"
#include "http.h"
#include "omq_server.h"
#include "beldex_logger.h"
#include "request_handler.h"
#include "serialization.h"
#include "signature.h"
#include "string_utils.hpp"
#include "utils.hpp"
#include "version.h"

#include <boost/endian/conversion.hpp>
#include <chrono>
#include <cpr/cpr.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <oxenmq/oxenmq.h>

#include <algorithm>

using json = nlohmann::json;

namespace beldex {

// Threshold of missing data records at which we start warning and consult bootstrap nodes (mainly
// so that we don't bother producing warning spam or going to the bootstrap just for a few new nodes
// that will often have missing info for a few minutes).
using MISSING_PUBKEY_THRESHOLD = std::ratio<3, 100>;

/// TODO: there should be config.h to store constants like these
constexpr std::chrono::seconds BELDEXD_PING_INTERVAL = 30s;
constexpr int CLIENT_RETRIEVE_MESSAGE_LIMIT = 100;

MasterNode::MasterNode(
        mn_record address,
        const legacy_seckey& skey,
        OxenmqServer& omq_server,
        const std::filesystem::path& db_location,
        const bool force_start) :
      force_start_{force_start},
      db_{std::make_unique<Database>(db_location)},
      our_address_{std::move(address)},
      our_seckey_{skey},
      omq_server_{omq_server},
      all_stats_{*omq_server} {

    swarm_ = std::make_unique<Swarm>(our_address_);

    BELDEX_LOG(info, "Requesting initial swarm state");

#ifdef INTEGRATION_TEST
    syncing_ = false;
#endif

    omq_server->add_timer([this] { std::lock_guard l{mn_mutex_}; db_->clean_expired(); },
            Database::CLEANUP_PERIOD);

    // Periodically clean up any https request futures
    omq_server_->add_timer([this] {
        outstanding_https_reqs_.remove_if(
                [](auto& f) { return f.wait_for(0ms) == std::future_status::ready; });
    }, 1s);

    // We really want to make sure nodes don't get stuck in "syncing" mode,
    // so if we are still "syncing" after a long time, activate MN regardless
    auto delay_timer = std::make_shared<oxenmq::TimerID>();
    auto& dtimer = *delay_timer; // Get reference before we move away the shared_ptr
    omq_server_->add_timer(dtimer, [this, timer=std::move(delay_timer)] {
        omq_server_->cancel_timer(*timer);
        std::lock_guard lock{mn_mutex_};
        if (!syncing_)
            return;
        BELDEX_LOG(warn, "Block syncing is taking too long, activating SS regardless");
        syncing_ = false;
    }, 1h);
}

void MasterNode::on_beldexd_connected() {
    auto started = std::chrono::steady_clock::now();
    update_swarms();
    beldexd_ping();
    omq_server_->add_timer([this] { beldexd_ping(); }, BELDEXD_PING_INTERVAL);
    omq_server_->add_timer([this] { ping_peers(); },
            reachability_testing::TESTING_TIMER_INTERVAL);

    std::unique_lock lock{first_response_mutex_};
    while (true) {
        if (first_response_cv_.wait_for(lock, 5s, [this] { return got_first_response_; })) {
            BELDEX_LOG(info, "Got initial block update from beldexd in {}", util::short_duration(
                        std::chrono::steady_clock::now() - started));
            break;
        }
        BELDEX_LOG(warn, "Still waiting for initial block update from beldexd...");
    }
}

template <typename T>
static T get_or(const json& j, std::string_view key, std::common_type_t<T> default_val) {
    if (auto it = j.find(key); it != j.end())
        return it->get<T>();
    return default_val;
}

static block_update
parse_swarm_update(const std::string& response_body) {

    if (response_body.empty()) {
        BELDEX_LOG(critical, "Bad beldexd rpc response: no response body");
        throw std::runtime_error("Failed to parse swarm update");
    }

    std::map<swarm_id_t, std::vector<mn_record>> swarm_map;
    block_update bu;

    BELDEX_LOG(trace, "swarm repsonse: <{}>", response_body);

    try {
        json result = json::parse(response_body, nullptr, true);

        bu.height = result.at("height").get<uint64_t>();
        bu.block_hash = result.at("block_hash").get<std::string>();
        bu.hardfork = result.at("hardfork").get<int>();
        bu.mnode_revision = get_or<int>(result, "mnode_revision", 0);
        bu.unchanged = get_or<bool>(result, "unchanged", false);
        if (bu.unchanged)
            return bu;

        const json master_node_states = result.at("master_node_states");

        int missing_aux_pks = 0, total = 0;

        for (const auto& mn_json : master_node_states) {
            /// We want to include (test) decommissioned nodes, but not
            /// partially funded ones.
            if (!mn_json.at("funded").get<bool>()) {
                continue;
            }

            total++;
            const auto& pk_hex = mn_json.at("master_node_pubkey").get_ref<const std::string&>();
            const auto& pk_x25519_hex =
                mn_json.at("pubkey_x25519").get_ref<const std::string&>();
            const auto& pk_ed25519_hex =
                mn_json.at("pubkey_ed25519").get_ref<const std::string&>();

            if (pk_x25519_hex.empty() || pk_ed25519_hex.empty()) {
                // These will always either both be present or neither present.  If they are missing
                // there isn't much we can do: it means the remote hasn't transmitted them yet (or
                // our local beldexd hasn't received them yet).
                missing_aux_pks++;
                BELDEX_LOG(debug, "ed25519/x25519 pubkeys are missing from master node info {}", pk_hex);
                continue;
            }

            auto mn = mn_record{
                mn_json.at("public_ip").get_ref<const std::string&>(),
                mn_json.at("storage_port").get<uint16_t>(),
                mn_json.at("storage_lmq_port").get<uint16_t>(),
                legacy_pubkey::from_hex(pk_hex),
                ed25519_pubkey::from_hex(pk_ed25519_hex),
                x25519_pubkey::from_hex(pk_x25519_hex)};

            const swarm_id_t swarm_id =
                mn_json.at("swarm_id").get<swarm_id_t>();

            /// Storing decommissioned nodes (with dummy swarm id) in
            /// a separate data structure as it seems less error prone
            if (swarm_id == INVALID_SWARM_ID) {
                bu.decommissioned_nodes.push_back(std::move(mn));
            } else {
                bu.active_x25519_pubkeys.emplace(mn.pubkey_x25519.view());

                swarm_map[swarm_id].push_back(std::move(mn));
            }
        }

        if (missing_aux_pks >
                MISSING_PUBKEY_THRESHOLD::num*total/MISSING_PUBKEY_THRESHOLD::den) {
            BELDEX_LOG(warn, "Missing ed25519/x25519 pubkeys for {}/{} master nodes; "
                    "beldexd may be out of sync with the network", missing_aux_pks, total);
        }

    } catch (const std::exception& e) {
        BELDEX_LOG(critical, "Bad beldexd rpc response: invalid json ({})", e.what());
        throw std::runtime_error("Failed to parse swarm update");
    }

    for (auto const& swarm : swarm_map) {
        bu.swarms.emplace_back(SwarmInfo{swarm.first, swarm.second});
    }

    return bu;
}

void MasterNode::bootstrap_data() {

    std::lock_guard guard(mn_mutex_);

    BELDEX_LOG(trace, "Bootstrapping peer data");

    std::string params = json{
        {"fields", {
            {"master_node_pubkey", true},
            {"swarm_id", true},
            {"storage_port", true},
            {"public_ip", true},
            {"height", true},
            {"block_hash", true},
            {"hardfork", true},
            {"mnode_revision", true},
            {"funded", true},
            {"pubkey_x25519", true},
            {"pubkey_ed25519", true},
            {"storage_lmq_port", true}
        }}
    }.dump();

    std::vector<oxenmq::address> seed_nodes;
    if (beldex::is_mainnet) {
        seed_nodes.emplace_back("curve://public.beldex.io:29091/eee01f183b2079a529f4ba8933c0f0fcb8053337e003870ef6467a97f2259d73");
        seed_nodes.emplace_back("curve://seed1.beldex.io:29091/37659353131815666979acea91cefa909e3413811a5453c434879b3d7e5b7031");
        seed_nodes.emplace_back("curve://seed2.rpcnode.stream:29091/e06f6b3396b00430ff1ecfaeaa6f68030b5bcd8c3fd2fe813a0a5baa1cb9d008");
        seed_nodes.emplace_back("curve://seed3.beldex.io:29091/bcf02e1364237e549f45accc8cab95895198c0bc0e78a86f52df74d1c2dd8204");
    } else {
        seed_nodes.emplace_back("curve://54.80.140.73:19091/6713a9a96ea47b25223de373edc0203cf8b4d625e96bf2656b042db8e398064");
    }

    auto req_counter = std::make_shared<std::atomic<int>>(0);

    for (const auto& addr : seed_nodes) {

        auto connid = omq_server_->connect_remote(addr,
                [addr](oxenmq::ConnectionID) {
                    BELDEX_LOG(debug, "Connected to bootstrap node {}", addr);
                },
                [addr](oxenmq::ConnectionID, auto reason) {
                    BELDEX_LOG(debug, "Failed to connect to bootstrap node {}: {}", addr, reason);
                },
                oxenmq::connect_option::ephemeral_routing_id{true},
                oxenmq::connect_option::timeout{BOOTSTRAP_TIMEOUT}
        );
        omq_server_->request(connid, "rpc.get_master_nodes",
            [this, connid, addr, req_counter, node_count=(int)seed_nodes.size()](bool success, auto data) {
                if (!success)
                    BELDEX_LOG(err, "Failed to contact bootstrap node {}: request timed out", addr);
                else if (data.empty())
                    BELDEX_LOG(err, "Failed to request bootstrap node data from {}: request returned no data",
                            addr);
                else if (data[0] != "200")
                    BELDEX_LOG(err, "Failed to request bootstrap node data from {}: request returned failure status {}",
                            data[0]);
                else {
                    BELDEX_LOG(info, "Parsing response from bootstrap node {}", addr);
                    try {
                        auto update = parse_swarm_update(data[1]);
                        if (!update.unchanged)
                            on_bootstrap_update(std::move(update));
                        BELDEX_LOG(info, "Bootstrapped from {}", addr);
                    } catch (const std::exception& e) {
                        BELDEX_LOG(err,
                            "Exception caught while bootstrapping from {}: {}",
                            addr, e.what());
                    }
                }

                omq_server_->disconnect(connid);

                if (++(*req_counter) == node_count) {
                    BELDEX_LOG(info, "Bootstrapping done");
                    if (target_height_ > 0)
                        update_swarms();
                    else {
                        // If target height is still 0 after having contacted
                        // (successfully or not) all seed nodes, just assume we have
                        // finished syncing. (Otherwise we will never get a chance
                        // to update syncing status.)
                        BELDEX_LOG(warn,
                            "Could not contact any bootstrap nodes to get target "
                            "height. Assuming our local height is correct.");
                        syncing_ = false;
                    }
                }
            },
            params,
            oxenmq::send_option::request_timeout{BOOTSTRAP_TIMEOUT}
        );
    }
}

void MasterNode::shutdown() {
    shutting_down_ = true;
}

bool MasterNode::mnode_ready(std::string* reason) {
    if (shutting_down()) {
        if (reason) *reason = "shutting down";
        return false;
    }

    std::lock_guard guard(mn_mutex_);

    std::vector<std::string> problems;

    if (!hf_at_least(STORAGE_SERVER_HARDFORK))
        problems.push_back(fmt::format("not yet on hardfork {}.{}",
                    STORAGE_SERVER_HARDFORK.first, STORAGE_SERVER_HARDFORK.second));
    if (!swarm_ || !swarm_->is_valid())
        problems.push_back("not in any swarm");
    if (syncing_)
        problems.push_back("not done syncing");

    if (reason)
        *reason = util::join("; ", problems);

    return problems.empty() || force_start_;
}

void MasterNode::send_onion_to_mn(
        const mn_record& mn,
        std::string_view payload,
        OnionRequestMetadata&& data,
        std::function<void(bool success, std::vector<std::string> data)> cb) const {

    // Since HF18 we bencode everything (which is a bit more compact than sending the eph_key in
    // hex, plus flexible enough to allow other metadata such as the hop number and the encryption
    // type).
    data.hop_no++;
    omq_server_->request(
        mn.pubkey_x25519.view(), "mn.onion_request", std::move(cb),
        oxenmq::send_option::request_timeout{30s},
        omq_server_.encode_onion_data(payload, data));
}

void MasterNode::relay_data_reliable(const std::string& blob,
                                      const mn_record& mn) const {

    BELDEX_LOG(debug, "Relaying data to: {} (x25519 pubkey {})",
            mn.pubkey_legacy, mn.pubkey_x25519);

    omq_server_->request(
            mn.pubkey_x25519.view(),
            "mn.data",
            [](bool success, auto&& data) {
                if (!success) BELDEX_LOG(err, "Failed to relay batch data: timeout");
            },
            blob);
}

void MasterNode::record_proxy_request() { all_stats_.bump_proxy_requests(); }

void MasterNode::record_onion_request() { all_stats_.bump_onion_requests(); }

bool MasterNode::process_store(message msg, bool* new_msg) {

    std::lock_guard guard{mn_mutex_};

    /// only accept a message if we are in a swarm
    if (!swarm_) {
        // This should never be printed now that we have "mnode_ready"
        BELDEX_LOG(err, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database (if not already present)
    auto stored = db_->store(msg);
    if (stored)
        BELDEX_LOG(trace, *stored ? "saved message: {}" : "message already exists: {}", msg.data);
    if (new_msg)
        *new_msg = stored.value_or(false);
    return true;
}

void MasterNode::save_bulk(const std::vector<message>& msgs) {

    std::lock_guard guard(mn_mutex_);

    try { db_->bulk_store(msgs); }
    catch (const std::exception& e) {
        BELDEX_LOG(err, "failed to save batch to the database: {}", e.what());
        return;
    }

    BELDEX_LOG(trace, "saved messages count: {}", msgs.size());
}

void MasterNode::on_bootstrap_update(block_update&& bu) {

    // Used in a callback to needs a mutex even if it is private
    std::lock_guard guard(mn_mutex_);

    swarm_->apply_swarm_changes(bu.swarms);
    target_height_ = std::max(target_height_, bu.height);

    if (syncing_)
        omq_server_->set_active_sns(std::move(bu.active_x25519_pubkeys));
}

template <typename OStream>
OStream& operator<<(OStream& os, const MnodeStatus& status) {
    switch (status) {
    case MnodeStatus::UNSTAKED:
        return os << "Unstaked";
    case MnodeStatus::DECOMMISSIONED:
        return os << "Decommissioned";
    case MnodeStatus::ACTIVE:
        return os << "Active";
    default:
        return os << "Unknown";
    }
}

static MnodeStatus derive_mnode_status(const block_update& bu,
                                       const mn_record& our_address) {

    // TODO: try not to do this again in `derive_swarm_events`
    const auto our_swarm_it =
        std::find_if(bu.swarms.begin(), bu.swarms.end(),
                     [&our_address](const SwarmInfo& swarm_info) {
                         const auto& mnodes = swarm_info.mnodes;
                         return std::find(mnodes.begin(), mnodes.end(),
                                          our_address) != mnodes.end();
                     });

    if (our_swarm_it != bu.swarms.end()) {
        return MnodeStatus::ACTIVE;
    }

    if (std::find(bu.decommissioned_nodes.begin(),
                  bu.decommissioned_nodes.end(),
                  our_address) != bu.decommissioned_nodes.end()) {
        return MnodeStatus::DECOMMISSIONED;
    }

    return MnodeStatus::UNSTAKED;
}

void MasterNode::on_swarm_update(block_update&& bu) {

    hf_revision net_ver{bu.hardfork, bu.mnode_revision};
    if (hardfork_ != net_ver) {
        BELDEX_LOG(info, "New hardfork: {}.{}", net_ver.first, net_ver.second);
        hardfork_ = net_ver;
    }

    if (syncing_ && target_height_ != 0) {
        syncing_ = bu.height < target_height_;
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        BELDEX_LOG(debug, "Still syncing: {}/{}", bu.height, target_height_);
        // Note that because we are still syncing, we won't update our swarm id
        return;
    }

    if (bu.block_hash != block_hash_) {

        BELDEX_LOG(debug, "new block, height: {}, hash: {}", bu.height,
                 bu.block_hash);

        if (bu.height > block_height_ + 1 && block_height_ != 0) {
            BELDEX_LOG(warn, "Skipped some block(s), old: {} new: {}",
                     block_height_, bu.height);
            /// TODO: if we skipped a block, should we try to run peer tests for
            /// them as well?
        } else if (bu.height <= block_height_) {
            // TODO: investigate how testing will be affected under reorg
            BELDEX_LOG(warn,
                     "new block height is not higher than the current height");
        }

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;

        while (block_hashes_cache_.size() >= BLOCK_HASH_CACHE_SIZE)
            block_hashes_cache_.erase(block_hashes_cache_.begin());

        block_hashes_cache_.insert_or_assign(block_hashes_cache_.end(), bu.height, std::move(bu.block_hash));
    } else {
        BELDEX_LOG(trace, "already seen this block");
        return;
    }

    omq_server_->set_active_sns(std::move(bu.active_x25519_pubkeys));

    const SwarmEvents events = swarm_->derive_swarm_events(bu.swarms);

    // TODO: check our node's state

    const auto status = derive_mnode_status(bu, our_address_);

    if (status_ != status) {
        BELDEX_LOG(info, "Node status updated: {}", status);
        status_ = status;
    }

    swarm_->set_swarm_id(events.our_swarm_id);

    if (std::string reason; !mnode_ready(&reason)) {
        BELDEX_LOG(warn, "Storage server is still not ready: {}", reason);
        swarm_->update_state(bu.swarms, bu.decommissioned_nodes, events, false);
        return;
    } else {
        if (!active_) {
            // NOTE: because we never reset `active_` after we get
            // decommissioned, this code won't run when the node comes back
            // again
            BELDEX_LOG(info, "Storage server is now active!");
            active_ = true;
        }
    }

    swarm_->update_state(bu.swarms, bu.decommissioned_nodes, events, true);

    if (!events.new_mnodes.empty()) {
        relay_messages(get_all_messages(), events.new_mnodes);
    }

    if (!events.new_swarms.empty()) {
        bootstrap_swarms(events.new_swarms);
    }

    if (events.dissolved) {
        /// Go through all our PK and push them accordingly
        bootstrap_swarms();
    }

#ifndef INTEGRATION_TEST
    initiate_peer_test();
#endif
}

void MasterNode::update_swarms() {

    if (updating_swarms_.exchange(true)) {
        BELDEX_LOG(debug, "Swarm update already in progress, not sending another update request");
        return;
    }

    std::lock_guard lock{mn_mutex_};

    BELDEX_LOG(debug, "Swarm update triggered");

    json params{
        {"fields", {
            {"master_node_pubkey", true},
            {"swarm_id", true},
            {"storage_port", true},
            {"public_ip", true},
            {"height", true},
            {"block_hash", true},
            {"hardfork", true},
            {"mnode_revision", true},
            {"funded", true},
            {"pubkey_x25519", true},
            {"pubkey_ed25519", true},
            {"storage_lmq_port", true}
        }},
        {"active_only", false}
    };
    if (got_first_response_ && !block_hash_.empty())
        params["poll_block_hash"] = block_hash_;

    omq_server_.beldexd_request("rpc.get_master_nodes",
        [this](bool success, std::vector<std::string> data) {
            updating_swarms_ = false;
            if (!success || data.size() < 2) {
                BELDEX_LOG(critical, "Failed to contact local beldexd for master node list");
                return;
            }
            try {
                std::lock_guard lock{mn_mutex_};
                block_update bu = parse_swarm_update(data[1]);
                if (!got_first_response_) {
                    BELDEX_LOG(info, "Got initial swarm information from local Beldexd");

                    {
                        std::lock_guard l{first_response_mutex_};
                        got_first_response_ = true;
                    }
                    first_response_cv_.notify_all();

                    // Request some recent block hash heights so that we can properly carry out and
                    // respond to storage testing (for which we need to know recent block hashes).
                    // Incoming tests are *usually* height - TEST_BLOCKS_BUFFER, but request a
                    // couple extra as a buffer.
                    for (uint64_t h = bu.height - TEST_BLOCKS_BUFFER - 2; h < bu.height; h++)
                        omq_server_.beldexd_request("rpc.get_block_hash",
                                [this, h](bool success, std::vector<std::string> data) {
                                    if (!(success && data.size() == 2 && data[0] == "200" && data[1].size() == 66 &&
                                                data[1].front() == '"' && data[1].back() == '"'))
                                        return;
                                    std::string_view hash{data[1].data() + 1, data[1].size() - 2};
                                    if (oxenmq::is_hex(hash)) {
                                        BELDEX_LOG(debug, "Pre-loaded hash {} for height {}", hash, h);
                                        block_hashes_cache_.insert_or_assign(h, hash);
                                    }
                                },
                                "{\"height\":[" + util::int_to_string(h) + "]}");

#ifndef INTEGRATION_TEST
                    // If this is our very first response then we *may* want to try falling back to
                    // the bootstrap node *if* our response looks sparse: this will typically happen
                    // for a fresh master node because IP/port distribution through the network can
                    // take up to an hour.  We don't really want to hit the bootstrap nodes when we
                    // don't have to, though, so only do it if our responses is missing more than 3%
                    // of proof data (IPs/ports/ed25519/x25519 pubkeys) or we got back fewer than
                    // 100 MNs (10 on testnet).
                    //
                    // (In the future it would be nice to eliminate this by putting all the required
                    // data on chain, and get rid of needing to consult bootstrap nodes: but
                    // currently we still need this to deal with the lag).

                    auto [missing, total] = count_missing_data(bu);
                    if (total >= (beldex::is_mainnet ? 100 : 10)
                            && missing <=
                                MISSING_PUBKEY_THRESHOLD::num*total/MISSING_PUBKEY_THRESHOLD::den) {
                        BELDEX_LOG(info, "Initialized from beldexd with {}/{} MN records",
                                total-missing, total);
                        syncing_ = false;
                    } else {
                        BELDEX_LOG(info, "Detected some missing MN data ({}/{}); "
                                "querying bootstrap nodes for help", missing, total);
                        bootstrap_data();
                    }
#endif
                }

                if (!bu.unchanged) {
                    BELDEX_LOG(debug, "Blockchain updated, rebuilding swarm list");
                    on_swarm_update(std::move(bu));
                }
            } catch (const std::exception& e) {
                BELDEX_LOG(err, "Exception caught on swarm update: {}",
                         e.what());
            }
        },
        params.dump()
    );
}

void MasterNode::update_last_ping(ReachType type) {
    reach_records_.incoming_ping(type);
}

void MasterNode::ping_peers() {

    std::lock_guard lock{mn_mutex_};

    // TODO: Don't do anything until we are fully funded

    if (status_ == MnodeStatus::UNSTAKED || status_ == MnodeStatus::UNKNOWN) {
        BELDEX_LOG(trace, "Skipping peer testing (unstaked)");
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // Check if we've been tested (reached) recently ourselves
    reach_records_.check_incoming_tests(now);

    if (status_ == MnodeStatus::DECOMMISSIONED) {
        BELDEX_LOG(trace, "Skipping peer testing (decommissioned)");
        return;
    }

    /// We always test nodes due to be tested plus one general, non-failing node.

    auto to_test = reach_records_.get_failing(*swarm_, now);
    if (auto rando = reach_records_.next_random(*swarm_, now))
        to_test.emplace_back(std::move(*rando), 0);

    if (to_test.empty())
        BELDEX_LOG(trace, "no nodes to test this tick");
    else
        BELDEX_LOG(debug, "{} nodes to test", to_test.size());
    for (const auto& [mn, prev_fails] : to_test)
        test_reachability(mn, prev_fails);
}

std::vector<std::pair<std::string, std::string>> MasterNode::sign_request(std::string_view body) const {
    std::vector<std::pair<std::string, std::string>> headers;
    const auto signature = generate_signature(hash_data(body), {our_address_.pubkey_legacy, our_seckey_});
    headers.emplace_back(http::MNODE_SIGNATURE_HEADER, oxenmq::to_base64(util::view_guts(signature)));
    headers.emplace_back(http::MNODE_SENDER_HEADER, oxenmq::to_base32z(our_address_.pubkey_legacy.view()));
    return headers;
}

void MasterNode::test_reachability(const mn_record& mn, int previous_failures) {

    BELDEX_LOG(debug, "Testing {} MN {} for reachability",
            previous_failures > 0 ? "previously failing" : "random",
            mn.pubkey_legacy);

    if (mn.ip == "0.0.0.0") {
        // beldexd won't accept 0.0.0.0 in an uptime proof, which means if we see this the node hasn't
        // sent an uptime proof; we could treat it as a failure, but that seems unnecessary since
        // beldexd will already fail the master node for not sending uptime proofs.
        BELDEX_LOG(debug, "Skipping HTTPS test of {}: no public IP received yet");
        return;
    }

    static constexpr uint8_t TEST_WAITING = 0, TEST_FAILED = 1, TEST_PASSED = 2;

    // We start off two separate tests below; they share this pair and use the atomic int here to
    // figure out whether they were called first (in which case they do nothing) or second (in which
    // case they have to report the final result to beldexd).
    auto test_results = std::make_shared<std::pair<const mn_record, std::atomic<uint8_t>>>(
            mn, 0);
    cpr::Url url{fmt::format("https://{}:{}/ping_test/v1", mn.ip, mn.port)};
    cpr::Body body{""};
    cpr::Header headers{
        {"Host", mn.pubkey_ed25519
            ? oxenmq::to_base32z(mn.pubkey_ed25519.view()) + ".mnode"
            : "master-node.mnode"},
        {"Content-Type", "application/octet-stream"},
        {"User-Agent", "Beldex Storage Server/" + std::string{STORAGE_SERVER_VERSION_STRING}},
    };

    BELDEX_LOG(debug, "Sending HTTPS ping to {} @ {}", mn.pubkey_legacy, url);
    outstanding_https_reqs_.emplace_front(
        cpr::PostCallback(
            [this, &omq=*omq_server(), test_results, previous_failures]
            (cpr::Response r) {
                auto& [mn, result] = *test_results;
                auto& pk = mn.pubkey_legacy;
                bool success = false;
                if (r.error.code != cpr::ErrorCode::OK) {
                    BELDEX_LOG(debug, "FAILED HTTPS ping test of {}: {}", pk, r.error.message);
                } else if (r.status_code != 200) {
                    BELDEX_LOG(debug, "FAILED HTTPS ping test of {}: received non-200 status {} {}",
                            pk, r.status_code, r.status_line);
                } else {
                    if (auto it = r.header.find(http::MNODE_PUBKEY_HEADER);
                            it == r.header.end())
                        BELDEX_LOG(debug, "FAILED HTTPS ping test of {}: {} response header missing",
                                pk, http::MNODE_PUBKEY_HEADER);
                    else if (auto remote_pk = parse_legacy_pubkey(it->second); remote_pk != pk)
                        BELDEX_LOG(debug, "FAILED HTTPS ping test of {}: reply has wrong pubkey {}",
                                pk, remote_pk);
                    else
                        success = true;
                }
                if (success)
                    BELDEX_LOG(debug, "Successful HTTPS ping test of {}", pk);

                if (auto r = result.exchange(success ? TEST_PASSED : TEST_FAILED); r != TEST_WAITING)
                    report_reachability(mn, success && r == TEST_PASSED, previous_failures);
            },
            std::move(url),
            cpr::Timeout{MN_PING_TIMEOUT},
            cpr::Ssl(
                    cpr::ssl::TLSv1_2{},
                    cpr::ssl::VerifyHost{false},
                    cpr::ssl::VerifyPeer{false},
                    cpr::ssl::VerifyStatus{false}),
            cpr::MaxRedirects{0},
            std::move(headers),
            std::move(body)
        )
    );

    // test omq port:
    omq_server_->request(
        mn.pubkey_x25519.view(), "mn.ping",
        [this, test_results=std::move(test_results), previous_failures](bool success, const auto&) {
            auto& [mn, result] = *test_results;

            BELDEX_LOG(debug, "{} response for OxenMQ ping test of {}",
                    success ? "Successful" : "FAILED", mn.pubkey_legacy);

            if (auto r = result.exchange(success ? TEST_PASSED : TEST_FAILED); r != TEST_WAITING)
                report_reachability(mn, success && r == TEST_PASSED, previous_failures);
        },
        // Only use an existing (or new) outgoing connection:
        oxenmq::send_option::outgoing{},
        oxenmq::send_option::request_timeout{MN_PING_TIMEOUT}
    );
}

void MasterNode::beldexd_ping() {

    std::lock_guard guard(mn_mutex_);

    json beldexd_params{
        {"version", STORAGE_SERVER_VERSION},
        {"https_port", our_address_.port},
        {"omq_port", our_address_.omq_port}};

    omq_server_.beldexd_request("admin.storage_server_ping",
        [this](bool success, std::vector<std::string> data) {
            if (!success)
                BELDEX_LOG(critical, "Could not ping beldexd: Request failed ({})", data.front());
            else if (data.size() < 2 || data[1].empty())
                BELDEX_LOG(critical, "Could not ping beldexd: Empty body on reply");
            else
                try {
                    if (const auto status = json::parse(data[1]).at("status").get<std::string>();
                            status == "OK") {
                        auto good_pings = ++beldexd_pings_;
                        if (good_pings == 1) // First ping after startup or after ping failure
                            BELDEX_LOG(info, "Successfully pinged beldexd");
                        else if (good_pings % (1h / BELDEXD_PING_INTERVAL) == 0) // Once an hour
                            BELDEX_LOG(info, "{} successful beldexd pings", good_pings);
                        else
                            BELDEX_LOG(debug, "Successfully pinged Beldexd ({} consecutive times)", good_pings);
                    } else {
                        BELDEX_LOG(critical, "Could not ping beldexd: {}", status);
                        beldexd_pings_ = 0;
                    }
                } catch (...) {
                    BELDEX_LOG(critical, "Could not ping beldexd: bad json in response");
                }
        },
        beldexd_params.dump()
    );

    // Also re-subscribe (or subscribe, in case beldexd restarted) to block subscriptions.  This makes
    // beldexd start firing notify.block messages at as whenever new blocks arrive, but we have to
    // renew the subscription within 30min to keep it alive, so do it here (it doesn't hurt anything
    // for it to be much faster than 30min).
    omq_server_.beldexd_request("sub.block", [](bool success, auto&& result) {
        if (!success || result.empty())
            BELDEX_LOG(critical, "Failed to subscribe to beldexd block notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            BELDEX_LOG(info, "Subscribed to beldexd new block notifications");
        else if (result.front() == "ALREADY")
            BELDEX_LOG(debug, "Renewed beldexd new block notification subscription");
    });
}

void MasterNode::process_storage_test_response(const mn_record& testee,
                                                const message& msg,
                                                uint64_t test_height,
                                                std::string status,
                                                std::string answer) {
    ResultType result = ResultType::OTHER;

    if (status.empty()) {
        // TODO: retry here, otherwise tests sometimes fail (when MN not
        // running yet)
        BELDEX_LOG(debug, "Failed to send a storage test request to mnode: {}",
                 testee.pubkey_legacy);
    } else if (status == "OK") {
        if (answer == msg.data) {
            BELDEX_LOG(debug,
                     "Storage test is successful for: {} at height: {}",
                     testee.pubkey_legacy, test_height);
            result = ResultType::OK;
        } else {
            BELDEX_LOG(debug,
                     "Test answer doesn't match for: {} at height {}",
                     testee.pubkey_legacy, test_height);
#ifdef INTEGRATION_TEST
            BELDEX_LOG(warn, "got: {} expected: {}", value, msg.data);
#endif
            result = ResultType::MISMATCH;
        }
    } else if (status == "wrong request") {
        BELDEX_LOG(debug, "Storage test rejected by testee");
        result = ResultType::REJECTED;
    } else {
        BELDEX_LOG(debug, "Storage test failed for some other reason: {}", status);
    }

    all_stats_.record_storage_test_result(testee.pubkey_legacy, result);
}

void MasterNode::send_storage_test_req(const mn_record& testee,
                                        uint64_t test_height,
                                        const message& msg) {

    bool is_b64 = oxenmq::is_base64(msg.hash);
    if (!is_b64) {
            BELDEX_LOG(err, "Unable to initiate storage test: retrieved msg hash is not expected BLAKE2b+base64");
            return;
    }

    omq_server_->request(
        testee.pubkey_x25519.view(), "mn.storage_test",
        [this, testee, msg, height=block_height_](bool success, auto data) {
            if (!success || data.size() != 2) {
                BELDEX_LOG(debug, "Storage test request failed: {}",
                        !success ? "request timed out" : "wrong number of elements in response");
            }
            if (data.size() < 2)
                data.resize(2);
            process_storage_test_response(testee, msg, height, std::move(data[0]), std::move(data[1]));
        },
        oxenmq::send_option::request_timeout{STORAGE_TEST_TIMEOUT},
        // Data parts: test height and msg hash (in bytes)
        std::to_string(block_height_),
        oxenmq::from_base64(msg.hash)
    );
}

void MasterNode::report_reachability(const mn_record& mn, bool reachable, int previous_failures) {
    auto cb = [mn_pk=mn.pubkey_legacy, reachable](bool success, std::vector<std::string> data) {
        if (!success) {
            BELDEX_LOG(warn, "Could not report node status: {}",
                    data.empty() ? "unknown reason" : data[0]);
            return;
        }

        if (data.size() < 2 || data[1].empty()) {
            BELDEX_LOG(warn, "Empty body on Beldexd report node status");
            return;
        }

        try {
            const auto status = json::parse(data[1]).at("status").get<std::string>();

            if (status == "OK") {
                BELDEX_LOG(debug, "Successfully reported {} node: {}",
                        reachable ? "reachable" : "UNREACHABLE", mn_pk);
            } else {
                BELDEX_LOG(warn, "Could not report node: {}", status);
            }
        } catch (...) {
            BELDEX_LOG(err,
                     "Could not report node status: bad json in response");
        }
    };

    json params{
        {"type", "storage"},
        {"pubkey", mn.pubkey_legacy.hex()},
        {"passed", reachable}
    };

    omq_server_.beldexd_request("admin.report_peer_status",
            std::move(cb), params.dump());

    if (!reachable || previous_failures > 0) {
        std::lock_guard guard(mn_mutex_);
        if (!reachable)
            reach_records_.add_failing_node(mn.pubkey_legacy, previous_failures);
        else
            reach_records_.remove_node_from_failing(mn.pubkey_legacy);
    }
}

// Deterministically selects two random swarm members; returns the pair on success, nullopt on
// failure.
std::optional<std::pair<mn_record, mn_record>> MasterNode::derive_tester_testee(uint64_t blk_height) {

    std::lock_guard guard(mn_mutex_);

    std::vector<mn_record> members = swarm_->other_nodes();
    members.push_back(our_address_);

    if (members.size() < 2) {
        BELDEX_LOG(trace, "Could not initiate peer test: swarm too small");
        return std::nullopt;
    }

    std::sort(members.begin(), members.end(),
            [](const auto& a, const auto& b) { return a.pubkey_legacy < b.pubkey_legacy; });

    std::string block_hash;
    if (blk_height == block_height_) {
        block_hash = block_hash_;
    } else if (blk_height < block_height_) {

        BELDEX_LOG(trace, "got storage test request for an older block: {}/{}",
                 blk_height, block_height_);

        if (auto it = block_hashes_cache_.find(blk_height); it != block_hashes_cache_.end()) {
            block_hash = it->second;
        } else {
            BELDEX_LOG(debug, "Could not find hash for a given block height");
            return std::nullopt;
        }
    } else {
        BELDEX_LOG(debug, "Could not find hash: block height is in the future");
        return std::nullopt;
    }

    uint64_t seed;
    if (block_hash.size() < sizeof(seed)) {
        BELDEX_LOG(err, "Could not initiate peer test: invalid block hash");
        return std::nullopt;
    }

    std::memcpy(&seed, block_hash.data(), sizeof(seed));
    boost::endian::little_to_native_inplace(seed);
    std::mt19937_64 mt(seed);
    const auto tester_idx =
        util::uniform_distribution_portable(mt, members.size());

    uint64_t testee_idx;
    do {
        testee_idx = util::uniform_distribution_portable(mt, members.size());
    } while (testee_idx == tester_idx);

    return std::make_pair(std::move(members[tester_idx]), std::move(members[testee_idx]));
}

std::pair<MessageTestStatus, std::string> MasterNode::process_storage_test_req(
    uint64_t blk_height,
    const legacy_pubkey& tester_pk,
    const std::string& msg_hash_hex) {

    std::lock_guard guard(mn_mutex_);

    // 1. Check height, retry if we are behind
    std::string block_hash;

    if (blk_height > block_height_) {
        BELDEX_LOG(debug, "Our blockchain is behind, height: {}, requested: {}",
                 block_height_, blk_height);
        return {MessageTestStatus::RETRY, ""};
    }

    // 2. Check tester/testee pair
    {
        auto tester_testee = derive_tester_testee(blk_height);
        if (!tester_testee) {
            BELDEX_LOG(err, "We have no mnodes to derive tester/testee from");
            return {MessageTestStatus::WRONG_REQ, ""};
        }
        auto [tester, testee] = *std::move(tester_testee);

        if (testee != our_address_) {
            BELDEX_LOG(err, "We are NOT the testee for height: {}", blk_height);
            return {MessageTestStatus::WRONG_REQ, ""};
        }

        if (tester.pubkey_legacy != tester_pk) {
            BELDEX_LOG(debug, "Wrong tester: {}, expected: {}", tester_pk,
                     tester.pubkey_legacy);
#ifdef INTEGRATION_TEST
            BELDEX_LOG(critical, "ABORT in integration test");
            std::abort();
#endif
            return {MessageTestStatus::WRONG_REQ, ""};
        } else {
            BELDEX_LOG(trace, "Tester is valid: {}", tester_pk);
        }
    }

    // 3. If for a current/past block, try to respond right away
    auto msg = db_->retrieve_by_hash(msg_hash_hex);
    if (!msg)
        return {MessageTestStatus::RETRY, ""};

    return {MessageTestStatus::SUCCESS, std::move(msg->data)};
}

void MasterNode::initiate_peer_test() {

    std::lock_guard guard(mn_mutex_);

    // 1. Select the tester/testee pair

    if (block_height_ < TEST_BLOCKS_BUFFER) {
        BELDEX_LOG(debug, "Height {} is too small, skipping all tests",
                 block_height_);
        return;
    }

    const uint64_t test_height = block_height_ - TEST_BLOCKS_BUFFER;

    auto tester_testee = derive_tester_testee(test_height);
    if (!tester_testee)
        return;
    auto [tester, testee] = *std::move(tester_testee);

    BELDEX_LOG(trace, "For height {}; tester: {} testee: {}", test_height,
            tester.pubkey_legacy, testee.pubkey_legacy);

    if (tester != our_address_) {
        /// Not our turn to initiate a test
        return;
    }

    /// 2. Storage Testing: initiate a testing request with a randomly selected message
    if (auto msg = db_->retrieve_random()) {
        BELDEX_LOG(trace, "Selected random message: {}, {}", msg->hash, msg->data);
        send_storage_test_req(testee, test_height, *msg);
    } else {
        BELDEX_LOG(debug, "Could not select a message for testing");
    }
}

void MasterNode::bootstrap_swarms(
    const std::vector<swarm_id_t>& swarms) const {

    std::lock_guard guard(mn_mutex_);

    if (swarms.empty())
        BELDEX_LOG(info, "Bootstrapping all swarms");
    else if (BELDEX_LOG_ENABLED(info))
        BELDEX_LOG(info, "Bootstrapping swarms: [{}]", util::join(", ", swarms));

    const auto& all_swarms = swarm_->all_valid_swarms();

    std::unordered_map<user_pubkey_t, swarm_id_t> pk_swarm_cache;
    std::unordered_map<swarm_id_t, std::vector<message>> to_relay;

    std::vector<message> all_entries = get_all_messages();
    BELDEX_LOG(debug, "We have {} messages", all_entries.size());
    for (auto& entry : all_entries) {
        if (!entry.pubkey) {
            BELDEX_LOG(err, "Invalid pubkey in a message while bootstrapping other nodes");
            continue;
        }

        auto [it, ins] = pk_swarm_cache.try_emplace(entry.pubkey);
        if (ins)
            it->second = get_swarm_by_pk(all_swarms, entry.pubkey).swarm_id;
        auto swarm_id = it->second;

        if (swarms.empty() || std::find(swarms.begin(), swarms.end(), swarm_id) != swarms.end())
            to_relay[swarm_id].push_back(std::move(entry));
    }

    BELDEX_LOG(trace, "Bootstrapping {} swarms", to_relay.size());

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (size_t i = 0; i < all_swarms.size(); ++i)
        swarm_id_to_idx.emplace(all_swarms[i].swarm_id, i);

    for (const auto& [swarm_id, items] : to_relay)
        relay_messages(items, all_swarms[swarm_id_to_idx[swarm_id]].mnodes);
}

void MasterNode::relay_messages(const std::vector<message>& messages,
                                 const std::vector<mn_record>& mnodes) const {
    std::vector<std::string> batches = serialize_messages(
            messages.begin(), messages.end(), SERIALIZATION_VERSION_BT);

    if (BELDEX_LOG_ENABLED(debug)) {
        BELDEX_LOG(debug, "Relayed messages:");
        for (auto msg : batches)
            BELDEX_LOG(debug, "    {}", msg);
        BELDEX_LOG(debug, "To Mnodes:");
        for (auto mn : mnodes)
            BELDEX_LOG(debug, "    {}", mn.pubkey_legacy);

        BELDEX_LOG(debug, "Serialised batches: {}", batches.size());
    }

    for (const mn_record& mn : mnodes)
        for (auto& batch : batches)
            relay_data_reliable(batch, mn);
}

std::vector<message> MasterNode::retrieve(
        const user_pubkey_t& pubkey, const std::string& last_hash) {
    all_stats_.bump_retrieve_requests();
    return db_->retrieve(pubkey, last_hash, CLIENT_RETRIEVE_MESSAGE_LIMIT);
}

std::optional<std::vector<std::string>> MasterNode::delete_all_messages(
        const user_pubkey_t& pubkey) {
    return db_->delete_all(pubkey);
}

std::optional<std::vector<std::string>> MasterNode::delete_messages(
        const user_pubkey_t& pubkey,
        const std::vector<std::string>& msg_hashes) {
    return db_->delete_by_hash(pubkey, msg_hashes);
}

std::optional<std::vector<std::string>> MasterNode::delete_messages_before(
        const user_pubkey_t& pubkey, std::chrono::system_clock::time_point timestamp) {
    return db_->delete_by_timestamp(pubkey, timestamp);
}

std::optional<std::vector<std::string>>
MasterNode::update_messages_expiry(
        const user_pubkey_t& pubkey,
        const std::vector<std::string>& msg_hashes,
        std::chrono::system_clock::time_point new_exp) {
    return db_->update_expiry(pubkey, msg_hashes, new_exp);
}

std::optional<std::vector<std::string>>
MasterNode::update_all_expiries(
        const user_pubkey_t& pubkey,
        std::chrono::system_clock::time_point new_exp) {
    return db_->update_all_expiries(pubkey, new_exp);
}

void to_json(nlohmann::json& j, const test_result& val) {
    j["timestamp"] = std::chrono::duration<double>(val.timestamp.time_since_epoch()).count();
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats_t& stats) {

    json peers;
    for (const auto& [pk, stats] : stats.peer_report()) {
        auto& p = peers[pk.hex()];

        p["requests_failed"] = stats.requests_failed;
        p["pushes_failed"] = stats.requests_failed;
        p["storage_tests"] = stats.storage_tests;
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

        {"peers", std::move(peers)}
    };
}

std::string MasterNode::get_stats_for_session_client() const {
    return json{{"version", STORAGE_SERVER_VERSION_STRING}}.dump();
}

std::string MasterNode::get_stats() const {

    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    val["total_stored"] = db_->get_message_count();
    val["db_used"] = db_->get_used_bytes();
    val["db_max"] = Database::SIZE_LIMIT;

    return val.dump();
}

std::string MasterNode::get_status_line() const {
    // This produces a short, single-line status string, used when running as a
    // systemd Type=notify service to update the service Status line.  The
    // status message has to be fairly short: has to fit on one line, and if
    // it's too long systemd just truncates it when displaying it.

    std::lock_guard guard(mn_mutex_);

    // v2.3.4; sw=abcd…789(n=7); 1234 msgs (47.3MB) for 567 users; reqs(S/R/O/P): 123/456/789/1011 (last 62.3min)
    std::ostringstream s;
    s << 'v' << STORAGE_SERVER_VERSION_STRING;
    if (!beldex::is_mainnet)
        s << " (TESTNET)";

    if (syncing_)
        s << "; SYNCING";
    s << "; sw=";
    if (!swarm_ || !swarm_->is_valid())
        s << "NONE";
    else {
        std::string swarm = fmt::format("{:016x}", swarm_->our_swarm_id());
        s << swarm.substr(0, 4) << u8"…" << swarm.substr(swarm.size()-3);
        s << "(n=" << (1 + swarm_->other_nodes().size()) << ")";
    }
    s << "; " << db_->get_message_count() << " msgs";

    if (auto bytes_stored = db_->get_used_bytes(); bytes_stored > 0) {
        s << " (";
        auto oldprec = s.precision(3);
        if (bytes_stored >= 999'500'000)
            s << bytes_stored * 1e-9 << 'G';
        else if (bytes_stored >= 999'500)
            s << bytes_stored * 1e-6 << 'M';
        else if (bytes_stored >= 1000)
            s << bytes_stored * 1e-3 << 'k';
        else
            s << bytes_stored;
        s.precision(oldprec);
        s << "B)";
    }

    s << " for " << db_->get_owner_count() << " users";

    auto [window, stats] = all_stats_.get_recent_requests();
    s << "; reqs(S/R/O/P): " << stats.client_store_requests << '/'
        << stats.client_retrieve_requests << '/'
        << stats.onion_requests << '/'
        << stats.proxy_requests
        << " (last " << util::short_duration(window) << ")";
    return s.str();
}

std::vector<message> MasterNode::get_all_messages() const {
    BELDEX_LOG(trace, "Get all messages");
    return db_->retrieve_all();
}

void MasterNode::process_push_batch(const std::string& blob) {

    std::lock_guard guard(mn_mutex_);

    if (blob.empty())
        return;

    std::vector<message> items = deserialize_messages(blob);

    BELDEX_LOG(trace, "Saving all: begin");

    BELDEX_LOG(debug, "Got {} messages from peers, size: {}", items.size(),
             blob.size());

    save_bulk(items);

    BELDEX_LOG(trace, "Saving all: end");
}

bool MasterNode::is_pubkey_for_us(const user_pubkey_t& pk) const {

    std::lock_guard guard(mn_mutex_);

    if (!swarm_) {
        BELDEX_LOG(err, "Swarm data missing");
        return false;
    }
    return swarm_->is_pubkey_for_us(pk);
}

SwarmInfo MasterNode::get_swarm(const user_pubkey_t& pk) {

    std::lock_guard guard(mn_mutex_);

    if (!swarm_) {
        BELDEX_LOG(err, "Swarm data missing");
        return {};
    }

    return get_swarm_by_pk(swarm_->all_valid_swarms(), pk);
}

std::vector<mn_record>
MasterNode::get_swarm_peers() {
    std::lock_guard guard{mn_mutex_};

    return swarm_->other_nodes();
}

} // namespace beldex
