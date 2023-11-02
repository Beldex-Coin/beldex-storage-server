#include "swarm.h"
#include "beldex_logger.h"

#include "master_node.h"

#include <boost/endian/conversion.hpp>
#include <cstdlib>
#include <ostream>
#include <unordered_map>

#include "string_utils.hpp"
#include "utils.hpp"

namespace beldex {
static bool swarm_exists(const std::vector<SwarmInfo>& all_swarms, const swarm_id_t& swarm) {
    const auto it =
            std::find_if(all_swarms.begin(), all_swarms.end(), [&swarm](const SwarmInfo& si) {
                return si.swarm_id == swarm;
            });

    return it != all_swarms.end();
}

void debug_print(std::ostream& os, const block_update& bu) {
    os << "Block update: {\n";
    os << "     height: " << bu.height << '\n';
    os << "     block hash: " << bu.block_hash << '\n';
    os << "     hardfork: " << bu.hardfork << '.' << bu.mnode_revision << '\n';
    os << "     swarms: [\n";

    for (const SwarmInfo& swarm : bu.swarms) {
        os << "         {\n";
        os << "             id: " << swarm.swarm_id << '\n';
        os << "         }\n";
    }

    os << "     ]\n";
    os << "}\n";
}

Swarm::~Swarm() = default;

bool Swarm::is_existing_swarm(swarm_id_t sid) const {
    return std::any_of(
            all_valid_swarms_.begin(),
            all_valid_swarms_.end(),
            [sid](const SwarmInfo& cur_swarm_info) { return cur_swarm_info.swarm_id == sid; });
}

SwarmEvents Swarm::derive_swarm_events(const std::vector<SwarmInfo>& swarms) const {
    SwarmEvents events = {};

    const auto our_swarm_it =
            std::find_if(swarms.begin(), swarms.end(), [this](const SwarmInfo& swarm_info) {
                const auto& mnodes = swarm_info.mnodes;
                return std::find(mnodes.begin(), mnodes.end(), our_address_) != mnodes.end();
            });

    if (our_swarm_it == swarms.end()) {
        // We are not in any swarm, nothing to do
        events.our_swarm_id = INVALID_SWARM_ID;
        return events;
    }

    const auto& new_swarm_mnodes = our_swarm_it->mnodes;
    const auto new_swarm_id = our_swarm_it->swarm_id;

    events.our_swarm_id = new_swarm_id;
    events.our_swarm_members = new_swarm_mnodes;

    if (cur_swarm_id_ == INVALID_SWARM_ID) {
        // Only started in a swarm, nothing to do at this stage
        return events;
    }

    if (cur_swarm_id_ != new_swarm_id) {
        // Got moved to a new swarm
        if (!swarm_exists(swarms, cur_swarm_id_)) {
            // Dissolved, new to push all our data to new swarms
            events.dissolved = true;
        }

        // If our old swarm is still alive, there is nothing for us to do
        return events;
    }

    /// --- WE are still in the same swarm if we reach here ---

    /// See if anyone joined our swarm
    for (const auto& mn : new_swarm_mnodes) {
        const auto it = std::find(swarm_peers_.begin(), swarm_peers_.end(), mn);

        if (it == swarm_peers_.end() && mn != our_address_) {
            events.new_mnodes.push_back(mn);
        }
    }

    /// See if there are any new swarms

    for (const auto& swarm_info : swarms)
        if (!is_existing_swarm(swarm_info.swarm_id))
            events.new_swarms.push_back(swarm_info.swarm_id);

    /// NOTE: need to be careful and make sure we don't miss any
    /// swarm update (e.g. if we don't update frequently enough)

    return events;
}

void Swarm::set_swarm_id(swarm_id_t sid) {
    if (sid == INVALID_SWARM_ID) {
        BELDEX_LOG(warn, "We are not currently an active Master Node");
    } else {
        if (cur_swarm_id_ == INVALID_SWARM_ID) {
            BELDEX_LOG(info, "EVENT: started MN in swarm: 0x{}", util::int_to_string(sid, 16));
        } else if (cur_swarm_id_ != sid) {
            BELDEX_LOG(info, "EVENT: got moved into a new swarm: 0x{}", util::int_to_string(sid, 16));
        }
    }

    cur_swarm_id_ = sid;
}

static auto get_mnode_map_from_swarms(const std::vector<SwarmInfo>& swarms) {
    std::unordered_map<legacy_pubkey, mn_record> mnode_map;
    for (const auto& swarm : swarms) {
        for (const auto& mnode : swarm.mnodes) {
            mnode_map.emplace(mnode.pubkey_legacy, mnode);
        }
    }
    return mnode_map;
}

template <typename T>
bool update_if_changed(T& val, const T& new_val, const std::common_type_t<T>& ignore_val) {
    if (new_val != ignore_val && new_val != val) {
        val = new_val;
        return true;
    }
    return false;
}

std::vector<SwarmInfo> apply_ips(
        const std::vector<SwarmInfo>& swarms_to_keep, const std::vector<SwarmInfo>& other_swarms) {
    std::vector<SwarmInfo> result_swarms = swarms_to_keep;
    const auto other_mnode_map = get_mnode_map_from_swarms(other_swarms);

    int updates_count = 0;
    for (auto& [swarm_id, mnodes] : result_swarms) {
        for (auto& mnode : mnodes) {
            const auto other_mnode_it = other_mnode_map.find(mnode.pubkey_legacy);
            if (other_mnode_it != other_mnode_map.end()) {
                auto& mn = other_mnode_it->second;
                // Keep swarms_to_keep but don't overwrite with default IPs/ports
                bool updated = false;
                if (update_if_changed(mnode.ip, mn.ip, "0.0.0.0"))
                    updated = true;
                if (update_if_changed(mnode.port, mn.port, 0))
                    updated = true;
                if (update_if_changed(mnode.omq_port, mn.omq_port, 0))
                    updated = true;
                if (updated)
                    updates_count++;
            }
        }
    }

    BELDEX_LOG(debug, "Updated {} entries from beldexd", updates_count);
    return result_swarms;
}

void Swarm::apply_swarm_changes(const std::vector<SwarmInfo>& new_swarms) {
    BELDEX_LOG(trace, "Applying swarm changes");

    all_valid_swarms_ = apply_ips(new_swarms, all_valid_swarms_);
}

void Swarm::update_state(
        const std::vector<SwarmInfo>& swarms,
        const std::vector<mn_record>& decommissioned,
        const SwarmEvents& events,
        bool active) {
    if (active) {
        // The following only makes sense for active nodes in a swarm

        if (events.dissolved) {
            BELDEX_LOG(info, "EVENT: our old swarm got DISSOLVED!");
        }

        for (const mn_record& mn : events.new_mnodes) {
            BELDEX_LOG(info, "EVENT: detected new MN: {}", mn.pubkey_legacy);
        }

        for (swarm_id_t swarm : events.new_swarms) {
            BELDEX_LOG(info, "EVENT: detected a new swarm: {}", swarm);
        }

        apply_swarm_changes(swarms);

        const auto& members = events.our_swarm_members;

        /// sanity check
        if (members.empty())
            return;

        swarm_peers_.clear();
        swarm_peers_.reserve(members.size() - 1);

        std::copy_if(
                members.begin(),
                members.end(),
                std::back_inserter(swarm_peers_),
                [this](const mn_record& record) { return record != our_address_; });
    }

    // Store a copy of every node in a separate data structure
    all_funded_nodes_.clear();
    all_funded_ed25519_.clear();
    all_funded_x25519_.clear();

    for (const auto& si : swarms) {
        for (const auto& mn : si.mnodes) {
            all_funded_nodes_.emplace(mn.pubkey_legacy, mn);
        }
    }

    for (const auto& mn : decommissioned) {
        all_funded_nodes_.emplace(mn.pubkey_legacy, mn);
    }

    for (const auto& [pk, mn] : all_funded_nodes_) {
        all_funded_ed25519_.emplace(mn.pubkey_ed25519, pk);
        all_funded_x25519_.emplace(mn.pubkey_x25519, pk);
    }
}

std::optional<mn_record> Swarm::find_node(const legacy_pubkey& pk) const {
    if (auto it = all_funded_nodes_.find(pk); it != all_funded_nodes_.end())
        return it->second;
    return std::nullopt;
}

std::optional<mn_record> Swarm::find_node(const ed25519_pubkey& pk) const {
    if (auto it = all_funded_ed25519_.find(pk); it != all_funded_ed25519_.end())
        return find_node(it->second);
    return std::nullopt;
}

std::optional<mn_record> Swarm::find_node(const x25519_pubkey& pk) const {
    if (auto it = all_funded_x25519_.find(pk); it != all_funded_x25519_.end())
        return find_node(it->second);
    return std::nullopt;
}

uint64_t pubkey_to_swarm_space(const user_pubkey_t& pk) {
    const auto bytes = pk.raw();
    assert(bytes.size() == 32);

    uint64_t res = 0;
    for (size_t i = 0; i < 4; i++) {
        uint64_t buf;
        std::memcpy(&buf, bytes.data() + i * 8, 8);
        res ^= buf;
    }
    boost::endian::big_to_native_inplace(res);

    return res;
}

bool Swarm::is_pubkey_for_us(const user_pubkey_t& pk) const {
    /// TODO: Make sure no exceptions bubble up from here!
    return cur_swarm_id_ == get_swarm_by_pk(all_valid_swarms_, pk).swarm_id;
}

static const SwarmInfo null_swarm{INVALID_SWARM_ID, {}};

const SwarmInfo& get_swarm_by_pk(
        const std::vector<SwarmInfo>& all_swarms, const user_pubkey_t& pk) {
    const uint64_t res = pubkey_to_swarm_space(pk);

    /// We reserve UINT64_MAX as a sentinel swarm id for unassigned mnodes
    constexpr swarm_id_t MAX_ID = INVALID_SWARM_ID - 1;

    const SwarmInfo* cur_best = &null_swarm;
    uint64_t cur_min = INVALID_SWARM_ID;

    /// We don't require that all_swarms is sorted, so we find
    /// the smallest/largest elements in the same loop
    const SwarmInfo* leftmost = &null_swarm;
    const SwarmInfo* rightmost = nullptr;

    for (const auto& si : all_swarms) {
        if (si.swarm_id == INVALID_SWARM_ID) {
            /// Just to be sure we check again that no decomissioned
            /// node is exposed to clients
            continue;
        }

        uint64_t dist = (si.swarm_id > res) ? (si.swarm_id - res) : (res - si.swarm_id);
        if (dist < cur_min) {
            cur_best = &si;
            cur_min = dist;
        }

        /// Find the letfmost
        if (si.swarm_id < leftmost->swarm_id) {
            leftmost = &si;
        }

        if (!rightmost || si.swarm_id > rightmost->swarm_id) {
            rightmost = &si;
        }
    }

    if (!rightmost)  // Found no swarms at all
        return null_swarm;

    // handle special case
    if (res > rightmost->swarm_id) {
        // since rightmost is at least as large as leftmost,
        // res >= leftmost_id in this branch, so the value will
        // not overflow; the same logic applies to the else branch
        const uint64_t dist = (MAX_ID - res) + leftmost->swarm_id;
        if (dist < cur_min) {
            cur_best = leftmost;
        }
    } else if (res < leftmost->swarm_id) {
        const uint64_t dist = res + (MAX_ID - rightmost->swarm_id);
        if (dist < cur_min) {
            cur_best = rightmost;
        }
    }

    return *cur_best;
}

std::pair<int, int> count_missing_data(const block_update& bu) {
    auto result = std::make_pair(0, 0);
    auto& [missing, total] = result;

    for (auto& swarm : bu.swarms) {
        for (auto& mnode : swarm.mnodes) {
            total++;
            if (mnode.ip.empty() || mnode.ip == "0.0.0.0" || !mnode.port || !mnode.omq_port
                || !mnode.pubkey_ed25519 || !mnode.pubkey_x25519) {
                BELDEX_LOG(
                        warn,
                        "well wtf {} {} {} {} {}",
                        mnode.ip,
                        mnode.port,
                        mnode.omq_port,
                        mnode.pubkey_ed25519,
                        mnode.pubkey_x25519);
                missing++;
            }
        }
    }
    return result;
}

}  // namespace beldex
