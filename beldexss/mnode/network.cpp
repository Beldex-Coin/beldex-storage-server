#include "network.h"
#include <oxenmq/oxenmq.h>
#include <cassert>
#include <iterator>
#include <ranges>
#include "oxenc/endian.h"
#include "beldexss/crypto/keys.h"
#include "swarm.h"

namespace beldexss::mnode {

Network::Network(oxenmq::OxenMQ& omq) : contacts{omq} {}

uint64_t Network::pubkey_to_swarm_space(const user_pubkey& pk) {
    const auto bytes = pk.raw();
    assert(bytes.size() == 32);

    uint64_t res = 0;
    for (size_t i = 0; i < bytes.size(); i += 8)
        res ^= oxenc::load_big_to_host<uint64_t>(bytes.data() + i);

    return res;
}

swarms_t::const_iterator Network::_find_swarm_for(const user_pubkey& pk) const {
    if (swarms_.empty())
        return swarms_.end();
    if (swarms_.size() == 1)
        return swarms_.begin();

    const uint64_t swarm_pos = pubkey_to_swarm_space(pk);

    // Find the right boundary, i.e. first swarm with swarm_id >= res
    auto right_it = swarms_.lower_bound(swarm_pos);

    if (right_it == swarms_.end())
        // swarm_pos is > the top swarm_id, meaning it is big and in the wrapping space between last
        // and first elements.
        right_it = swarms_.begin();

    // Our "left" is the swarm just before right (with wraparound, if right is the first swarm)
    auto left_it = std::prev(right_it == swarms_.begin() ? swarms_.end() : right_it);

    // So now we know that this pubkey is somewhere in [left, right], so our swarm is whichever of
    // those is closest to us, with intentional uint64_t overflow here to properly measure distance
    // across the max-uint64_t boundary.
    uint64_t dright = right_it->first - swarm_pos;
    uint64_t dleft = swarm_pos - left_it->first;

    return dright < dleft ? right_it : left_it;
}

std::optional<swarm_id_t> Network::get_swarm_id_for(const user_pubkey& pk) const {
    std::shared_lock lock{mut_};
    if (auto it = _find_swarm_for(pk); it != swarms_.end())
        return it->first;
    return std::nullopt;
}

std::optional<std::pair<swarm_id_t, std::set<crypto::legacy_pubkey>>> Network::get_swarm_for(
        const user_pubkey& pk) const {
    std::shared_lock lock{mut_};
    if (auto it = _find_swarm_for(pk); it != swarms_.end())
        return *it;
    return std::nullopt;
}

std::optional<std::set<crypto::legacy_pubkey>> Network::get_swarm(swarm_id_t swid) const {
    std::shared_lock lock{mut_};
    if (auto it = swarms_.find(swid); it != swarms_.end())
        return it->second;
    return std::nullopt;
}

void Network::update_swarms(
        swarms_t&& new_swarms, const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    // We are only called from Swarm, which already holds the lock:
    // std::unique_lock lock{mut_};

    std::set<crypto::legacy_pubkey> old_pks = contacts.get_pubkeys();
    auto new_pks = std::views::keys(new_contacts);
    std::vector<crypto::legacy_pubkey> removed;
    std::set_difference(
            old_pks.begin(),
            old_pks.end(),
            new_pks.begin(),
            new_pks.end(),
            std::back_inserter(removed));

    contacts.update_and_erase(
            new_contacts.begin(), new_contacts.end(), removed.begin(), removed.end());

    swarms_ = std::move(new_swarms);
}

}  // namespace beldexss::mnode
