#pragma once

#include <cstdint>
#include <map>
#include <set>

#include <beldexss/common/pubkey.h>
#include <beldexss/crypto/keys.h>
#include "contacts.h"

namespace beldexss::mnode {

using swarm_id_t = uint64_t;

using swarms_t = std::map<swarm_id_t, std::set<crypto::legacy_pubkey>>;

class Swarm;

constexpr swarm_id_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

struct block_update {
    swarms_t swarms;
    std::map<crypto::legacy_pubkey, contact> contacts;
    bool decommed = false;
    uint64_t height;
    std::string block_hash;
    int hardfork;
    int mnode_revision;
};

// Class that maintains global storage server network information, such as contact info
// for all nodes and current swarm IDs.
class Network {
    mutable std::shared_mutex mut_;

    swarms_t swarms_;

    friend class Swarm;

    swarms_t::const_iterator _find_swarm_for(const user_pubkey& pk) const;

    // Processes a swarm update; this replaces the current swarm map with the given one, and updates
    // contacts to remove any no-longer-present nodes, add any new ones, and update any changed
    // contact info.  As part of the update, swarm.update() is called at the end to have the current
    // swarm state update itself from the updated network info.
    //
    // This method is not to be called directly, but rather as part of swarm.update_swarms().
    void update_swarms(
            swarms_t&& new_swarms, const std::map<crypto::legacy_pubkey, contact>& new_contacts);

  public:
    /// Constructs a Network object.  The omq instance will be passed to `contacts` so that any
    /// x25519 pubkey list changes are automatically propagated to oxenmq for MN authentication.
    Network(oxenmq::OxenMQ& omq);

    // Holds all current contact information for network nodes.
    Contacts contacts;

    /// Maps a pubkey into a 64-bit "swarm space" value; the swarm you belong to is whichever one
    /// has a swarm id closest to this pubkey-derived value.
    static uint64_t pubkey_to_swarm_space(const user_pubkey& pk);

    // Looks up the swarm for a pubkey and returns the swarm_id.  Returns nullopt on error (which
    // will only happen if there are no swarms at all).
    std::optional<swarm_id_t> get_swarm_id_for(const user_pubkey& pk) const;

    // Looks up the swarm for a pubkey and returns both the swarm_id and a set of swarm members.
    // Returns nullopt on error (which will only happen if there are no swarms at all).
    std::optional<std::pair<swarm_id_t, std::set<crypto::legacy_pubkey>>> get_swarm_for(
            const user_pubkey& pk) const;

    // Looks up a swarm by swarm_id_t.  Returns nullopt if there is no such swarm id, otherwise
    // returns the set of swarm member pubkeys.
    std::optional<std::set<crypto::legacy_pubkey>> get_swarm(swarm_id_t swid) const;
};

}  // namespace beldexss::mnode
