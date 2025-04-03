#pragma once

#include <cstdint>
#include <string>

#include <beldexss/crypto/keys.h>

namespace beldexss::mnode {

struct mn_record {
    std::string ip;
    uint16_t port{0};
    uint16_t omq_port{0};
    crypto::legacy_pubkey pubkey_legacy{};
    crypto::ed25519_pubkey pubkey_ed25519{};
    crypto::x25519_pubkey pubkey_x25519{};
};

// Returns true if two mn_record's refer to the same mnode (i.e. have the same legacy pubkey).
// Note that other fields/pubkeys are not checked.
inline bool operator==(const mn_record& lhs, const mn_record& rhs) {
    return lhs.pubkey_legacy == rhs.pubkey_legacy;
}
// Returns true if two mn_record's have different pubkey_legacy values.
inline bool operator!=(const mn_record& lhs, const mn_record& rhs) {
    return !(lhs == rhs);
}

}  // namespace beldexss::mnode
