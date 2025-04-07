#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <beldexss/crypto/keys.h>

namespace beldexss::mnode {

struct mn_record {
    std::string ip;
    uint16_t port{0};
    uint16_t omq_quic_port{0};  // Same port for both: quic is UDP, OMQ is TCP
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

struct mn_test {
    const mnode::mn_record mn;
    std::function<void(const mnode::mn_record, bool passed)> finished;
    std::atomic<int> remaining;
    std::atomic<bool> failed{false};

    mn_test(const mnode::mn_record& mn,
            int test_count,
            std::function<void(const mnode::mn_record&, bool passed)> finished) :
            mn{mn}, finished{std::move(finished)}, remaining{test_count} {}

    void add_result(bool pass) {
        if (!pass)
            failed = true;
        if (--remaining == 0)
            finished(mn, pass && !failed);
    }
};

}  // namespace beldexss::mnode
