#pragma once

#include <atomic>
#include <functional>

#include <beldexss/crypto/keys.h>

namespace beldexss::mnode {

struct mn_test {
    crypto::legacy_pubkey pubkey{};
    std::function<void(const crypto::legacy_pubkey&, bool passed)> finished;
    std::atomic<int> remaining;
    std::atomic<bool> failed{false};

    mn_test(const crypto::legacy_pubkey& mn,
            int test_count,
            std::function<void(const crypto::legacy_pubkey&, bool passed)> finished) :
            pubkey{mn}, finished{std::move(finished)}, remaining{test_count} {}

    void add_result(bool pass) {
        if (!pass)
            failed = true;
        if (--remaining == 0)
            finished(pubkey, pass && !failed);
    }
};

}  // namespace beldexss::mnode
