#pragma once

#include <beldexss/crypto/keys.h>

#include <functional>
#include <string_view>

namespace beldex::rpc {

using beldexd_seckeys =
        std::tuple<crypto::legacy_seckey, crypto::ed25519_seckey, crypto::x25519_seckey>;

// Synchronously retrieves MN private keys from beldexd via the given oxenmq address.  This
// constructs a temporary OxenMQ instance to do the request (because generally storage server
// will have to re-construct one once we have the private keys).
//
// Returns legacy privkey; ed25519 privkey; x25519 privkey.
//
// Takes an optional callback to invoke immediately before each attempt and immediately after
// each failed attempt: if the callback returns false then get_mn_privkeys aborts, returning a
// tuple of empty keys.
//
// This retries indefinitely until the connection & request are successful, or the callback
// returns false.
beldexd_seckeys get_mn_privkeys(
        std::string_view beldexd_rpc_address, std::function<bool()> keep_trying = nullptr);

}  // namespace beldex::rpc
