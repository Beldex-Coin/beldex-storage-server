#pragma once

#include <beldexss/crypto/keys.h>

#include <functional>
#include <string_view>

namespace beldexss::rpc {

// Synchronously retrieves MN private keys from beldexd via the given oxenmq address.  This
// constructs a temporary OxenMQ instance to do the request (because generally storage server
// will have to re-construct one once we have the private keys).
//
// Returns legacy, ed25519, and x25519 keypairs.
//
// Takes an optional callback to invoke immediately before each attempt and immediately after
// each failed attempt: if the callback returns false then get_sn_keys aborts, returning a
// tuple of empty keys.
//
// This retries indefinitely until the connection & request are successful, or the callback
// returns false.
crypto::mnode_keypairs get_mn_keys(
        std::string_view beldexd_rpc_address, std::function<bool()> keep_trying = nullptr);

}  // namespace beldexss::rpc
