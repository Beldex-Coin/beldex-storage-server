#include "serialization.h"

#include "beldex_logger.h"
#include "oxenmq/bt_serialize.h"
#include "master_node.h"
#include "time.hpp"
#include "string_utils.hpp"

#include <boost/endian/conversion.hpp>
#include <oxenmq/base64.h>

#include <chrono>

namespace beldex {


std::vector<std::string> serialize_messages(std::function<const message*()> next_msg, uint8_t version) {

    std::vector<std::string> res;

    if (version == SERIALIZATION_VERSION_BT) {
        oxenmq::bt_list l;
        size_t counter = 2;
        while (auto* msg = next_msg()) {
            size_t ser_size =
                1 + // version byte
                2 + // l...e
                36 + // 33:pubkey
                2*15 + // millisecond epochs (13 digits) + `i...e`
                (4 + msg->hash.size()) + // xxx:HASH
                (6 + msg->data.size()) // xxxxx:DATA
            ;
            counter += ser_size;
            if (!l.empty() && counter > SERIALIZATION_BATCH_SIZE) {
                // Adding this message would push us over the limit, so finish it off and start a
                // new serialization piece.
                std::ostringstream oss;
                oss << SERIALIZATION_VERSION_BT << oxenmq::bt_serializer(l);
                res.push_back(oss.str());
                l.clear();
                counter = 1 + 2 + ser_size;
            }
            assert(msg->pubkey);
            l.push_back(oxenmq::bt_list{{
                msg->pubkey.prefixed_raw(),
                msg->hash,
                to_epoch_ms(msg->timestamp),
                to_epoch_ms(msg->expiry),
                msg->data}});
        }

        std::ostringstream oss;
        oss << uint8_t{1} /* version*/ << oxenmq::bt_serializer(l);
        res.push_back(oss.str());
    } else {
        BELDEX_LOG(critical, "Invalid serialization version {}", +version);
        throw std::logic_error{"Invalid serialization version " + std::to_string(version)};
    }

    return res;
}



std::vector<message> deserialize_messages(std::string_view slice) {

    BELDEX_LOG(trace, "=== Deserializing ===");

    // v0 (now unsupported) didn't send a version at all, and sent things incredibly inefficiently.
    // v1+ put the version as the first byte (but can't use any of '0'..'9','a'..'f','A'..'F'
    // because v0 started out with a hex pubkey).
    uint8_t version = 0;
    if (!slice.empty() && slice.front() < '0' && slice.front() != 0) {
        version = slice.front();
        slice.remove_prefix(1);
    }

    if (version != SERIALIZATION_VERSION_BT) {
        BELDEX_LOG(err, "Invalid deserialization version {}", +version);
        return {};
    }

    // v1:
    std::vector<message> result;
    try {
        oxenmq::bt_list_consumer l{slice};
        while (!l.is_finished()) {
            auto& item = result.emplace_back();
            auto m = l.consume_list_consumer();
            if (!item.pubkey.load(m.consume_string_view())) {
                BELDEX_LOG(debug, "Unable to deserialize(v1) pubkey");
                return {};
            }
            item.hash = m.consume_string();
            item.timestamp = from_epoch_ms(m.consume_integer<int64_t>());
            item.expiry = from_epoch_ms(m.consume_integer<int64_t>());
            item.data = m.consume_string();
        }
    } catch (const std::exception& e) {
        throw e;
        BELDEX_LOG(debug, "Failed to deserialize(v1): {}", e.what());
        return {};
    }

    BELDEX_LOG(trace, "=== END ===");

    return result;
}

} // namespace beldex
