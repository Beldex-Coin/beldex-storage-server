#include "serialization.h"
#include "master_node.h"

#include <catch2/catch.hpp>

#include <chrono>
#include <string>

using namespace beldex;

TEST_CASE("v0 serialization - basic values", "[serialization]") {

    user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    const auto data = "data";
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{12'345'678ms};
    const auto ttl = 3456s;
    std::vector<message> msgs;
    msgs.emplace_back(pub_key, hash, timestamp, timestamp + ttl, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 0);
    REQUIRE(serialized.size() == 1);
    const auto expected_serialized = oxenmq::to_hex(pub_key.prefixed_hex()) +
        "040000000000000068617368" // size+hash
        "08000000000000005a47463059513d3d" // size+data (ZGF0YQ== in b64)
        "00bc340000000000" // ttl
        "4e61bc0000000000" // timestamp
        "0000000000000000"s; // nonce
    CHECK(oxenmq::to_hex(serialized.front()) == expected_serialized);

    msgs.push_back(msgs.front());
    const std::vector<std::string> batches = serialize_messages(msgs.begin(), msgs.end(), 0);
    CHECK(batches.size() == 1);
    CHECK(oxenmq::to_hex(batches[0]) == expected_serialized + expected_serialized);

    const auto messages = deserialize_messages(batches[0]);
    CHECK(messages.size() == 2);
    for (int i = 0; i < messages.size(); ++i) {
        CHECK(messages[i].pubkey == pub_key);
        CHECK(messages[i].data == data);
        CHECK(messages[i].hash == hash);
        CHECK(messages[i].timestamp == timestamp);
        CHECK(messages[i].expiry == timestamp + ttl);
    }
}

TEST_CASE("v0 serialization - batch serialization", "[serialization]") {
    user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    std::string data(100000, 'x');
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    const auto ttl = 24h;
    std::vector<message> msgs;
    msgs.emplace_back(pub_key, hash, timestamp, timestamp + ttl, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 0);
    REQUIRE(serialized.size() == 1);
    auto first = serialized.front();
    const size_t num_messages = (SERIALIZATION_BATCH_SIZE / serialized.front().size()) + 1;
    msgs = {num_messages, msgs.front()};
    serialized = serialize_messages(msgs.begin(), msgs.end(), 0);
    CHECK(serialized.size() == 1);
    msgs.push_back(msgs.front());
    serialized = serialize_messages(msgs.begin(), msgs.end(), 0);
    CHECK(serialized.size() == 2);
}

TEST_CASE("v1 serialization - basic values", "[serialization]") {
    user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    const auto data = "da\x00ta"s;
    const auto hash = "hash\x00\x01\x02\x03"s;
    const std::chrono::system_clock::time_point timestamp{12'345'678ms};
    const auto expiry = timestamp + 3456s;
    std::vector<message> msgs;
    msgs.emplace_back(pub_key, hash, timestamp, expiry, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    REQUIRE(serialized.size() == 1);
    const auto expected_serialized =
        "l"
        "33:\x05\x43\x68\x52\x00\x05\x78\x6b\x24\x9b\xcd\x46\x1d\x28\xf7\x5e\x56" // pubkey
               "\x0e\xa7\x94\x01\x4e\xeb\x17\xfc\xf6\x00\x3f\x37\xd8\x76\x78\x3e"
        "8:hash\x00\x01\x02\x03" // hash
        "i12345678e" // timestamp
        "i15801678e" // expiry
        "5:da\x00ta" // data
        "e"s;
    CHECK(serialized.front() == "\x01l"s + expected_serialized + "e");

    msgs.push_back(msgs.front());
    const std::vector<std::string> batches = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(batches.size() == 1);
    REQUIRE(batches[0] == "\x01l"s + expected_serialized + expected_serialized + "e");

    const auto messages = deserialize_messages(batches[0]);
    CHECK(messages.size() == 2);
    for (int i = 0; i < messages.size(); ++i) {
        CHECK(messages[i].pubkey == pub_key);
        CHECK(messages[i].data == data);
        CHECK(messages[i].hash == hash);
        CHECK(messages[i].timestamp == timestamp);
        CHECK(messages[i].expiry == expiry);
    }
}

TEST_CASE("v1 serialization - batch serialization", "[serialization]") {
    user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    std::string data(100000, 'x');
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    const auto ttl = 24h;
    std::vector<message> msgs;
    msgs.emplace_back(pub_key, hash, timestamp, timestamp + ttl, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    REQUIRE(serialized.size() == 1);
    auto first = serialized.front();
    const size_t num_messages = (SERIALIZATION_BATCH_SIZE / (serialized.front().size() - 2));
    msgs = {num_messages, msgs.front()};
    serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(serialized.size() == 1);
    msgs.push_back(msgs.front());
    serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(serialized.size() == 2);
}
