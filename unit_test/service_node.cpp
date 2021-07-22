#include <catch2/catch.hpp>
#include <iostream>

#include "beldexd_key.h"
#include "request_handler.h"
#include "swarm.h"
#include "time.hpp"

#include <oxenmq/base64.h>

using namespace std::literals;

static auto create_dummy_mn_record() -> beldex::mn_record {

    const auto pk = beldex::legacy_pubkey::from_hex(
        "330e73449f6656cfe7816fa00d850af1f45884eab9e404026ca51f54b045e385");
    const auto pk_x25519 = beldex::x25519_pubkey::from_hex(
        "66ab11bed0e6219e1f3aea9b9e33f89cf636d5db203ed4efb9090cdb15902414");
    const auto pk_ed25519 = beldex::ed25519_pubkey::from_hex(
        "a38418ae9af2fedb560f400953f91cefb91a7a7efc971edfa31744ce5c4e319a");
    const std::string ip = "0.0.0.0";

    return {ip, 8080, 8081, pk, pk_ed25519, pk_x25519};
}

using ip_ports = std::tuple<const char*, uint16_t, uint16_t>;

static auto test_ip_update(ip_ports old_addr, ip_ports new_addr,
                           ip_ports expected) -> void {

    using beldex::mn_record;

    auto mn = create_dummy_mn_record();

    std::tie(mn.ip, mn.port, mn.omq_port) = old_addr;

    beldex::SwarmInfo si{0, std::vector<mn_record>{mn}};
    auto current = std::vector<beldex::SwarmInfo>{si};

    std::tie(mn.ip, mn.port, mn.omq_port) = new_addr;

    beldex::SwarmInfo si2{0, std::vector<mn_record>{mn}};
    auto incoming = std::vector<beldex::SwarmInfo>{si2};

    auto new_records = apply_ips(current, incoming);

    CHECK(new_records[0].mnodes[0].ip == std::get<0>(expected));
    CHECK(new_records[0].mnodes[0].port == std::get<1>(expected));
    CHECK(new_records[0].mnodes[0].omq_port == std::get<2>(expected));
}

TEST_CASE("master nodes - updates IP address", "[master-nodes][updates]") {

    auto mn = create_dummy_mn_record();

    const auto default_ip = ip_ports{"0.0.0.0", 0, 0};
    const auto ip1 = ip_ports{"1.1.1.1", 123, 456};
    const auto ip2 = ip_ports{"1.2.3.4", 123, 456};

    // Should update
    test_ip_update(ip1, ip2, ip2);

    // Should update
    test_ip_update(default_ip, ip2, ip2);

    // Should NOT update with default ip
    test_ip_update(ip1, default_ip, ip1);
}

/// Check that we don't inadvertently change how we compute message hashes
TEST_CASE("master nodes - message hashing", "[master-nodes][messages]") {

    const auto timestamp = std::chrono::system_clock::time_point{1616650862026ms};
    const auto expiry = timestamp + 48h;
    beldex::user_pubkey_t pk;
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    const auto data = oxenmq::from_base64(
            "CAES1gIKA1BVVBIPL2FwaS92MS9tZXNzYWdlGrsCCAYovfqZv4YvQq8CVwutUBbhRzZw80TvR6uTYMKg9DSag"
            "rtpeEpY31L7VxawfS8aSya0SiDa4J025SkjP13YX8g5pxgQ8Z6hgfNArMqr/tSijJ9miVKVDJ63YWE85O8kyW"
            "F8tdtZR5j0Vxb+JH5U8Rg1bp7ftKk3OSf7JJMcrUUrDnctQHe540zJ2OTDJ03DfubkX5NmKqEu5nhXGxeeDv3"
            "mTiL63fjtCvZYcikfjf6Nh1AX++HTgJ9SGoEIMastGUorFrmmXb2sbjHxNiJn0Radj/VzcA9VxYwBW5+AbGQ2"
            "d9+vvm7X+8vh+jIenJfjxf+8CWER+9adNfb4YUH07I+godNCV0O0J05gzqfKdT7J8MBZzFBtKrbk8oCagPpTs"
            "q/wZyYFKFKKD+q+zh704dYBILvs5yXUA96pIAA=");

    auto expected_old =
        "dd5f46395dbab44c9d96711a68cd70e326c4a39d6ccce7a319b0262c18699d20"
        "44610196519ad7283e3defebcdf3bccd6499fce1254fdee661e68f0611dc3104";
    CHECK(computeMessageHash(timestamp, expiry, pk, data, true /*old*/) == expected_old);
    CHECK(beldex::compute_hash_sha512_hex({
                std::to_string(beldex::to_epoch_ms(timestamp)) +
                std::to_string(beldex::to_epoch_ms(expiry) - beldex::to_epoch_ms(timestamp)) +
                pk.prefixed_hex() +
                oxenmq::to_base64(data)})
            == expected_old);

    auto expected_new = "rY7K5YXNsg7d8LBP6R4OoOr6L7IMFxa3Tr8ca5v5nBI";
    CHECK(computeMessageHash(timestamp, expiry, pk, data, false /*!old*/) == expected_new);
    CHECK(beldex::compute_hash_blake2b_b64({
                std::to_string(beldex::to_epoch_ms(timestamp)) +
                std::to_string(beldex::to_epoch_ms(expiry)) +
                pk.prefixed_raw() +
                data})
            == expected_new);

}

TEST_CASE("master nodes - pubkey to swarm id") {
    beldex::user_pubkey_t pk;
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    CHECK(pubkey_to_swarm_space(pk) == 4532060000165252872ULL);

    REQUIRE(pk.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK(pubkey_to_swarm_space(pk) == 0);

    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000123456789abcdef"));
    CHECK(pubkey_to_swarm_space(pk) == 0x0123456789abcdefULL);
}
