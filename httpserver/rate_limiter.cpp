#include "rate_limiter.h"

#include "beldex_common.h"

#include <chrono>
#include <oxenmq/oxenmq.h>

#include <algorithm>

extern "C" {
#include <arpa/inet.h>
}

namespace beldex {

namespace {

    using namespace std::chrono;

    // Time between to consecutive tokens for clients
    constexpr microseconds TOKEN_PERIOD_US = 1'000'000us / RateLimiter::TOKEN_RATE;

    // Time between to consecutive tokens for mnodes
    constexpr microseconds TOKEN_PERIOD_MN_US = 1'000'000us / RateLimiter::TOKEN_RATE_MN;

    constexpr microseconds FILL_EMPTY_BUCKET_US = TOKEN_PERIOD_US * RateLimiter::BUCKET_SIZE;

}  // namespace

RateLimiter::RateLimiter(oxenmq::OxenMQ& omq) {
    omq.add_timer(
            [this] {
                std::lock_guard lock{mutex_};
                clean_buckets(steady_clock::now());
            },
            10s);
}

template <typename TokenBucket>
static bool fill_bucket(
        TokenBucket& bucket, steady_clock::time_point now, bool master_node = false) {
    auto elapsed_us = duration_cast<microseconds>(now - bucket.last_time_point);
    // clamp elapsed time to how long it takes to fill up the whole bucket
    // (simplifies overlow checking)
    elapsed_us = std::min(elapsed_us, FILL_EMPTY_BUCKET_US);

    const auto token_period = master_node ? TOKEN_PERIOD_MN_US : TOKEN_PERIOD_US;

    const uint32_t token_added = elapsed_us.count() / token_period.count();
    bucket.num_tokens += token_added;
    if (bucket.num_tokens >= RateLimiter::BUCKET_SIZE) {
        bucket.num_tokens = RateLimiter::BUCKET_SIZE;
        return true;
    }
    return false;
}

template <typename TokenBucket>
static bool remove_token(TokenBucket& b, steady_clock::time_point now, bool mn = false) {
    fill_bucket(b, now, mn);
    if (b.num_tokens == 0)
        return false;
    b.num_tokens--;
    b.last_time_point = now;
    return true;
}

bool RateLimiter::should_rate_limit(const legacy_pubkey& pubkey, steady_clock::time_point now) {
    std::lock_guard lock{mutex_};
    if (auto [it, ins] = mnode_buckets_.emplace(pubkey, TokenBucket{BUCKET_SIZE - 1, now}); ins)
        return false;
    else
        return !remove_token(it->second, now, true);
}

bool RateLimiter::should_rate_limit_client(uint32_t ip, steady_clock::time_point now) {
    std::lock_guard lock{mutex_};

    if (auto it = client_buckets_.find(ip); it != client_buckets_.end())
        return !remove_token(it->second, now);

    if (client_buckets_.size() >= MAX_CLIENTS) {
        clean_buckets(now);
        if (client_buckets_.size() >= MAX_CLIENTS)
            return true;
    }
    client_buckets_.emplace(ip, TokenBucket{BUCKET_SIZE - 1, now});
    return false;
}

bool RateLimiter::should_rate_limit_client(
        const std::string& ip_dotted_quad, steady_clock::time_point now) {
    struct in_addr ip;
    int res = inet_pton(AF_INET, ip_dotted_quad.c_str(), &ip);
    return res == 1 ? should_rate_limit_client(ip.s_addr) : false;
}

void RateLimiter::clean_buckets(steady_clock::time_point now) {
    for (auto it = client_buckets_.begin(); it != client_buckets_.end();) {
        if (fill_bucket(it->second, now))
            it = client_buckets_.erase(it);
        else
            ++it;
    }

    for (auto it = mnode_buckets_.begin(); it != mnode_buckets_.end();) {
        if (fill_bucket(it->second, now, true))
            it = mnode_buckets_.erase(it);
        else
            ++it;
    }
}

}  // namespace beldex
