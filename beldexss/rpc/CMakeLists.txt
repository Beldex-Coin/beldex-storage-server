
add_library(rpc STATIC
    client_rpc_endpoints.cpp
    onion_processing.cpp
    beldexd_rpc.cpp
    rate_limiter.cpp
    request_handler.cpp)

target_link_libraries(rpc
    PUBLIC
    nlohmann_json::nlohmann_json
    PRIVATE
    crypto
    server
    mnode
    http
    utils
    logging
    version

    cpr::cpr
    oxenmq::oxenmq
    oxenc::oxenc
    sodium)

