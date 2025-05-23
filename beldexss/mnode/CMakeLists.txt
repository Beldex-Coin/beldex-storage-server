
add_library(mnode STATIC
    contacts.cpp
    network.cpp
    reachability_testing.cpp
    serialization.cpp
    master_node.cpp
    stats.cpp
    swarm.cpp)

target_link_libraries(mnode
    PUBLIC
    oxenmq::oxenmq
    cpr::cpr
    PRIVATE
    crypto
    utils
    quic
    server
    logging
    rpc
    oxenc::oxenc
    sodium)
